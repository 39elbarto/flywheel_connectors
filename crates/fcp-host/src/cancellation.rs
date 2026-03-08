//! Operation cancellation: graceful abort with cleanup and audit.
//!
//! Provides types and logic for cancelling in-flight operations with:
//! - Reason codes explaining why cancellation was requested
//! - Cleanup behavior control (best-effort, full, abandon, checkpoint)
//! - Partial result capture from cancelled operations
//! - Checkpoint/resume support for resumable operations
//! - Audit trail for all cancellation decisions
//!
//! Based on bead `flywheel_connectors-2653`.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{HostError, HostResult};

// ─────────────────────────────────────────────────────────────────────────────
// Cancel Reason
// ─────────────────────────────────────────────────────────────────────────────

/// Why an operation was cancelled.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CancelReason {
    /// User explicitly requested cancellation.
    UserRequested,
    /// Agent detected an issue and is aborting.
    AgentAbort {
        /// Reason for the abort.
        reason: String,
    },
    /// Approaching timeout, requesting graceful shutdown.
    TimeoutApproaching {
        /// Milliseconds remaining before hard timeout.
        remaining_ms: u64,
    },
    /// Resource limit approaching.
    ResourceLimit {
        /// Which resource is constrained.
        resource: String,
        /// Current usage.
        current: u64,
        /// Limit threshold.
        limit: u64,
    },
    /// Superseded by another operation.
    Superseded {
        /// ID of the superseding operation.
        by_operation_id: String,
    },
    /// Session or connection is closing.
    SessionClosing,
}

impl CancelReason {
    /// Human-readable label for this reason category.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::UserRequested => "user_requested",
            Self::AgentAbort { .. } => "agent_abort",
            Self::TimeoutApproaching { .. } => "timeout_approaching",
            Self::ResourceLimit { .. } => "resource_limit",
            Self::Superseded { .. } => "superseded",
            Self::SessionClosing => "session_closing",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Cleanup Behavior
// ─────────────────────────────────────────────────────────────────────────────

/// How cleanup should be handled after cancellation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CleanupBehavior {
    /// Best-effort cleanup; may leave partial state.
    #[default]
    BestEffort,
    /// Must fully clean up before returning (bounded by timeout).
    Full {
        /// Maximum time to spend on cleanup.
        timeout_ms: u64,
    },
    /// No cleanup; abandon immediately and return.
    Abandon,
    /// Checkpoint state for potential resume later.
    Checkpoint,
}

// ─────────────────────────────────────────────────────────────────────────────
// Cancellation State
// ─────────────────────────────────────────────────────────────────────────────

/// Current state of a cancellation request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CancellationOutcome {
    /// Operation was successfully cancelled.
    Cancelled,
    /// Operation had already completed before cancellation arrived.
    TooLate,
    /// Cancellation is in progress (cleanup running).
    Pending,
    /// Cancellation failed (operation could not be stopped).
    Failed,
}

// ─────────────────────────────────────────────────────────────────────────────
// Cancellation Request & Response
// ─────────────────────────────────────────────────────────────────────────────

/// A request to cancel an in-flight operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancellationRequest {
    /// ID of the operation to cancel.
    pub operation_id: String,
    /// Why the operation is being cancelled.
    pub reason: CancelReason,
    /// How cleanup should be handled.
    #[serde(default)]
    pub cleanup: CleanupBehavior,
    /// Whether to return partial results if available.
    #[serde(default)]
    pub return_partial: bool,
}

/// Result of a cancellation attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancellationResponse {
    /// ID of the cancelled operation.
    pub operation_id: String,
    /// Outcome of the cancellation attempt.
    pub outcome: CancellationOutcome,
    /// Partial results if available and requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partial_result: Option<PartialResult>,
    /// Checkpoint info if checkpoint cleanup was requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<CheckpointInfo>,
    /// Cleanup summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cleanup_result: Option<CleanupResult>,
    /// Duration of the cancellation process in milliseconds.
    pub duration_ms: u64,
}

/// Partial results from a cancelled operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialResult {
    /// Number of items completed before cancellation.
    pub completed_items: u64,
    /// Total items expected (if known).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_items: Option<u64>,
    /// The partial output data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// Checkpoint information for resumable operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointInfo {
    /// Checkpoint ID for resume.
    pub id: String,
    /// Whether this checkpoint can be used to resume.
    pub resumable: bool,
    /// When the checkpoint expires.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Opaque state for the connector.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<serde_json::Value>,
}

/// Summary of cleanup after cancellation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanupResult {
    /// Whether cleanup completed successfully.
    pub success: bool,
    /// Resources that were cleaned up.
    pub cleaned: Vec<String>,
    /// Resources that could not be cleaned up.
    pub failed: Vec<String>,
    /// Duration of cleanup in milliseconds.
    pub duration_ms: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Audit Event
// ─────────────────────────────────────────────────────────────────────────────

/// Audit event for a cancellation action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancellationAuditEvent {
    /// When the event occurred.
    pub timestamp: DateTime<Utc>,
    /// Operation that was cancelled.
    pub operation_id: String,
    /// Reason for cancellation.
    pub reason: CancelReason,
    /// Outcome of the cancellation.
    pub outcome: CancellationOutcome,
    /// Duration of the cancellation process.
    pub duration_ms: u64,
    /// Whether partial results were returned.
    pub had_partial_result: bool,
    /// Whether a checkpoint was created.
    pub had_checkpoint: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Operation Tracker
// ─────────────────────────────────────────────────────────────────────────────

/// Tracks the state of an in-flight operation.
#[derive(Debug, Clone)]
struct TrackedOperation {
    /// Whether the operation has been completed.
    completed: bool,
    /// Whether a cancellation has been requested.
    cancel_requested: bool,
}

/// Controller that manages operation tracking and cancellation.
///
/// # Panics
///
/// Methods that access the internal mutex will panic if the mutex is
/// poisoned (only possible if a thread panicked while holding the lock).
pub struct CancellationController {
    operations: Mutex<HashMap<String, TrackedOperation>>,
    audit_log: Mutex<Vec<CancellationAuditEvent>>,
}

impl std::fmt::Debug for CancellationController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CancellationController")
            .field("operations", &format_args!("<Mutex>"))
            .field("audit_log", &format_args!("<Mutex>"))
            .finish()
    }
}

impl CancellationController {
    /// Create a new cancellation controller.
    #[must_use]
    pub fn new() -> Self {
        Self {
            operations: Mutex::new(HashMap::new()),
            audit_log: Mutex::new(Vec::new()),
        }
    }

    /// Register an operation for tracking.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn track(&self, operation_id: &str) {
        let mut ops = self.operations.lock().expect("operations lock");
        ops.insert(
            operation_id.to_string(),
            TrackedOperation {
                completed: false,
                cancel_requested: false,
            },
        );
    }

    /// Mark an operation as completed.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn complete(&self, operation_id: &str) {
        let mut ops = self.operations.lock().expect("operations lock");
        if let Some(op) = ops.get_mut(operation_id) {
            op.completed = true;
        }
    }

    /// Check if cancellation has been requested for an operation.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn is_cancel_requested(&self, operation_id: &str) -> bool {
        self.operations
            .lock()
            .expect("operations lock")
            .get(operation_id)
            .is_some_and(|op| op.cancel_requested)
    }

    /// Request cancellation of an operation.
    ///
    /// Uses `now` for timestamp determinism.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::ConnectorNotFound`] if the operation is not tracked.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn cancel(
        &self,
        request: &CancellationRequest,
        now: DateTime<Utc>,
    ) -> HostResult<CancellationResponse> {
        let start = Instant::now();

        let outcome = {
            let mut ops = self.operations.lock().expect("operations lock");
            match ops.get_mut(&request.operation_id) {
                None => {
                    return Err(HostError::ConnectorNotFound(format!(
                        "operation not found: {}",
                        request.operation_id
                    )));
                }
                Some(op) if op.completed => CancellationOutcome::TooLate,
                Some(op) if op.cancel_requested => CancellationOutcome::Pending,
                Some(op) => {
                    op.cancel_requested = true;
                    CancellationOutcome::Cancelled
                }
            }
        };

        let duration_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);

        // Build checkpoint if requested and cancellation succeeded.
        let checkpoint = if matches!(request.cleanup, CleanupBehavior::Checkpoint)
            && outcome == CancellationOutcome::Cancelled
        {
            Some(CheckpointInfo {
                id: format!("ckpt_{}", request.operation_id),
                resumable: true,
                expires_at: Some(now + chrono::Duration::hours(24)),
                state: None,
            })
        } else {
            None
        };

        // Build cleanup result.
        let cleanup_result = match outcome {
            CancellationOutcome::Cancelled | CancellationOutcome::Pending => Some(CleanupResult {
                success: true,
                cleaned: vec!["operation_state".into()],
                failed: vec![],
                duration_ms,
            }),
            _ => None,
        };

        // Record audit event.
        let audit_event = CancellationAuditEvent {
            timestamp: now,
            operation_id: request.operation_id.clone(),
            reason: request.reason.clone(),
            outcome,
            duration_ms,
            had_partial_result: false, // Set by caller when partial data exists
            had_checkpoint: checkpoint.is_some(),
        };
        self.audit_log.lock().expect("audit lock").push(audit_event);

        Ok(CancellationResponse {
            operation_id: request.operation_id.clone(),
            outcome,
            partial_result: None, // Set by caller when partial data is available
            checkpoint,
            cleanup_result,
            duration_ms,
        })
    }

    /// Remove a completed or cancelled operation from tracking.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn remove(&self, operation_id: &str) {
        self.operations
            .lock()
            .expect("operations lock")
            .remove(operation_id);
    }

    /// Number of currently tracked operations.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn tracked_count(&self) -> usize {
        self.operations.lock().expect("operations lock").len()
    }

    /// Get audit events, newest first.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn audit_events(&self) -> Vec<CancellationAuditEvent> {
        let mut result = {
            let guard = self.audit_log.lock().expect("audit lock");
            guard.clone()
        };
        result.reverse();
        result
    }

    /// Clear all audit events.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn clear_audit_log(&self) {
        self.audit_log.lock().expect("audit lock").clear();
    }
}

impl Default for CancellationController {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use fcp_core::OperationId;

    fn fixed_now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 3, 7, 12, 0, 0).unwrap()
    }

    fn cancel_request(op_id: &str, reason: CancelReason) -> CancellationRequest {
        CancellationRequest {
            operation_id: op_id.into(),
            reason,
            cleanup: CleanupBehavior::default(),
            return_partial: false,
        }
    }

    // ── CancelReason tests ──

    #[test]
    fn cancel_reason_user_requested_label() {
        assert_eq!(CancelReason::UserRequested.label(), "user_requested");
    }

    #[test]
    fn cancel_reason_agent_abort_label() {
        let r = CancelReason::AgentAbort {
            reason: "bad state".into(),
        };
        assert_eq!(r.label(), "agent_abort");
    }

    #[test]
    fn cancel_reason_timeout_label() {
        let r = CancelReason::TimeoutApproaching { remaining_ms: 500 };
        assert_eq!(r.label(), "timeout_approaching");
    }

    #[test]
    fn cancel_reason_resource_limit_label() {
        let r = CancelReason::ResourceLimit {
            resource: "memory".into(),
            current: 900,
            limit: 1000,
        };
        assert_eq!(r.label(), "resource_limit");
    }

    #[test]
    fn cancel_reason_superseded_label() {
        let r = CancelReason::Superseded {
            by_operation_id: "op_new".into(),
        };
        assert_eq!(r.label(), "superseded");
    }

    #[test]
    fn cancel_reason_session_closing_label() {
        assert_eq!(CancelReason::SessionClosing.label(), "session_closing");
    }

    #[test]
    fn cancel_reason_json_roundtrip() {
        let r = CancelReason::AgentAbort {
            reason: "detected error".into(),
        };
        let json = serde_json::to_string(&r).unwrap();
        let parsed: CancelReason = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.label(), "agent_abort");
    }

    #[test]
    fn cancel_reason_resource_limit_json_roundtrip() {
        let r = CancelReason::ResourceLimit {
            resource: "tokens".into(),
            current: 950,
            limit: 1000,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("tokens"));
        assert!(json.contains("950"));
    }

    // ── CleanupBehavior tests ──

    #[test]
    fn cleanup_default_is_best_effort() {
        assert!(matches!(
            CleanupBehavior::default(),
            CleanupBehavior::BestEffort
        ));
    }

    #[test]
    fn cleanup_full_has_timeout() {
        let c = CleanupBehavior::Full { timeout_ms: 5000 };
        if let CleanupBehavior::Full { timeout_ms } = c {
            assert_eq!(timeout_ms, 5000);
        } else {
            panic!("expected Full variant");
        }
    }

    #[test]
    fn cleanup_json_roundtrip() {
        let c = CleanupBehavior::Checkpoint;
        let json = serde_json::to_string(&c).unwrap();
        let parsed: CleanupBehavior = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, CleanupBehavior::Checkpoint));
    }

    #[test]
    fn cleanup_abandon_json_roundtrip() {
        let c = CleanupBehavior::Abandon;
        let json = serde_json::to_string(&c).unwrap();
        let parsed: CleanupBehavior = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, CleanupBehavior::Abandon));
    }

    // ── CancellationOutcome tests ──

    #[test]
    fn outcome_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&CancellationOutcome::TooLate).unwrap(),
            "\"too_late\""
        );
        assert_eq!(
            serde_json::to_string(&CancellationOutcome::Cancelled).unwrap(),
            "\"cancelled\""
        );
    }

    #[test]
    fn outcome_equality() {
        assert_eq!(
            CancellationOutcome::Cancelled,
            CancellationOutcome::Cancelled
        );
        assert_ne!(CancellationOutcome::Cancelled, CancellationOutcome::TooLate);
    }

    // ── CancellationController tests ──

    #[test]
    fn track_and_count() {
        let ctrl = CancellationController::new();
        assert_eq!(ctrl.tracked_count(), 0);
        ctrl.track("op1");
        assert_eq!(ctrl.tracked_count(), 1);
        ctrl.track("op2");
        assert_eq!(ctrl.tracked_count(), 2);
    }

    #[test]
    fn cancel_unknown_operation_errors() {
        let ctrl = CancellationController::new();
        let req = cancel_request("nonexistent", CancelReason::UserRequested);
        let err = ctrl.cancel(&req, fixed_now()).unwrap_err();
        assert!(err.to_string().contains("operation not found"));
    }

    #[test]
    fn cancel_active_operation_succeeds() {
        let ctrl = CancellationController::new();
        ctrl.track("op1");
        let req = cancel_request("op1", CancelReason::UserRequested);
        let resp = ctrl.cancel(&req, fixed_now()).unwrap();
        assert_eq!(resp.outcome, CancellationOutcome::Cancelled);
        assert_eq!(resp.operation_id, "op1");
    }

    #[test]
    fn cancel_completed_operation_returns_too_late() {
        let ctrl = CancellationController::new();
        ctrl.track("op1");
        ctrl.complete("op1");
        let req = cancel_request("op1", CancelReason::UserRequested);
        let resp = ctrl.cancel(&req, fixed_now()).unwrap();
        assert_eq!(resp.outcome, CancellationOutcome::TooLate);
    }

    #[test]
    fn cancel_already_cancelled_returns_pending() {
        let ctrl = CancellationController::new();
        ctrl.track("op1");
        let req = cancel_request("op1", CancelReason::UserRequested);
        ctrl.cancel(&req, fixed_now()).unwrap();
        // Second cancellation attempt.
        let resp = ctrl.cancel(&req, fixed_now()).unwrap();
        assert_eq!(resp.outcome, CancellationOutcome::Pending);
    }

    #[test]
    fn is_cancel_requested_false_initially() {
        let ctrl = CancellationController::new();
        ctrl.track("op1");
        assert!(!ctrl.is_cancel_requested("op1"));
    }

    #[test]
    fn is_cancel_requested_true_after_cancel() {
        let ctrl = CancellationController::new();
        ctrl.track("op1");
        let req = cancel_request("op1", CancelReason::UserRequested);
        ctrl.cancel(&req, fixed_now()).unwrap();
        assert!(ctrl.is_cancel_requested("op1"));
    }

    #[test]
    fn is_cancel_requested_unknown_returns_false() {
        let ctrl = CancellationController::new();
        assert!(!ctrl.is_cancel_requested("nonexistent"));
    }

    #[test]
    fn remove_decreases_count() {
        let ctrl = CancellationController::new();
        ctrl.track("op1");
        ctrl.track("op2");
        assert_eq!(ctrl.tracked_count(), 2);
        ctrl.remove("op1");
        assert_eq!(ctrl.tracked_count(), 1);
    }

    #[test]
    fn remove_unknown_is_noop() {
        let ctrl = CancellationController::new();
        ctrl.track("op1");
        ctrl.remove("nonexistent");
        assert_eq!(ctrl.tracked_count(), 1);
    }

    // ── Checkpoint tests ──

    #[test]
    fn checkpoint_created_on_checkpoint_cleanup() {
        let ctrl = CancellationController::new();
        ctrl.track("op1");
        let req = CancellationRequest {
            operation_id: "op1".into(),
            reason: CancelReason::UserRequested,
            cleanup: CleanupBehavior::Checkpoint,
            return_partial: false,
        };
        let resp = ctrl.cancel(&req, fixed_now()).unwrap();
        assert_eq!(resp.outcome, CancellationOutcome::Cancelled);
        let ckpt = resp.checkpoint.unwrap();
        assert!(ckpt.resumable);
        assert!(ckpt.id.contains("op1"));
        assert!(ckpt.expires_at.is_some());
    }

    #[test]
    fn no_checkpoint_on_best_effort() {
        let ctrl = CancellationController::new();
        ctrl.track("op1");
        let req = cancel_request("op1", CancelReason::UserRequested);
        let resp = ctrl.cancel(&req, fixed_now()).unwrap();
        assert!(resp.checkpoint.is_none());
    }

    #[test]
    fn no_checkpoint_on_too_late() {
        let ctrl = CancellationController::new();
        ctrl.track("op1");
        ctrl.complete("op1");
        let req = CancellationRequest {
            operation_id: "op1".into(),
            reason: CancelReason::UserRequested,
            cleanup: CleanupBehavior::Checkpoint,
            return_partial: false,
        };
        let resp = ctrl.cancel(&req, fixed_now()).unwrap();
        assert_eq!(resp.outcome, CancellationOutcome::TooLate);
        assert!(resp.checkpoint.is_none());
    }

    // ── Cleanup result tests ──

    #[test]
    fn cleanup_result_present_on_cancel() {
        let ctrl = CancellationController::new();
        ctrl.track("op1");
        let req = cancel_request("op1", CancelReason::UserRequested);
        let resp = ctrl.cancel(&req, fixed_now()).unwrap();
        let cleanup = resp.cleanup_result.unwrap();
        assert!(cleanup.success);
        assert!(!cleanup.cleaned.is_empty());
        assert!(cleanup.failed.is_empty());
    }

    #[test]
    fn no_cleanup_result_on_too_late() {
        let ctrl = CancellationController::new();
        ctrl.track("op1");
        ctrl.complete("op1");
        let req = cancel_request("op1", CancelReason::UserRequested);
        let resp = ctrl.cancel(&req, fixed_now()).unwrap();
        assert!(resp.cleanup_result.is_none());
    }

    // ── Audit log tests ──

    #[test]
    fn audit_event_recorded_on_cancel() {
        let ctrl = CancellationController::new();
        ctrl.track("op1");
        let req = cancel_request("op1", CancelReason::UserRequested);
        ctrl.cancel(&req, fixed_now()).unwrap();
        let events = ctrl.audit_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation_id, "op1");
        assert_eq!(events[0].outcome, CancellationOutcome::Cancelled);
        assert_eq!(events[0].reason.label(), "user_requested");
    }

    #[test]
    fn audit_event_recorded_on_too_late() {
        let ctrl = CancellationController::new();
        ctrl.track("op1");
        ctrl.complete("op1");
        let req = cancel_request("op1", CancelReason::SessionClosing);
        ctrl.cancel(&req, fixed_now()).unwrap();
        let events = ctrl.audit_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, CancellationOutcome::TooLate);
    }

    #[test]
    fn audit_multiple_events() {
        let ctrl = CancellationController::new();
        ctrl.track("op1");
        ctrl.track("op2");
        ctrl.cancel(
            &cancel_request("op1", CancelReason::UserRequested),
            fixed_now(),
        )
        .unwrap();
        ctrl.cancel(
            &cancel_request("op2", CancelReason::SessionClosing),
            fixed_now(),
        )
        .unwrap();
        let events = ctrl.audit_events();
        assert_eq!(events.len(), 2);
        // Newest first.
        assert_eq!(events[0].operation_id, "op2");
        assert_eq!(events[1].operation_id, "op1");
    }

    #[test]
    fn clear_audit_log() {
        let ctrl = CancellationController::new();
        ctrl.track("op1");
        ctrl.cancel(
            &cancel_request("op1", CancelReason::UserRequested),
            fixed_now(),
        )
        .unwrap();
        assert_eq!(ctrl.audit_events().len(), 1);
        ctrl.clear_audit_log();
        assert!(ctrl.audit_events().is_empty());
    }

    #[test]
    fn audit_checkpoint_flag_set() {
        let ctrl = CancellationController::new();
        ctrl.track("op1");
        let req = CancellationRequest {
            operation_id: "op1".into(),
            reason: CancelReason::UserRequested,
            cleanup: CleanupBehavior::Checkpoint,
            return_partial: false,
        };
        ctrl.cancel(&req, fixed_now()).unwrap();
        let events = ctrl.audit_events();
        assert!(events[0].had_checkpoint);
    }

    #[test]
    fn audit_no_checkpoint_flag() {
        let ctrl = CancellationController::new();
        ctrl.track("op1");
        ctrl.cancel(
            &cancel_request("op1", CancelReason::UserRequested),
            fixed_now(),
        )
        .unwrap();
        let events = ctrl.audit_events();
        assert!(!events[0].had_checkpoint);
    }

    // ── Serialization tests ──

    #[test]
    fn cancellation_request_json_roundtrip() {
        let req = CancellationRequest {
            operation_id: "op_abc".into(),
            reason: CancelReason::TimeoutApproaching { remaining_ms: 1000 },
            cleanup: CleanupBehavior::Full { timeout_ms: 5000 },
            return_partial: true,
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: CancellationRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.operation_id, "op_abc");
        assert!(parsed.return_partial);
    }

    #[test]
    fn cancellation_response_json_roundtrip() {
        let resp = CancellationResponse {
            operation_id: "op_abc".into(),
            outcome: CancellationOutcome::Cancelled,
            partial_result: Some(PartialResult {
                completed_items: 42,
                total_items: Some(100),
                data: Some(serde_json::json!({"items": [1, 2, 3]})),
            }),
            checkpoint: None,
            cleanup_result: Some(CleanupResult {
                success: true,
                cleaned: vec!["temp_files".into()],
                failed: vec![],
                duration_ms: 10,
            }),
            duration_ms: 15,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: CancellationResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.outcome, CancellationOutcome::Cancelled);
        assert_eq!(parsed.partial_result.unwrap().completed_items, 42);
    }

    #[test]
    fn checkpoint_info_json_roundtrip() {
        let ckpt = CheckpointInfo {
            id: "ckpt_123".into(),
            resumable: true,
            expires_at: Some(fixed_now()),
            state: Some(serde_json::json!({"cursor": "page_5"})),
        };
        let json = serde_json::to_string(&ckpt).unwrap();
        let parsed: CheckpointInfo = serde_json::from_str(&json).unwrap();
        assert!(parsed.resumable);
        assert_eq!(parsed.id, "ckpt_123");
    }

    // ── Default trait tests ──

    #[test]
    fn controller_default() {
        let ctrl = CancellationController::default();
        assert_eq!(ctrl.tracked_count(), 0);
    }

    #[test]
    fn controller_debug() {
        let ctrl = CancellationController::new();
        ctrl.track("op1");
        let dbg = format!("{ctrl:?}");
        assert!(dbg.contains("CancellationController"));
        assert!(dbg.contains("operations"));
    }

    // ── PartialResult tests ──

    #[test]
    fn partial_result_with_data() {
        let pr = PartialResult {
            completed_items: 50,
            total_items: Some(200),
            data: Some(serde_json::json!({"batch": "partial"})),
        };
        let json = serde_json::to_string(&pr).unwrap();
        let parsed: PartialResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.completed_items, 50);
        assert_eq!(parsed.total_items, Some(200));
    }

    #[test]
    fn partial_result_minimal() {
        let pr = PartialResult {
            completed_items: 0,
            total_items: None,
            data: None,
        };
        let json = serde_json::to_string(&pr).unwrap();
        assert!(!json.contains("total_items"));
        assert!(!json.contains("data"));
    }

    // ── Edge cases ──

    #[test]
    fn complete_unknown_operation_is_noop() {
        let ctrl = CancellationController::new();
        ctrl.complete("nonexistent"); // Should not panic.
        assert_eq!(ctrl.tracked_count(), 0);
    }

    #[test]
    fn track_same_id_overwrites() {
        let ctrl = CancellationController::new();
        ctrl.track("op1");
        ctrl.track("op1");
        assert_eq!(ctrl.tracked_count(), 1);
    }

    #[test]
    fn cancel_with_all_reason_variants() {
        let ctrl = CancellationController::new();
        let reasons = vec![
            CancelReason::UserRequested,
            CancelReason::AgentAbort {
                reason: "err".into(),
            },
            CancelReason::TimeoutApproaching { remaining_ms: 100 },
            CancelReason::ResourceLimit {
                resource: "mem".into(),
                current: 90,
                limit: 100,
            },
            CancelReason::Superseded {
                by_operation_id: "op_new".into(),
            },
            CancelReason::SessionClosing,
        ];
        for (i, reason) in reasons.into_iter().enumerate() {
            let id = format!("op{i}");
            ctrl.track(&id);
            let req = cancel_request(&id, reason);
            let resp = ctrl.cancel(&req, fixed_now()).unwrap();
            assert_eq!(resp.outcome, CancellationOutcome::Cancelled);
        }
        assert_eq!(ctrl.audit_events().len(), 6);
    }

    // Note: OperationId from fcp_core is not used directly in the controller
    // to keep the API string-based and flexible. Callers convert as needed.
    #[test]
    fn operation_id_interop() {
        let op_id = OperationId::from_static("test.cancel.op");
        let ctrl = CancellationController::new();
        ctrl.track(op_id.as_str());
        assert!(ctrl.tracked_count() == 1);
        let req = cancel_request(op_id.as_str(), CancelReason::UserRequested);
        let resp = ctrl.cancel(&req, fixed_now()).unwrap();
        assert_eq!(resp.outcome, CancellationOutcome::Cancelled);
    }

    // ── CancelReason serialization (extended) ──

    #[test]
    fn cancel_reason_user_requested_deserialize_from_json() {
        let json = r#"{"type":"user_requested"}"#;
        let r: CancelReason = serde_json::from_str(json).unwrap();
        assert_eq!(r.label(), "user_requested");
    }

    #[test]
    fn cancel_reason_agent_abort_deserialize_from_json() {
        let json = r#"{"type":"agent_abort","reason":"something went wrong"}"#;
        let r: CancelReason = serde_json::from_str(json).unwrap();
        assert_eq!(r.label(), "agent_abort");
        if let CancelReason::AgentAbort { reason } = r {
            assert_eq!(reason, "something went wrong");
        } else {
            panic!("expected AgentAbort");
        }
    }

    #[test]
    fn cancel_reason_timeout_approaching_deserialize_from_json() {
        let json = r#"{"type":"timeout_approaching","remaining_ms":250}"#;
        let r: CancelReason = serde_json::from_str(json).unwrap();
        if let CancelReason::TimeoutApproaching { remaining_ms } = r {
            assert_eq!(remaining_ms, 250);
        } else {
            panic!("expected TimeoutApproaching");
        }
    }

    #[test]
    fn cancel_reason_resource_limit_deserialize_from_json() {
        let json = r#"{"type":"resource_limit","resource":"cpu","current":95,"limit":100}"#;
        let r: CancelReason = serde_json::from_str(json).unwrap();
        if let CancelReason::ResourceLimit {
            resource,
            current,
            limit,
        } = r
        {
            assert_eq!(resource, "cpu");
            assert_eq!(current, 95);
            assert_eq!(limit, 100);
        } else {
            panic!("expected ResourceLimit");
        }
    }

    #[test]
    fn cancel_reason_superseded_deserialize_from_json() {
        let json = r#"{"type":"superseded","by_operation_id":"op_replacement"}"#;
        let r: CancelReason = serde_json::from_str(json).unwrap();
        if let CancelReason::Superseded { by_operation_id } = r {
            assert_eq!(by_operation_id, "op_replacement");
        } else {
            panic!("expected Superseded");
        }
    }

    #[test]
    fn cancel_reason_session_closing_deserialize_from_json() {
        let json = r#"{"type":"session_closing"}"#;
        let r: CancelReason = serde_json::from_str(json).unwrap();
        assert_eq!(r.label(), "session_closing");
    }

    #[test]
    fn cancel_reason_unknown_variant_rejected() {
        let json = r#"{"type":"cosmic_ray"}"#;
        let result = serde_json::from_str::<CancelReason>(json);
        assert!(result.is_err());
    }

    #[test]
    fn cancel_reason_superseded_json_roundtrip() {
        let r = CancelReason::Superseded {
            by_operation_id: "op_v2".into(),
        };
        let json = serde_json::to_string(&r).unwrap();
        let parsed: CancelReason = serde_json::from_str(&json).unwrap();
        if let CancelReason::Superseded { by_operation_id } = parsed {
            assert_eq!(by_operation_id, "op_v2");
        } else {
            panic!("expected Superseded");
        }
    }

    // ── CleanupBehavior::Full (extended) ──

    #[test]
    fn cleanup_full_zero_timeout() {
        let c = CleanupBehavior::Full { timeout_ms: 0 };
        if let CleanupBehavior::Full { timeout_ms } = c {
            assert_eq!(timeout_ms, 0);
        } else {
            panic!("expected Full");
        }
    }

    #[test]
    fn cleanup_full_json_roundtrip_with_timeout() {
        let c = CleanupBehavior::Full { timeout_ms: 30000 };
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("30000"));
        let parsed: CleanupBehavior = serde_json::from_str(&json).unwrap();
        if let CleanupBehavior::Full { timeout_ms } = parsed {
            assert_eq!(timeout_ms, 30000);
        } else {
            panic!("expected Full");
        }
    }

    // ── CancellationOutcome (extended) ──

    #[test]
    fn outcome_pending_json_roundtrip() {
        let o = CancellationOutcome::Pending;
        let json = serde_json::to_string(&o).unwrap();
        assert_eq!(json, "\"pending\"");
        let parsed: CancellationOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, CancellationOutcome::Pending);
    }

    #[test]
    fn outcome_failed_json_roundtrip() {
        let o = CancellationOutcome::Failed;
        let json = serde_json::to_string(&o).unwrap();
        assert_eq!(json, "\"failed\"");
        let parsed: CancellationOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, CancellationOutcome::Failed);
    }

    #[test]
    fn outcome_all_variants_not_equal() {
        let variants = [
            CancellationOutcome::Cancelled,
            CancellationOutcome::TooLate,
            CancellationOutcome::Pending,
            CancellationOutcome::Failed,
        ];
        for i in 0..variants.len() {
            for j in 0..variants.len() {
                if i == j {
                    assert_eq!(variants[i], variants[j]);
                } else {
                    assert_ne!(variants[i], variants[j]);
                }
            }
        }
    }

    // ── CancellationRequest (extended) ──

    #[test]
    fn request_with_return_partial_true() {
        let req = CancellationRequest {
            operation_id: "op_partial".into(),
            reason: CancelReason::UserRequested,
            cleanup: CleanupBehavior::default(),
            return_partial: true,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("true"));
        let parsed: CancellationRequest = serde_json::from_str(&json).unwrap();
        assert!(parsed.return_partial);
    }

    #[test]
    fn request_with_full_cleanup() {
        let req = CancellationRequest {
            operation_id: "op_full".into(),
            reason: CancelReason::SessionClosing,
            cleanup: CleanupBehavior::Full { timeout_ms: 10000 },
            return_partial: false,
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: CancellationRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.operation_id, "op_full");
        assert!(matches!(
            parsed.cleanup,
            CleanupBehavior::Full { timeout_ms: 10000 }
        ));
    }

    #[test]
    fn request_with_abandon_cleanup() {
        let req = CancellationRequest {
            operation_id: "op_abandon".into(),
            reason: CancelReason::AgentAbort {
                reason: "fatal".into(),
            },
            cleanup: CleanupBehavior::Abandon,
            return_partial: false,
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: CancellationRequest = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed.cleanup, CleanupBehavior::Abandon));
    }

    #[test]
    fn request_with_checkpoint_cleanup() {
        let req = CancellationRequest {
            operation_id: "op_ckpt".into(),
            reason: CancelReason::TimeoutApproaching { remaining_ms: 500 },
            cleanup: CleanupBehavior::Checkpoint,
            return_partial: true,
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: CancellationRequest = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed.cleanup, CleanupBehavior::Checkpoint));
        assert!(parsed.return_partial);
    }

    #[test]
    fn request_cleanup_defaults_when_missing() {
        let json = r#"{"operation_id":"op_x","reason":{"type":"user_requested"}}"#;
        let parsed: CancellationRequest = serde_json::from_str(json).unwrap();
        assert!(matches!(parsed.cleanup, CleanupBehavior::BestEffort));
        assert!(!parsed.return_partial);
    }

    // ── CancellationResponse (extended) ──

    #[test]
    fn response_none_fields_omitted_in_json() {
        let resp = CancellationResponse {
            operation_id: "op_sparse".into(),
            outcome: CancellationOutcome::TooLate,
            partial_result: None,
            checkpoint: None,
            cleanup_result: None,
            duration_ms: 5,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("partial_result"));
        assert!(!json.contains("checkpoint"));
        assert!(!json.contains("cleanup_result"));
    }

    #[test]
    fn response_all_fields_populated() {
        let resp = CancellationResponse {
            operation_id: "op_full_resp".into(),
            outcome: CancellationOutcome::Cancelled,
            partial_result: Some(PartialResult {
                completed_items: 10,
                total_items: Some(50),
                data: Some(serde_json::json!([1, 2, 3])),
            }),
            checkpoint: Some(CheckpointInfo {
                id: "ckpt_99".into(),
                resumable: true,
                expires_at: Some(fixed_now()),
                state: Some(serde_json::json!({"page": 5})),
            }),
            cleanup_result: Some(CleanupResult {
                success: true,
                cleaned: vec!["cache".into(), "temp".into()],
                failed: vec![],
                duration_ms: 3,
            }),
            duration_ms: 12,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: CancellationResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.operation_id, "op_full_resp");
        assert!(parsed.partial_result.is_some());
        assert!(parsed.checkpoint.is_some());
        assert!(parsed.cleanup_result.is_some());
        assert_eq!(parsed.duration_ms, 12);
    }

    // ── PartialResult (extended) ──

    #[test]
    fn partial_result_large_values() {
        let pr = PartialResult {
            completed_items: u64::MAX,
            total_items: Some(u64::MAX),
            data: None,
        };
        let json = serde_json::to_string(&pr).unwrap();
        let parsed: PartialResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.completed_items, u64::MAX);
        assert_eq!(parsed.total_items, Some(u64::MAX));
    }

    #[test]
    fn partial_result_completed_exceeds_total() {
        let pr = PartialResult {
            completed_items: 200,
            total_items: Some(100),
            data: None,
        };
        let json = serde_json::to_string(&pr).unwrap();
        let parsed: PartialResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.completed_items, 200);
        assert_eq!(parsed.total_items, Some(100));
    }

    #[test]
    fn partial_result_with_complex_data() {
        let pr = PartialResult {
            completed_items: 3,
            total_items: None,
            data: Some(serde_json::json!({
                "rows": [
                    {"id": 1, "name": "alpha"},
                    {"id": 2, "name": "beta"},
                    {"id": 3, "name": "gamma"}
                ],
                "metadata": {"source": "test"}
            })),
        };
        let json = serde_json::to_string(&pr).unwrap();
        let parsed: PartialResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.completed_items, 3);
        let data = parsed.data.unwrap();
        assert!(data["rows"].is_array());
        assert_eq!(data["rows"].as_array().unwrap().len(), 3);
    }

    // ── CheckpointInfo (extended) ──

    #[test]
    fn checkpoint_without_state() {
        let ckpt = CheckpointInfo {
            id: "ckpt_no_state".into(),
            resumable: true,
            expires_at: Some(fixed_now()),
            state: None,
        };
        let json = serde_json::to_string(&ckpt).unwrap();
        // "state" as a key should not appear, but "ckpt_no_state" contains
        // the substring "state" in the id — check for the key specifically.
        assert!(!json.contains("\"state\""));
        let parsed: CheckpointInfo = serde_json::from_str(&json).unwrap();
        assert!(parsed.state.is_none());
    }

    #[test]
    fn checkpoint_without_expires_at() {
        let ckpt = CheckpointInfo {
            id: "ckpt_no_expiry".into(),
            resumable: true,
            expires_at: None,
            state: Some(serde_json::json!({"cursor": 42})),
        };
        let json = serde_json::to_string(&ckpt).unwrap();
        assert!(!json.contains("expires_at"));
        let parsed: CheckpointInfo = serde_json::from_str(&json).unwrap();
        assert!(parsed.expires_at.is_none());
        assert!(parsed.state.is_some());
    }

    #[test]
    fn checkpoint_non_resumable() {
        let ckpt = CheckpointInfo {
            id: "ckpt_final".into(),
            resumable: false,
            expires_at: None,
            state: None,
        };
        let json = serde_json::to_string(&ckpt).unwrap();
        let parsed: CheckpointInfo = serde_json::from_str(&json).unwrap();
        assert!(!parsed.resumable);
        assert!(parsed.expires_at.is_none());
        assert!(parsed.state.is_none());
    }

    // ── CleanupResult (extended) ──

    #[test]
    fn cleanup_result_with_failed_items() {
        let cr = CleanupResult {
            success: false,
            cleaned: vec!["cache".into()],
            failed: vec!["lock_file".into(), "temp_dir".into()],
            duration_ms: 500,
        };
        let json = serde_json::to_string(&cr).unwrap();
        let parsed: CleanupResult = serde_json::from_str(&json).unwrap();
        assert!(!parsed.success);
        assert_eq!(parsed.cleaned.len(), 1);
        assert_eq!(parsed.failed.len(), 2);
        assert_eq!(parsed.failed[0], "lock_file");
        assert_eq!(parsed.failed[1], "temp_dir");
    }

    #[test]
    fn cleanup_result_empty_cleaned_list() {
        let cr = CleanupResult {
            success: false,
            cleaned: vec![],
            failed: vec!["everything".into()],
            duration_ms: 100,
        };
        let json = serde_json::to_string(&cr).unwrap();
        let parsed: CleanupResult = serde_json::from_str(&json).unwrap();
        assert!(parsed.cleaned.is_empty());
        assert_eq!(parsed.failed.len(), 1);
    }

    #[test]
    fn cleanup_result_zero_duration() {
        let cr = CleanupResult {
            success: true,
            cleaned: vec!["state".into()],
            failed: vec![],
            duration_ms: 0,
        };
        let json = serde_json::to_string(&cr).unwrap();
        let parsed: CleanupResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.duration_ms, 0);
    }

    #[test]
    fn cleanup_result_both_cleaned_and_failed() {
        let cr = CleanupResult {
            success: false,
            cleaned: vec!["a".into(), "b".into(), "c".into()],
            failed: vec!["d".into(), "e".into()],
            duration_ms: 250,
        };
        let json = serde_json::to_string(&cr).unwrap();
        let parsed: CleanupResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.cleaned.len(), 3);
        assert_eq!(parsed.failed.len(), 2);
        assert!(!parsed.success);
    }

    // ── CancellationAuditEvent (extended) ──

    #[test]
    fn audit_event_json_roundtrip_all_fields() {
        let event = CancellationAuditEvent {
            timestamp: fixed_now(),
            operation_id: "op_audited".into(),
            reason: CancelReason::ResourceLimit {
                resource: "disk".into(),
                current: 980,
                limit: 1000,
            },
            outcome: CancellationOutcome::Cancelled,
            duration_ms: 42,
            had_partial_result: true,
            had_checkpoint: true,
        };
        let json = serde_json::to_string(&event).unwrap();
        let parsed: CancellationAuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.operation_id, "op_audited");
        assert_eq!(parsed.outcome, CancellationOutcome::Cancelled);
        assert_eq!(parsed.duration_ms, 42);
        assert!(parsed.had_partial_result);
        assert!(parsed.had_checkpoint);
        assert_eq!(parsed.reason.label(), "resource_limit");
    }

    #[test]
    fn audit_event_clone() {
        let event = CancellationAuditEvent {
            timestamp: fixed_now(),
            operation_id: "op_clone".into(),
            reason: CancelReason::SessionClosing,
            outcome: CancellationOutcome::Pending,
            duration_ms: 7,
            had_partial_result: false,
            had_checkpoint: false,
        };
        let cloned = event.clone();
        assert_eq!(event.operation_id, "op_clone");
        assert_eq!(cloned.outcome, CancellationOutcome::Pending);
        assert_eq!(cloned.duration_ms, 7);
    }

    // ── CancellationController (extended) ──

    #[test]
    fn controller_track_many_cancel_some() {
        let ctrl = CancellationController::new();
        for i in 0..20 {
            ctrl.track(&format!("op_{i}"));
        }
        assert_eq!(ctrl.tracked_count(), 20);

        // Cancel only even-numbered operations.
        for i in (0..20).step_by(2) {
            let req = cancel_request(&format!("op_{i}"), CancelReason::UserRequested);
            let resp = ctrl.cancel(&req, fixed_now()).unwrap();
            assert_eq!(resp.outcome, CancellationOutcome::Cancelled);
        }
        // Odd operations should not be cancel-requested.
        for i in (1..20).step_by(2) {
            assert!(!ctrl.is_cancel_requested(&format!("op_{i}")));
        }
        // Even operations should be cancel-requested.
        for i in (0..20).step_by(2) {
            assert!(ctrl.is_cancel_requested(&format!("op_{i}")));
        }
        assert_eq!(ctrl.audit_events().len(), 10);
    }

    #[test]
    fn controller_cancel_with_full_cleanup() {
        let ctrl = CancellationController::new();
        ctrl.track("op_full_cleanup");
        let req = CancellationRequest {
            operation_id: "op_full_cleanup".into(),
            reason: CancelReason::UserRequested,
            cleanup: CleanupBehavior::Full { timeout_ms: 3000 },
            return_partial: false,
        };
        let resp = ctrl.cancel(&req, fixed_now()).unwrap();
        assert_eq!(resp.outcome, CancellationOutcome::Cancelled);
        // No checkpoint because cleanup is Full, not Checkpoint.
        assert!(resp.checkpoint.is_none());
        // Cleanup result should be present because outcome is Cancelled.
        assert!(resp.cleanup_result.is_some());
    }

    #[test]
    fn controller_cancel_with_abandon() {
        let ctrl = CancellationController::new();
        ctrl.track("op_abandon");
        let req = CancellationRequest {
            operation_id: "op_abandon".into(),
            reason: CancelReason::AgentAbort {
                reason: "critical".into(),
            },
            cleanup: CleanupBehavior::Abandon,
            return_partial: false,
        };
        let resp = ctrl.cancel(&req, fixed_now()).unwrap();
        assert_eq!(resp.outcome, CancellationOutcome::Cancelled);
        // No checkpoint on Abandon.
        assert!(resp.checkpoint.is_none());
        assert!(resp.cleanup_result.is_some());
    }

    #[test]
    fn controller_retrack_after_remove() {
        let ctrl = CancellationController::new();
        ctrl.track("op_reuse");
        let req = cancel_request("op_reuse", CancelReason::UserRequested);
        ctrl.cancel(&req, fixed_now()).unwrap();
        assert!(ctrl.is_cancel_requested("op_reuse"));

        ctrl.remove("op_reuse");
        assert_eq!(ctrl.tracked_count(), 0);
        assert!(!ctrl.is_cancel_requested("op_reuse"));

        // Re-track the same ID; it should be fresh.
        ctrl.track("op_reuse");
        assert_eq!(ctrl.tracked_count(), 1);
        assert!(!ctrl.is_cancel_requested("op_reuse"));

        // Cancelling again should succeed (not Pending).
        let resp = ctrl.cancel(&req, fixed_now()).unwrap();
        assert_eq!(resp.outcome, CancellationOutcome::Cancelled);
    }

    #[test]
    fn controller_audit_ordering_many_ops() {
        let ctrl = CancellationController::new();
        let ids: Vec<String> = (0..10).map(|i| format!("seq_{i}")).collect();
        for id in &ids {
            ctrl.track(id);
        }
        for id in &ids {
            let req = cancel_request(id, CancelReason::SessionClosing);
            ctrl.cancel(&req, fixed_now()).unwrap();
        }
        let events = ctrl.audit_events();
        assert_eq!(events.len(), 10);
        // Newest first: last cancelled should be first in audit.
        assert_eq!(events[0].operation_id, "seq_9");
        assert_eq!(events[9].operation_id, "seq_0");
    }

    #[test]
    fn controller_clear_audit_then_add_more() {
        let ctrl = CancellationController::new();
        ctrl.track("op_a");
        ctrl.cancel(
            &cancel_request("op_a", CancelReason::UserRequested),
            fixed_now(),
        )
        .unwrap();
        assert_eq!(ctrl.audit_events().len(), 1);

        ctrl.clear_audit_log();
        assert!(ctrl.audit_events().is_empty());

        ctrl.track("op_b");
        ctrl.cancel(
            &cancel_request("op_b", CancelReason::SessionClosing),
            fixed_now(),
        )
        .unwrap();
        let events = ctrl.audit_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation_id, "op_b");
    }

    #[test]
    fn controller_track_cancel_remove_retrack_lifecycle() {
        let ctrl = CancellationController::new();

        // Phase 1: Track and cancel.
        ctrl.track("lifecycle_op");
        assert_eq!(ctrl.tracked_count(), 1);
        let req = cancel_request("lifecycle_op", CancelReason::UserRequested);
        let resp = ctrl.cancel(&req, fixed_now()).unwrap();
        assert_eq!(resp.outcome, CancellationOutcome::Cancelled);
        assert!(ctrl.is_cancel_requested("lifecycle_op"));

        // Phase 2: Remove.
        ctrl.remove("lifecycle_op");
        assert_eq!(ctrl.tracked_count(), 0);
        // Cancel after remove should error.
        let err = ctrl.cancel(&req, fixed_now()).unwrap_err();
        assert!(err.to_string().contains("operation not found"));

        // Phase 3: Re-track.
        ctrl.track("lifecycle_op");
        assert!(!ctrl.is_cancel_requested("lifecycle_op"));

        // Phase 4: Complete then try cancel.
        ctrl.complete("lifecycle_op");
        let resp2 = ctrl.cancel(&req, fixed_now()).unwrap();
        assert_eq!(resp2.outcome, CancellationOutcome::TooLate);

        // Audit should have 3 entries total (cancel, error is not audited, cancel again).
        // The error path returns Err before recording audit, so only 2 successful cancel calls recorded.
        assert_eq!(ctrl.audit_events().len(), 2);
    }

    // ── Edge cases ──

    #[test]
    fn empty_string_operation_id() {
        let ctrl = CancellationController::new();
        ctrl.track("");
        assert_eq!(ctrl.tracked_count(), 1);
        let req = cancel_request("", CancelReason::UserRequested);
        let resp = ctrl.cancel(&req, fixed_now()).unwrap();
        assert_eq!(resp.outcome, CancellationOutcome::Cancelled);
        assert_eq!(resp.operation_id, "");
        ctrl.remove("");
        assert_eq!(ctrl.tracked_count(), 0);
    }

    #[test]
    fn very_long_operation_id() {
        let long_id = "x".repeat(10000);
        let ctrl = CancellationController::new();
        ctrl.track(&long_id);
        let req = cancel_request(&long_id, CancelReason::UserRequested);
        let resp = ctrl.cancel(&req, fixed_now()).unwrap();
        assert_eq!(resp.outcome, CancellationOutcome::Cancelled);
        assert_eq!(resp.operation_id, long_id);
    }

    #[test]
    fn many_cancellations_of_same_op_after_retracks() {
        let ctrl = CancellationController::new();
        for _ in 0..50 {
            ctrl.track("repeated");
            let req = cancel_request("repeated", CancelReason::UserRequested);
            let resp = ctrl.cancel(&req, fixed_now()).unwrap();
            assert_eq!(resp.outcome, CancellationOutcome::Cancelled);
            ctrl.remove("repeated");
        }
        assert_eq!(ctrl.tracked_count(), 0);
        assert_eq!(ctrl.audit_events().len(), 50);
    }

    #[test]
    fn cancel_with_superseded_preserves_by_operation_id_in_audit() {
        let ctrl = CancellationController::new();
        ctrl.track("old_op");
        let req = cancel_request(
            "old_op",
            CancelReason::Superseded {
                by_operation_id: "new_op_v2".into(),
            },
        );
        ctrl.cancel(&req, fixed_now()).unwrap();
        let events = ctrl.audit_events();
        assert_eq!(events.len(), 1);
        if let CancelReason::Superseded { by_operation_id } = &events[0].reason {
            assert_eq!(by_operation_id, "new_op_v2");
        } else {
            panic!("expected Superseded reason in audit");
        }
    }

    #[test]
    fn cancel_pending_has_cleanup_result() {
        let ctrl = CancellationController::new();
        ctrl.track("op_pending");
        let req = cancel_request("op_pending", CancelReason::UserRequested);
        ctrl.cancel(&req, fixed_now()).unwrap(); // First: Cancelled
        let resp = ctrl.cancel(&req, fixed_now()).unwrap(); // Second: Pending
        assert_eq!(resp.outcome, CancellationOutcome::Pending);
        // Pending also gets a cleanup result per the controller logic.
        assert!(resp.cleanup_result.is_some());
    }

    #[test]
    fn checkpoint_id_format_includes_operation_id() {
        let ctrl = CancellationController::new();
        ctrl.track("my_special_op");
        let req = CancellationRequest {
            operation_id: "my_special_op".into(),
            reason: CancelReason::UserRequested,
            cleanup: CleanupBehavior::Checkpoint,
            return_partial: false,
        };
        let resp = ctrl.cancel(&req, fixed_now()).unwrap();
        let ckpt = resp.checkpoint.unwrap();
        assert_eq!(ckpt.id, "ckpt_my_special_op");
    }

    #[test]
    fn checkpoint_expires_24h_from_now() {
        let now = fixed_now();
        let ctrl = CancellationController::new();
        ctrl.track("op_expiry");
        let req = CancellationRequest {
            operation_id: "op_expiry".into(),
            reason: CancelReason::UserRequested,
            cleanup: CleanupBehavior::Checkpoint,
            return_partial: false,
        };
        let resp = ctrl.cancel(&req, now).unwrap();
        let ckpt = resp.checkpoint.unwrap();
        let expected_expiry = now + chrono::Duration::hours(24);
        assert_eq!(ckpt.expires_at, Some(expected_expiry));
    }

    #[test]
    fn audit_event_not_recorded_on_error() {
        let ctrl = CancellationController::new();
        // No tracking — cancel should error.
        let req = cancel_request("ghost_op", CancelReason::UserRequested);
        let result = ctrl.cancel(&req, fixed_now());
        assert!(result.is_err());
        // No audit event should be recorded for errors.
        assert!(ctrl.audit_events().is_empty());
    }

    #[test]
    fn controller_remove_cancelled_does_not_affect_audit() {
        let ctrl = CancellationController::new();
        ctrl.track("op_logged");
        ctrl.cancel(
            &cancel_request("op_logged", CancelReason::UserRequested),
            fixed_now(),
        )
        .unwrap();
        assert_eq!(ctrl.audit_events().len(), 1);

        // Removing the operation does not clear its audit entry.
        ctrl.remove("op_logged");
        assert_eq!(ctrl.audit_events().len(), 1);
        assert_eq!(ctrl.audit_events()[0].operation_id, "op_logged");
    }

    #[test]
    fn controller_complete_does_not_record_audit() {
        let ctrl = CancellationController::new();
        ctrl.track("op_complete_only");
        ctrl.complete("op_complete_only");
        // Completing without cancelling should produce no audit events.
        assert!(ctrl.audit_events().is_empty());
    }

    #[test]
    fn response_partial_result_is_none_from_controller() {
        // The controller always sets partial_result to None.
        // Callers are responsible for attaching partial results.
        let ctrl = CancellationController::new();
        ctrl.track("op_no_partial");
        let req = CancellationRequest {
            operation_id: "op_no_partial".into(),
            reason: CancelReason::UserRequested,
            cleanup: CleanupBehavior::default(),
            return_partial: true, // Even with return_partial=true
        };
        let resp = ctrl.cancel(&req, fixed_now()).unwrap();
        assert!(resp.partial_result.is_none());
    }

    #[test]
    fn audit_had_partial_result_always_false_from_controller() {
        // The controller always sets had_partial_result to false.
        let ctrl = CancellationController::new();
        ctrl.track("op_audit_partial");
        let req = CancellationRequest {
            operation_id: "op_audit_partial".into(),
            reason: CancelReason::UserRequested,
            cleanup: CleanupBehavior::default(),
            return_partial: true,
        };
        ctrl.cancel(&req, fixed_now()).unwrap();
        let events = ctrl.audit_events();
        assert!(!events[0].had_partial_result);
    }

    #[test]
    fn controller_track_overwrites_cancelled_state() {
        let ctrl = CancellationController::new();
        ctrl.track("op_overwrite");
        let req = cancel_request("op_overwrite", CancelReason::UserRequested);
        ctrl.cancel(&req, fixed_now()).unwrap();
        assert!(ctrl.is_cancel_requested("op_overwrite"));

        // Re-tracking should reset the state (overwrite).
        ctrl.track("op_overwrite");
        assert!(!ctrl.is_cancel_requested("op_overwrite"));
        assert_eq!(ctrl.tracked_count(), 1);
    }

    #[test]
    fn controller_track_overwrites_completed_state() {
        let ctrl = CancellationController::new();
        ctrl.track("op_reset");
        ctrl.complete("op_reset");
        // Cancel returns TooLate.
        let req = cancel_request("op_reset", CancelReason::UserRequested);
        let resp = ctrl.cancel(&req, fixed_now()).unwrap();
        assert_eq!(resp.outcome, CancellationOutcome::TooLate);

        // Re-track resets; cancel should now succeed.
        ctrl.track("op_reset");
        let resp2 = ctrl.cancel(&req, fixed_now()).unwrap();
        assert_eq!(resp2.outcome, CancellationOutcome::Cancelled);
    }

    #[test]
    fn cancel_reason_agent_abort_empty_reason() {
        let r = CancelReason::AgentAbort {
            reason: String::new(),
        };
        assert_eq!(r.label(), "agent_abort");
        let json = serde_json::to_string(&r).unwrap();
        let parsed: CancelReason = serde_json::from_str(&json).unwrap();
        if let CancelReason::AgentAbort { reason } = parsed {
            assert!(reason.is_empty());
        } else {
            panic!("expected AgentAbort");
        }
    }

    #[test]
    fn multiple_ops_different_reasons_in_audit() {
        let ctrl = CancellationController::new();
        ctrl.track("op_user");
        ctrl.track("op_timeout");
        ctrl.track("op_resource");

        ctrl.cancel(
            &cancel_request("op_user", CancelReason::UserRequested),
            fixed_now(),
        )
        .unwrap();
        ctrl.cancel(
            &cancel_request(
                "op_timeout",
                CancelReason::TimeoutApproaching { remaining_ms: 100 },
            ),
            fixed_now(),
        )
        .unwrap();
        ctrl.cancel(
            &cancel_request(
                "op_resource",
                CancelReason::ResourceLimit {
                    resource: "mem".into(),
                    current: 95,
                    limit: 100,
                },
            ),
            fixed_now(),
        )
        .unwrap();

        let events = ctrl.audit_events();
        assert_eq!(events.len(), 3);
        // Newest first.
        assert_eq!(events[0].reason.label(), "resource_limit");
        assert_eq!(events[1].reason.label(), "timeout_approaching");
        assert_eq!(events[2].reason.label(), "user_requested");
    }

    #[test]
    fn cancel_error_message_includes_operation_id() {
        let ctrl = CancellationController::new();
        let req = cancel_request("missing_op_xyz", CancelReason::UserRequested);
        let err = ctrl.cancel(&req, fixed_now()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("missing_op_xyz"));
    }

    #[test]
    fn cleanup_result_on_pending_contains_operation_state() {
        let ctrl = CancellationController::new();
        ctrl.track("op_pending_cleanup");
        let req = cancel_request("op_pending_cleanup", CancelReason::UserRequested);
        ctrl.cancel(&req, fixed_now()).unwrap(); // Cancelled
        let resp = ctrl.cancel(&req, fixed_now()).unwrap(); // Pending
        let cleanup = resp.cleanup_result.unwrap();
        assert!(cleanup.cleaned.contains(&"operation_state".to_string()));
    }

    #[test]
    fn no_checkpoint_on_pending_even_with_checkpoint_cleanup() {
        let ctrl = CancellationController::new();
        ctrl.track("op_ckpt_pending");
        let req = CancellationRequest {
            operation_id: "op_ckpt_pending".into(),
            reason: CancelReason::UserRequested,
            cleanup: CleanupBehavior::Checkpoint,
            return_partial: false,
        };
        // First cancel: Cancelled, should have checkpoint.
        let resp1 = ctrl.cancel(&req, fixed_now()).unwrap();
        assert_eq!(resp1.outcome, CancellationOutcome::Cancelled);
        assert!(resp1.checkpoint.is_some());

        // Second cancel: Pending, cancel_requested is already true.
        // Outcome is Pending, and checkpoint is only created when outcome == Cancelled.
        let resp2 = ctrl.cancel(&req, fixed_now()).unwrap();
        assert_eq!(resp2.outcome, CancellationOutcome::Pending);
        assert!(resp2.checkpoint.is_none());
    }

    #[test]
    fn audit_timestamp_matches_provided_now() {
        let now = Utc.with_ymd_and_hms(2025, 1, 15, 8, 30, 0).unwrap();
        let ctrl = CancellationController::new();
        ctrl.track("op_ts");
        ctrl.cancel(&cancel_request("op_ts", CancelReason::UserRequested), now)
            .unwrap();
        let events = ctrl.audit_events();
        assert_eq!(events[0].timestamp, now);
    }

}
