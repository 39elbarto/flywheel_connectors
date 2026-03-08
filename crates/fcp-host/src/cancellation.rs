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
}
