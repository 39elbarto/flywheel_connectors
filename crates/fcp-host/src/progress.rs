//! Long-running operation progress: real-time feedback and phase tracking.
//!
//! Provides types and logic for tracking progress of long-running operations:
//! - Progress updates with current/total, rate, ETA, and human-readable messages
//! - Phase transitions for multi-step operations
//! - Throttled update emission (configurable interval)
//! - Aggregated progress for batch operations
//! - Integration with the cancellation controller
//!
//! Based on bead `flywheel_connectors-w82c`.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Progress Unit
// ─────────────────────────────────────────────────────────────────────────────

/// Unit of measurement for progress values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgressUnit {
    /// Byte count.
    Bytes,
    /// Item count.
    Items,
    /// HTTP request count.
    Requests,
    /// Database row count.
    Rows,
    /// Custom unit with a label.
    Custom(String),
}

impl ProgressUnit {
    /// Human-readable label for this unit.
    #[must_use]
    pub fn label(&self) -> &str {
        match self {
            Self::Bytes => "bytes",
            Self::Items => "items",
            Self::Requests => "requests",
            Self::Rows => "rows",
            Self::Custom(s) => s,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Progress Update
// ─────────────────────────────────────────────────────────────────────────────

/// A snapshot of progress for an operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressUpdate {
    /// Current phase name (e.g. "uploading", "verifying").
    pub phase: String,
    /// Current progress value.
    pub current: u64,
    /// Total expected value (if known).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
    /// Unit of measurement.
    pub unit: ProgressUnit,
    /// Computed percentage (0.0–100.0), if total is known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub percentage: Option<f64>,
    /// Rate per second (in the same unit), if calculable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate: Option<u64>,
    /// Estimated time remaining in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eta_ms: Option<u64>,
    /// Human-readable status message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl ProgressUpdate {
    /// Compute percentage from current/total if total is known and non-zero.
    #[must_use]
    pub fn computed_percentage(&self) -> Option<f64> {
        self.total.and_then(|t| {
            if t == 0 {
                None
            } else {
                #[allow(clippy::cast_precision_loss)]
                Some(self.current as f64 / t as f64 * 100.0)
            }
        })
    }

    /// Whether progress is indeterminate (total unknown).
    #[must_use]
    pub const fn is_indeterminate(&self) -> bool {
        self.total.is_none()
    }

    /// Whether the operation has reached completion.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.total.is_some_and(|t| self.current >= t)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase Transition
// ─────────────────────────────────────────────────────────────────────────────

/// A transition between phases of a multi-step operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseTransition {
    /// Phase being exited.
    pub from_phase: String,
    /// Phase being entered.
    pub to_phase: String,
    /// Remaining phases after the current one.
    pub phases_remaining: Vec<String>,
    /// When the transition occurred.
    pub timestamp: DateTime<Utc>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Progress Notification (unified envelope)
// ─────────────────────────────────────────────────────────────────────────────

/// A progress notification emitted by the host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressNotification {
    /// Operation this notification belongs to.
    pub operation_id: String,
    /// Correlating request ID.
    pub request_id: u64,
    /// The notification payload.
    pub payload: ProgressPayload,
    /// When this notification was created.
    pub timestamp: DateTime<Utc>,
}

/// Payload of a progress notification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProgressPayload {
    /// A progress update with metrics.
    Update(ProgressUpdate),
    /// A phase transition.
    Phase(PhaseTransition),
}

// ─────────────────────────────────────────────────────────────────────────────
// Progress Options
// ─────────────────────────────────────────────────────────────────────────────

/// Options for progress streaming on an invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressOptions {
    /// Whether to stream progress updates.
    #[serde(default)]
    pub stream_progress: bool,
    /// Minimum interval between progress updates in milliseconds.
    #[serde(default = "default_progress_interval_ms")]
    pub progress_interval_ms: u64,
}

const fn default_progress_interval_ms() -> u64 {
    500
}

impl Default for ProgressOptions {
    fn default() -> Self {
        Self {
            stream_progress: false,
            progress_interval_ms: default_progress_interval_ms(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tracked Operation Progress
// ─────────────────────────────────────────────────────────────────────────────

/// Internal state for a tracked operation's progress.
#[derive(Debug, Clone)]
struct TrackedProgress {
    /// Request ID for correlation.
    request_id: u64,
    /// Current phase.
    current_phase: String,
    /// Phases already completed.
    completed_phases: Vec<String>,
    /// All known phases remaining after current.
    remaining_phases: Vec<String>,
    /// Latest progress update.
    latest_update: Option<ProgressUpdate>,
    /// All emitted notifications (for replay/audit).
    notifications: Vec<ProgressNotification>,
    /// When tracking started.
    started_at: Instant,
    /// When the last update was emitted (for throttling).
    last_emitted: Option<Instant>,
    /// Throttle interval.
    interval: Duration,
}

// ─────────────────────────────────────────────────────────────────────────────
// Aggregated Progress (for batch operations)
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregated progress across multiple operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedProgress {
    /// Total operations being tracked.
    pub total_operations: usize,
    /// Operations that have completed.
    pub completed_operations: usize,
    /// Operations currently in progress.
    pub in_progress_operations: usize,
    /// Overall percentage (average of individual percentages).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overall_percentage: Option<f64>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Progress Controller
// ─────────────────────────────────────────────────────────────────────────────

/// Controller that manages progress tracking for multiple operations.
///
/// # Panics
///
/// Methods that access the internal mutex will panic if the mutex is
/// poisoned (only possible if a thread panicked while holding the lock).
pub struct ProgressController {
    operations: Mutex<HashMap<String, TrackedProgress>>,
}

impl std::fmt::Debug for ProgressController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProgressController")
            .field("operations", &format_args!("<Mutex>"))
            .finish()
    }
}

impl ProgressController {
    /// Create a new progress controller.
    #[must_use]
    pub fn new() -> Self {
        Self {
            operations: Mutex::new(HashMap::new()),
        }
    }

    /// Start tracking progress for an operation.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn start_tracking(
        &self,
        operation_id: &str,
        request_id: u64,
        initial_phase: &str,
        options: &ProgressOptions,
    ) {
        let tracked = TrackedProgress {
            request_id,
            current_phase: initial_phase.to_string(),
            completed_phases: Vec::new(),
            remaining_phases: Vec::new(),
            latest_update: None,
            notifications: Vec::new(),
            started_at: Instant::now(),
            last_emitted: None,
            interval: Duration::from_millis(options.progress_interval_ms),
        };
        self.operations
            .lock()
            .expect("progress lock")
            .insert(operation_id.to_string(), tracked);
    }

    /// Record a progress update for an operation.
    ///
    /// Returns `true` if the update was emitted (i.e. enough time passed
    /// since the last emission based on the throttle interval), `false`
    /// if it was throttled. The latest update is always recorded internally
    /// regardless of throttling.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn record_update(
        &self,
        operation_id: &str,
        update: ProgressUpdate,
        now: DateTime<Utc>,
    ) -> bool {
        let mut ops = self.operations.lock().expect("progress lock");
        let Some(tracked) = ops.get_mut(operation_id) else {
            return false;
        };

        tracked.latest_update = Some(update.clone());

        let should_emit = match tracked.last_emitted {
            None => true,
            Some(last) => last.elapsed() >= tracked.interval,
        };

        if should_emit {
            tracked.last_emitted = Some(Instant::now());
            let notification = ProgressNotification {
                operation_id: operation_id.to_string(),
                request_id: tracked.request_id,
                payload: ProgressPayload::Update(update),
                timestamp: now,
            };
            tracked.notifications.push(notification);
        }

        drop(ops);
        should_emit
    }

    /// Record a phase transition (always emitted, never throttled).
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn record_phase_transition(
        &self,
        operation_id: &str,
        to_phase: &str,
        remaining: &[&str],
        now: DateTime<Utc>,
    ) -> bool {
        let mut ops = self.operations.lock().expect("progress lock");
        let Some(tracked) = ops.get_mut(operation_id) else {
            return false;
        };

        let from_phase = tracked.current_phase.clone();
        tracked.completed_phases.push(from_phase.clone());
        tracked.current_phase = to_phase.to_string();
        tracked.remaining_phases = remaining.iter().map(|s| (*s).to_string()).collect();

        let transition = PhaseTransition {
            from_phase,
            to_phase: to_phase.to_string(),
            phases_remaining: tracked.remaining_phases.clone(),
            timestamp: now,
        };
        let notification = ProgressNotification {
            operation_id: operation_id.to_string(),
            request_id: tracked.request_id,
            payload: ProgressPayload::Phase(transition),
            timestamp: now,
        };
        tracked.notifications.push(notification);
        drop(ops);
        true
    }

    /// Get the latest progress update for an operation.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn latest_update(&self, operation_id: &str) -> Option<ProgressUpdate> {
        self.operations
            .lock()
            .expect("progress lock")
            .get(operation_id)
            .and_then(|t| t.latest_update.clone())
    }

    /// Get the current phase of an operation.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn current_phase(&self, operation_id: &str) -> Option<String> {
        self.operations
            .lock()
            .expect("progress lock")
            .get(operation_id)
            .map(|t| t.current_phase.clone())
    }

    /// Get all notifications emitted for an operation.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn notifications(&self, operation_id: &str) -> Vec<ProgressNotification> {
        self.operations
            .lock()
            .expect("progress lock")
            .get(operation_id)
            .map_or_else(Vec::new, |t| t.notifications.clone())
    }

    /// Get the number of tracked operations.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn tracked_count(&self) -> usize {
        self.operations.lock().expect("progress lock").len()
    }

    /// Stop tracking an operation and return its notifications.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn stop_tracking(&self, operation_id: &str) -> Vec<ProgressNotification> {
        self.operations
            .lock()
            .expect("progress lock")
            .remove(operation_id)
            .map_or_else(Vec::new, |t| t.notifications)
    }

    /// Get elapsed time since tracking started for an operation.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn elapsed_ms(&self, operation_id: &str) -> Option<u64> {
        self.operations
            .lock()
            .expect("progress lock")
            .get(operation_id)
            .map(|t| u64::try_from(t.started_at.elapsed().as_millis()).unwrap_or(u64::MAX))
    }

    /// Compute aggregated progress across all tracked operations.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn aggregate(&self) -> AggregatedProgress {
        let ops = self.operations.lock().expect("progress lock");
        let total = ops.len();
        let mut completed = 0usize;
        let mut in_progress = 0usize;
        let mut pct_sum = 0.0f64;
        let mut pct_count = 0usize;

        for tracked in ops.values() {
            if tracked
                .latest_update
                .as_ref()
                .is_some_and(ProgressUpdate::is_complete)
            {
                completed += 1;
            } else {
                in_progress += 1;
            }

            if let Some(pct) = tracked
                .latest_update
                .as_ref()
                .and_then(ProgressUpdate::computed_percentage)
            {
                pct_sum += pct;
                pct_count += 1;
            }
        }
        drop(ops);

        AggregatedProgress {
            total_operations: total,
            completed_operations: completed,
            in_progress_operations: in_progress,
            overall_percentage: if pct_count > 0 {
                #[allow(clippy::cast_precision_loss)]
                Some(pct_sum / pct_count as f64)
            } else {
                None
            },
        }
    }

    /// Get completed phases for an operation.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn completed_phases(&self, operation_id: &str) -> Vec<String> {
        self.operations
            .lock()
            .expect("progress lock")
            .get(operation_id)
            .map_or_else(Vec::new, |t| t.completed_phases.clone())
    }
}

impl Default for ProgressController {
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

    fn fixed_now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 3, 7, 12, 0, 0).unwrap()
    }

    fn default_opts() -> ProgressOptions {
        ProgressOptions {
            stream_progress: true,
            progress_interval_ms: 500,
        }
    }

    fn zero_throttle_opts() -> ProgressOptions {
        ProgressOptions {
            stream_progress: true,
            progress_interval_ms: 0,
        }
    }

    fn make_update(phase: &str, current: u64, total: Option<u64>) -> ProgressUpdate {
        ProgressUpdate {
            phase: phase.into(),
            current,
            total,
            unit: ProgressUnit::Items,
            percentage: total.map(|t| {
                if t == 0 {
                    0.0
                } else {
                    #[allow(clippy::cast_precision_loss)]
                    {
                        current as f64 / t as f64 * 100.0
                    }
                }
            }),
            rate: None,
            eta_ms: None,
            message: None,
        }
    }

    // ── ProgressUnit tests ──

    #[test]
    fn unit_bytes_label() {
        assert_eq!(ProgressUnit::Bytes.label(), "bytes");
    }

    #[test]
    fn unit_items_label() {
        assert_eq!(ProgressUnit::Items.label(), "items");
    }

    #[test]
    fn unit_requests_label() {
        assert_eq!(ProgressUnit::Requests.label(), "requests");
    }

    #[test]
    fn unit_rows_label() {
        assert_eq!(ProgressUnit::Rows.label(), "rows");
    }

    #[test]
    fn unit_custom_label() {
        let u = ProgressUnit::Custom("pages".into());
        assert_eq!(u.label(), "pages");
    }

    #[test]
    fn unit_json_roundtrip() {
        let u = ProgressUnit::Bytes;
        let json = serde_json::to_string(&u).unwrap();
        let parsed: ProgressUnit = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, ProgressUnit::Bytes);
    }

    #[test]
    fn unit_custom_json_roundtrip() {
        let u = ProgressUnit::Custom("chunks".into());
        let json = serde_json::to_string(&u).unwrap();
        let parsed: ProgressUnit = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, u);
    }

    #[test]
    fn unit_equality() {
        assert_eq!(ProgressUnit::Bytes, ProgressUnit::Bytes);
        assert_ne!(ProgressUnit::Bytes, ProgressUnit::Items);
    }

    // ── ProgressUpdate tests ──

    #[test]
    fn update_computed_percentage_with_total() {
        let u = make_update("uploading", 50, Some(200));
        assert!((u.computed_percentage().unwrap() - 25.0).abs() < f64::EPSILON);
    }

    #[test]
    fn update_computed_percentage_without_total() {
        let u = make_update("scanning", 50, None);
        assert!(u.computed_percentage().is_none());
    }

    #[test]
    fn update_computed_percentage_zero_total() {
        let u = make_update("empty", 0, Some(0));
        assert!(u.computed_percentage().is_none());
    }

    #[test]
    fn update_is_indeterminate() {
        let u = make_update("scanning", 10, None);
        assert!(u.is_indeterminate());
    }

    #[test]
    fn update_is_not_indeterminate() {
        let u = make_update("uploading", 10, Some(100));
        assert!(!u.is_indeterminate());
    }

    #[test]
    fn update_is_complete() {
        let u = make_update("done", 100, Some(100));
        assert!(u.is_complete());
    }

    #[test]
    fn update_is_complete_over() {
        let u = make_update("done", 110, Some(100));
        assert!(u.is_complete());
    }

    #[test]
    fn update_is_not_complete() {
        let u = make_update("working", 50, Some(100));
        assert!(!u.is_complete());
    }

    #[test]
    fn update_is_not_complete_indeterminate() {
        let u = make_update("scanning", 50, None);
        assert!(!u.is_complete());
    }

    #[test]
    fn update_json_roundtrip() {
        let u = ProgressUpdate {
            phase: "uploading".into(),
            current: 500,
            total: Some(1000),
            unit: ProgressUnit::Bytes,
            percentage: Some(50.0),
            rate: Some(1000),
            eta_ms: Some(500),
            message: Some("Uploading chunk 5 of 10".into()),
        };
        let json = serde_json::to_string(&u).unwrap();
        let parsed: ProgressUpdate = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.current, 500);
        assert_eq!(parsed.phase, "uploading");
        assert_eq!(parsed.rate, Some(1000));
    }

    #[test]
    fn update_json_skips_none_fields() {
        let u = make_update("scanning", 10, None);
        let json = serde_json::to_string(&u).unwrap();
        assert!(!json.contains("total"));
        assert!(!json.contains("rate"));
        assert!(!json.contains("eta_ms"));
        assert!(!json.contains("message"));
    }

    // ── PhaseTransition tests ──

    #[test]
    fn phase_transition_json_roundtrip() {
        let pt = PhaseTransition {
            from_phase: "preparing".into(),
            to_phase: "uploading".into(),
            phases_remaining: vec!["verifying".into(), "completing".into()],
            timestamp: fixed_now(),
        };
        let json = serde_json::to_string(&pt).unwrap();
        let parsed: PhaseTransition = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.from_phase, "preparing");
        assert_eq!(parsed.to_phase, "uploading");
        assert_eq!(parsed.phases_remaining.len(), 2);
    }

    #[test]
    fn phase_transition_empty_remaining() {
        let pt = PhaseTransition {
            from_phase: "verifying".into(),
            to_phase: "completing".into(),
            phases_remaining: vec![],
            timestamp: fixed_now(),
        };
        let json = serde_json::to_string(&pt).unwrap();
        let parsed: PhaseTransition = serde_json::from_str(&json).unwrap();
        assert!(parsed.phases_remaining.is_empty());
    }

    // ── ProgressNotification tests ──

    #[test]
    fn notification_update_json_roundtrip() {
        let n = ProgressNotification {
            operation_id: "op_1".into(),
            request_id: 42,
            payload: ProgressPayload::Update(make_update("uploading", 50, Some(100))),
            timestamp: fixed_now(),
        };
        let json = serde_json::to_string(&n).unwrap();
        let parsed: ProgressNotification = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.operation_id, "op_1");
        assert_eq!(parsed.request_id, 42);
        assert!(matches!(parsed.payload, ProgressPayload::Update(_)));
    }

    #[test]
    fn notification_phase_json_roundtrip() {
        let n = ProgressNotification {
            operation_id: "op_1".into(),
            request_id: 7,
            payload: ProgressPayload::Phase(PhaseTransition {
                from_phase: "a".into(),
                to_phase: "b".into(),
                phases_remaining: vec!["c".into()],
                timestamp: fixed_now(),
            }),
            timestamp: fixed_now(),
        };
        let json = serde_json::to_string(&n).unwrap();
        let parsed: ProgressNotification = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed.payload, ProgressPayload::Phase(_)));
    }

    // ── ProgressOptions tests ──

    #[test]
    fn options_default() {
        let opts = ProgressOptions::default();
        assert!(!opts.stream_progress);
        assert_eq!(opts.progress_interval_ms, 500);
    }

    #[test]
    fn options_json_roundtrip() {
        let opts = ProgressOptions {
            stream_progress: true,
            progress_interval_ms: 250,
        };
        let json = serde_json::to_string(&opts).unwrap();
        let parsed: ProgressOptions = serde_json::from_str(&json).unwrap();
        assert!(parsed.stream_progress);
        assert_eq!(parsed.progress_interval_ms, 250);
    }

    #[test]
    fn options_json_defaults_applied() {
        let json = r#"{"stream_progress": true}"#;
        let parsed: ProgressOptions = serde_json::from_str(json).unwrap();
        assert!(parsed.stream_progress);
        assert_eq!(parsed.progress_interval_ms, 500);
    }

    // ── ProgressController: basic tracking ──

    #[test]
    fn controller_new_is_empty() {
        let ctrl = ProgressController::new();
        assert_eq!(ctrl.tracked_count(), 0);
    }

    #[test]
    fn controller_default_is_empty() {
        let ctrl = ProgressController::default();
        assert_eq!(ctrl.tracked_count(), 0);
    }

    #[test]
    fn controller_debug() {
        let ctrl = ProgressController::new();
        let dbg = format!("{ctrl:?}");
        assert!(dbg.contains("ProgressController"));
        assert!(dbg.contains("operations"));
    }

    #[test]
    fn start_tracking_increases_count() {
        let ctrl = ProgressController::new();
        ctrl.start_tracking("op1", 1, "init", &default_opts());
        assert_eq!(ctrl.tracked_count(), 1);
        ctrl.start_tracking("op2", 2, "init", &default_opts());
        assert_eq!(ctrl.tracked_count(), 2);
    }

    #[test]
    fn start_tracking_same_id_overwrites() {
        let ctrl = ProgressController::new();
        ctrl.start_tracking("op1", 1, "phase_a", &default_opts());
        ctrl.start_tracking("op1", 2, "phase_b", &default_opts());
        assert_eq!(ctrl.tracked_count(), 1);
        assert_eq!(ctrl.current_phase("op1").unwrap(), "phase_b");
    }

    #[test]
    fn stop_tracking_decreases_count() {
        let ctrl = ProgressController::new();
        ctrl.start_tracking("op1", 1, "init", &default_opts());
        ctrl.start_tracking("op2", 2, "init", &default_opts());
        let notifs = ctrl.stop_tracking("op1");
        assert!(notifs.is_empty());
        assert_eq!(ctrl.tracked_count(), 1);
    }

    #[test]
    fn stop_tracking_unknown_returns_empty() {
        let ctrl = ProgressController::new();
        let notifs = ctrl.stop_tracking("nonexistent");
        assert!(notifs.is_empty());
    }

    // ── ProgressController: updates ──

    #[test]
    fn record_update_first_always_emits() {
        let ctrl = ProgressController::new();
        ctrl.start_tracking("op1", 1, "working", &default_opts());
        let emitted = ctrl.record_update("op1", make_update("working", 10, Some(100)), fixed_now());
        assert!(emitted);
    }

    #[test]
    fn record_update_unknown_op_returns_false() {
        let ctrl = ProgressController::new();
        let emitted = ctrl.record_update(
            "nonexistent",
            make_update("working", 10, Some(100)),
            fixed_now(),
        );
        assert!(!emitted);
    }

    #[test]
    fn record_update_stores_latest() {
        let ctrl = ProgressController::new();
        ctrl.start_tracking("op1", 1, "working", &zero_throttle_opts());
        ctrl.record_update("op1", make_update("working", 10, Some(100)), fixed_now());
        ctrl.record_update("op1", make_update("working", 50, Some(100)), fixed_now());
        let latest = ctrl.latest_update("op1").unwrap();
        assert_eq!(latest.current, 50);
    }

    #[test]
    fn latest_update_unknown_returns_none() {
        let ctrl = ProgressController::new();
        assert!(ctrl.latest_update("nonexistent").is_none());
    }

    #[test]
    fn record_update_throttled() {
        let ctrl = ProgressController::new();
        // Use a large interval so subsequent updates are throttled.
        let opts = ProgressOptions {
            stream_progress: true,
            progress_interval_ms: 60_000,
        };
        ctrl.start_tracking("op1", 1, "working", &opts);
        let first = ctrl.record_update("op1", make_update("working", 10, Some(100)), fixed_now());
        assert!(first);
        // Second update immediately after should be throttled.
        let second = ctrl.record_update("op1", make_update("working", 20, Some(100)), fixed_now());
        assert!(!second);
        // But the latest is still recorded internally.
        assert_eq!(ctrl.latest_update("op1").unwrap().current, 20);
    }

    #[test]
    fn record_update_zero_interval_always_emits() {
        let ctrl = ProgressController::new();
        ctrl.start_tracking("op1", 1, "working", &zero_throttle_opts());
        for i in 0..5 {
            let emitted = ctrl.record_update(
                "op1",
                make_update("working", i * 10, Some(100)),
                fixed_now(),
            );
            assert!(emitted);
        }
    }

    // ── ProgressController: phase transitions ──

    #[test]
    fn phase_transition_recorded() {
        let ctrl = ProgressController::new();
        ctrl.start_tracking("op1", 1, "preparing", &default_opts());
        let recorded =
            ctrl.record_phase_transition("op1", "uploading", &["verifying"], fixed_now());
        assert!(recorded);
        assert_eq!(ctrl.current_phase("op1").unwrap(), "uploading");
    }

    #[test]
    fn phase_transition_unknown_op_returns_false() {
        let ctrl = ProgressController::new();
        let recorded = ctrl.record_phase_transition("nonexistent", "uploading", &[], fixed_now());
        assert!(!recorded);
    }

    #[test]
    fn phase_transition_tracks_completed_phases() {
        let ctrl = ProgressController::new();
        ctrl.start_tracking("op1", 1, "phase_a", &default_opts());
        ctrl.record_phase_transition("op1", "phase_b", &["phase_c"], fixed_now());
        ctrl.record_phase_transition("op1", "phase_c", &[], fixed_now());
        let completed = ctrl.completed_phases("op1");
        assert_eq!(completed, vec!["phase_a", "phase_b"]);
        assert_eq!(ctrl.current_phase("op1").unwrap(), "phase_c");
    }

    #[test]
    fn completed_phases_unknown_returns_empty() {
        let ctrl = ProgressController::new();
        assert!(ctrl.completed_phases("nonexistent").is_empty());
    }

    #[test]
    fn phase_transition_always_emitted_not_throttled() {
        let ctrl = ProgressController::new();
        let opts = ProgressOptions {
            stream_progress: true,
            progress_interval_ms: 60_000,
        };
        ctrl.start_tracking("op1", 1, "a", &opts);
        // Transitions are never throttled even with huge interval.
        assert!(ctrl.record_phase_transition("op1", "b", &["c"], fixed_now()));
        assert!(ctrl.record_phase_transition("op1", "c", &[], fixed_now()));
        let notifs = ctrl.notifications("op1");
        assert_eq!(notifs.len(), 2);
    }

    // ── ProgressController: notifications ──

    #[test]
    fn notifications_empty_initially() {
        let ctrl = ProgressController::new();
        ctrl.start_tracking("op1", 1, "init", &default_opts());
        assert!(ctrl.notifications("op1").is_empty());
    }

    #[test]
    fn notifications_unknown_returns_empty() {
        let ctrl = ProgressController::new();
        assert!(ctrl.notifications("nonexistent").is_empty());
    }

    #[test]
    fn notifications_contain_updates_and_phases() {
        let ctrl = ProgressController::new();
        ctrl.start_tracking("op1", 1, "preparing", &zero_throttle_opts());
        ctrl.record_update("op1", make_update("preparing", 0, Some(100)), fixed_now());
        ctrl.record_phase_transition("op1", "uploading", &["verifying"], fixed_now());
        ctrl.record_update("op1", make_update("uploading", 50, Some(100)), fixed_now());

        let notifs = ctrl.notifications("op1");
        assert_eq!(notifs.len(), 3);
        assert!(matches!(notifs[0].payload, ProgressPayload::Update(_)));
        assert!(matches!(notifs[1].payload, ProgressPayload::Phase(_)));
        assert!(matches!(notifs[2].payload, ProgressPayload::Update(_)));
    }

    #[test]
    fn stop_tracking_returns_notifications() {
        let ctrl = ProgressController::new();
        ctrl.start_tracking("op1", 1, "working", &zero_throttle_opts());
        ctrl.record_update("op1", make_update("working", 10, Some(100)), fixed_now());
        ctrl.record_update("op1", make_update("working", 50, Some(100)), fixed_now());

        let notifs = ctrl.stop_tracking("op1");
        assert_eq!(notifs.len(), 2);
        assert_eq!(ctrl.tracked_count(), 0);
    }

    // ── ProgressController: current_phase ──

    #[test]
    fn current_phase_initial() {
        let ctrl = ProgressController::new();
        ctrl.start_tracking("op1", 1, "init", &default_opts());
        assert_eq!(ctrl.current_phase("op1").unwrap(), "init");
    }

    #[test]
    fn current_phase_unknown_returns_none() {
        let ctrl = ProgressController::new();
        assert!(ctrl.current_phase("nonexistent").is_none());
    }

    // ── ProgressController: elapsed ──

    #[test]
    fn elapsed_ms_returns_some_for_tracked() {
        let ctrl = ProgressController::new();
        ctrl.start_tracking("op1", 1, "init", &default_opts());
        let elapsed = ctrl.elapsed_ms("op1");
        assert!(elapsed.is_some());
    }

    #[test]
    fn elapsed_ms_unknown_returns_none() {
        let ctrl = ProgressController::new();
        assert!(ctrl.elapsed_ms("nonexistent").is_none());
    }

    // ── ProgressController: aggregate ──

    #[test]
    fn aggregate_empty() {
        let ctrl = ProgressController::new();
        let agg = ctrl.aggregate();
        assert_eq!(agg.total_operations, 0);
        assert_eq!(agg.completed_operations, 0);
        assert_eq!(agg.in_progress_operations, 0);
        assert!(agg.overall_percentage.is_none());
    }

    #[test]
    fn aggregate_single_in_progress() {
        let ctrl = ProgressController::new();
        ctrl.start_tracking("op1", 1, "working", &zero_throttle_opts());
        ctrl.record_update("op1", make_update("working", 50, Some(100)), fixed_now());

        let agg = ctrl.aggregate();
        assert_eq!(agg.total_operations, 1);
        assert_eq!(agg.completed_operations, 0);
        assert_eq!(agg.in_progress_operations, 1);
        assert!((agg.overall_percentage.unwrap() - 50.0).abs() < f64::EPSILON);
    }

    #[test]
    fn aggregate_single_completed() {
        let ctrl = ProgressController::new();
        ctrl.start_tracking("op1", 1, "working", &zero_throttle_opts());
        ctrl.record_update("op1", make_update("working", 100, Some(100)), fixed_now());

        let agg = ctrl.aggregate();
        assert_eq!(agg.total_operations, 1);
        assert_eq!(agg.completed_operations, 1);
        assert_eq!(agg.in_progress_operations, 0);
        assert!((agg.overall_percentage.unwrap() - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn aggregate_multiple_mixed() {
        let ctrl = ProgressController::new();
        ctrl.start_tracking("op1", 1, "working", &zero_throttle_opts());
        ctrl.start_tracking("op2", 2, "working", &zero_throttle_opts());
        ctrl.start_tracking("op3", 3, "working", &zero_throttle_opts());

        ctrl.record_update("op1", make_update("working", 100, Some(100)), fixed_now()); // 100%
        ctrl.record_update("op2", make_update("working", 50, Some(100)), fixed_now()); // 50%
        // op3 has no update — indeterminate

        let agg = ctrl.aggregate();
        assert_eq!(agg.total_operations, 3);
        assert_eq!(agg.completed_operations, 1);
        assert_eq!(agg.in_progress_operations, 2);
        // Average of 100% and 50% = 75% (op3 excluded from average)
        assert!((agg.overall_percentage.unwrap() - 75.0).abs() < f64::EPSILON);
    }

    #[test]
    fn aggregate_indeterminate_only() {
        let ctrl = ProgressController::new();
        ctrl.start_tracking("op1", 1, "scanning", &zero_throttle_opts());
        ctrl.record_update("op1", make_update("scanning", 50, None), fixed_now());

        let agg = ctrl.aggregate();
        assert_eq!(agg.total_operations, 1);
        assert_eq!(agg.in_progress_operations, 1);
        assert!(agg.overall_percentage.is_none());
    }

    // ── AggregatedProgress tests ──

    #[test]
    fn aggregated_progress_json_roundtrip() {
        let agg = AggregatedProgress {
            total_operations: 5,
            completed_operations: 3,
            in_progress_operations: 2,
            overall_percentage: Some(72.5),
        };
        let json = serde_json::to_string(&agg).unwrap();
        let parsed: AggregatedProgress = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.total_operations, 5);
        assert_eq!(parsed.completed_operations, 3);
        assert!((parsed.overall_percentage.unwrap() - 72.5).abs() < f64::EPSILON);
    }

    #[test]
    fn aggregated_progress_json_no_percentage() {
        let agg = AggregatedProgress {
            total_operations: 1,
            completed_operations: 0,
            in_progress_operations: 1,
            overall_percentage: None,
        };
        let json = serde_json::to_string(&agg).unwrap();
        assert!(!json.contains("overall_percentage"));
    }

    // ── Edge cases ──

    #[test]
    fn update_with_rate_and_eta() {
        let u = ProgressUpdate {
            phase: "uploading".into(),
            current: 50_000_000,
            total: Some(100_000_000),
            unit: ProgressUnit::Bytes,
            percentage: Some(50.0),
            rate: Some(5_000_000),
            eta_ms: Some(10_000),
            message: Some("Uploading chunk 5 of 10".into()),
        };
        assert_eq!(u.rate, Some(5_000_000));
        assert_eq!(u.eta_ms, Some(10_000));
        assert!(!u.is_complete());
        assert!(!u.is_indeterminate());
    }

    #[test]
    fn multiple_operations_independent() {
        let ctrl = ProgressController::new();
        ctrl.start_tracking("op1", 1, "a", &zero_throttle_opts());
        ctrl.start_tracking("op2", 2, "x", &zero_throttle_opts());

        ctrl.record_update("op1", make_update("a", 30, Some(100)), fixed_now());
        ctrl.record_update("op2", make_update("x", 70, Some(100)), fixed_now());

        assert_eq!(ctrl.latest_update("op1").unwrap().current, 30);
        assert_eq!(ctrl.latest_update("op2").unwrap().current, 70);
        assert_eq!(ctrl.current_phase("op1").unwrap(), "a");
        assert_eq!(ctrl.current_phase("op2").unwrap(), "x");
    }

    #[test]
    fn full_lifecycle() {
        let ctrl = ProgressController::new();
        ctrl.start_tracking("op1", 1, "preparing", &zero_throttle_opts());

        // Update in preparing phase.
        ctrl.record_update("op1", make_update("preparing", 0, Some(100)), fixed_now());

        // Transition to uploading.
        ctrl.record_phase_transition("op1", "uploading", &["verifying"], fixed_now());

        // Multiple updates in uploading phase.
        for i in 1..=5 {
            ctrl.record_update(
                "op1",
                make_update("uploading", i * 20, Some(100)),
                fixed_now(),
            );
        }

        // Transition to verifying.
        ctrl.record_phase_transition("op1", "verifying", &[], fixed_now());

        // Final update.
        ctrl.record_update("op1", make_update("verifying", 100, Some(100)), fixed_now());

        let notifs = ctrl.notifications("op1");
        // 1 preparing update + 1 phase transition + 5 uploading updates + 1 phase transition + 1 verifying update = 9
        assert_eq!(notifs.len(), 9);

        let completed = ctrl.completed_phases("op1");
        assert_eq!(completed, vec!["preparing", "uploading"]);
        assert_eq!(ctrl.current_phase("op1").unwrap(), "verifying");

        let latest = ctrl.latest_update("op1").unwrap();
        assert!(latest.is_complete());

        // Stop tracking and verify notifications returned.
        let final_notifs = ctrl.stop_tracking("op1");
        assert_eq!(final_notifs.len(), 9);
        assert_eq!(ctrl.tracked_count(), 0);
    }

    #[test]
    fn notification_request_id_matches() {
        let ctrl = ProgressController::new();
        ctrl.start_tracking("op1", 42, "working", &zero_throttle_opts());
        ctrl.record_update("op1", make_update("working", 10, Some(100)), fixed_now());

        let notifs = ctrl.notifications("op1");
        assert_eq!(notifs[0].request_id, 42);
        assert_eq!(notifs[0].operation_id, "op1");
    }

    #[test]
    fn notification_timestamps_set() {
        let ctrl = ProgressController::new();
        ctrl.start_tracking("op1", 1, "working", &zero_throttle_opts());
        let ts = fixed_now();
        ctrl.record_update("op1", make_update("working", 10, Some(100)), ts);

        let notifs = ctrl.notifications("op1");
        assert_eq!(notifs[0].timestamp, ts);
    }

    // ── ProgressUnit: additional variant and serialization tests ──

    #[test]
    fn unit_bytes_json_roundtrip() {
        let u = ProgressUnit::Bytes;
        let json = serde_json::to_string(&u).unwrap();
        assert_eq!(json, r#""bytes""#);
        let parsed: ProgressUnit = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, ProgressUnit::Bytes);
    }

    #[test]
    fn unit_items_json_roundtrip() {
        let u = ProgressUnit::Items;
        let json = serde_json::to_string(&u).unwrap();
        assert_eq!(json, r#""items""#);
        let parsed: ProgressUnit = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, ProgressUnit::Items);
    }

    #[test]
    fn unit_requests_json_roundtrip() {
        let u = ProgressUnit::Requests;
        let json = serde_json::to_string(&u).unwrap();
        assert_eq!(json, r#""requests""#);
        let parsed: ProgressUnit = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, ProgressUnit::Requests);
    }

    #[test]
    fn unit_rows_json_roundtrip() {
        let u = ProgressUnit::Rows;
        let json = serde_json::to_string(&u).unwrap();
        assert_eq!(json, r#""rows""#);
        let parsed: ProgressUnit = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, ProgressUnit::Rows);
    }

    #[test]
    fn unit_custom_empty_string_label() {
        let u = ProgressUnit::Custom(String::new());
        assert_eq!(u.label(), "");
    }

    #[test]
    fn unit_custom_empty_string_json_roundtrip() {
        let u = ProgressUnit::Custom(String::new());
        let json = serde_json::to_string(&u).unwrap();
        let parsed: ProgressUnit = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, u);
        assert_eq!(parsed.label(), "");
    }

    #[test]
    fn unit_custom_unicode_label() {
        let u = ProgressUnit::Custom("\u{1f4e6} packages".into());
        assert_eq!(u.label(), "\u{1f4e6} packages");
    }

    #[test]
    fn unit_custom_unicode_json_roundtrip() {
        let u = ProgressUnit::Custom("\u{00e9}l\u{00e9}ments".into());
        let json = serde_json::to_string(&u).unwrap();
        let parsed: ProgressUnit = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, u);
    }

    #[test]
    fn unit_clone_preserves_value() {
        let u = ProgressUnit::Custom("widgets".into());
        let cloned = u.clone();
        assert_eq!(u, cloned);
    }

    #[test]
    fn unit_custom_ne_different_labels() {
        let a = ProgressUnit::Custom("apples".into());
        let b = ProgressUnit::Custom("oranges".into());
        assert_ne!(a, b);
    }

    // ── ProgressUpdate: computed_percentage edge cases ──

    #[test]
    fn update_computed_percentage_current_zero_total_nonzero() {
        let u = make_update("init", 0, Some(100));
        assert!((u.computed_percentage().unwrap() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn update_computed_percentage_current_equals_total() {
        let u = make_update("done", 500, Some(500));
        assert!((u.computed_percentage().unwrap() - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn update_computed_percentage_current_exceeds_total() {
        let u = make_update("overflow", 200, Some(100));
        let pct = u.computed_percentage().unwrap();
        assert!((pct - 200.0).abs() < f64::EPSILON);
    }

    #[test]
    fn update_computed_percentage_total_one_current_one() {
        let u = make_update("single", 1, Some(1));
        assert!((u.computed_percentage().unwrap() - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn update_computed_percentage_large_values() {
        let u = make_update("big", u64::MAX / 2, Some(u64::MAX));
        let pct = u.computed_percentage().unwrap();
        assert!(pct > 49.0 && pct < 51.0);
    }

    #[test]
    fn update_is_complete_zero_total_zero_current() {
        // total=0, current=0 => current >= total, so is_complete is true
        let u = make_update("edge", 0, Some(0));
        assert!(u.is_complete());
    }

    #[test]
    fn update_is_complete_total_one() {
        let u = make_update("minimal", 1, Some(1));
        assert!(u.is_complete());
    }

    // ── ProgressUpdate: JSON serialization with all fields ──

    #[test]
    fn update_json_all_fields_populated() {
        let u = ProgressUpdate {
            phase: "uploading".into(),
            current: 75,
            total: Some(100),
            unit: ProgressUnit::Rows,
            percentage: Some(75.0),
            rate: Some(250),
            eta_ms: Some(100),
            message: Some("Processing rows".into()),
        };
        let json = serde_json::to_string(&u).unwrap();
        assert!(json.contains("\"total\":100"));
        assert!(json.contains("\"rate\":250"));
        assert!(json.contains("\"eta_ms\":100"));
        assert!(json.contains("\"message\":\"Processing rows\""));
        assert!(json.contains("\"percentage\":75.0"));
    }

    #[test]
    fn update_json_all_optional_fields_none() {
        let u = ProgressUpdate {
            phase: "scanning".into(),
            current: 42,
            total: None,
            unit: ProgressUnit::Items,
            percentage: None,
            rate: None,
            eta_ms: None,
            message: None,
        };
        let json = serde_json::to_string(&u).unwrap();
        assert!(!json.contains("total"));
        assert!(!json.contains("percentage"));
        assert!(!json.contains("rate"));
        assert!(!json.contains("eta_ms"));
        assert!(!json.contains("message"));
        // Required fields still present
        assert!(json.contains("\"phase\":\"scanning\""));
        assert!(json.contains("\"current\":42"));
        assert!(json.contains("\"unit\":\"items\""));
    }

    #[test]
    fn update_json_roundtrip_with_custom_unit() {
        let u = ProgressUpdate {
            phase: "counting".into(),
            current: 10,
            total: Some(50),
            unit: ProgressUnit::Custom("widgets".into()),
            percentage: Some(20.0),
            rate: None,
            eta_ms: None,
            message: None,
        };
        let json = serde_json::to_string(&u).unwrap();
        let parsed: ProgressUpdate = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.unit, ProgressUnit::Custom("widgets".into()));
        assert_eq!(parsed.current, 10);
    }

    #[test]
    fn update_json_deserialized_missing_optional_fields() {
        let json = r#"{"phase":"test","current":5,"unit":"bytes"}"#;
        let parsed: ProgressUpdate = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.phase, "test");
        assert_eq!(parsed.current, 5);
        assert!(parsed.total.is_none());
        assert!(parsed.percentage.is_none());
        assert!(parsed.rate.is_none());
        assert!(parsed.eta_ms.is_none());
        assert!(parsed.message.is_none());
    }

    // ── PhaseTransition: additional tests ──

    #[test]
    fn phase_transition_single_remaining() {
        let pt = PhaseTransition {
            from_phase: "init".into(),
            to_phase: "process".into(),
            phases_remaining: vec!["finalize".into()],
            timestamp: fixed_now(),
        };
        let json = serde_json::to_string(&pt).unwrap();
        let parsed: PhaseTransition = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.phases_remaining, vec!["finalize"]);
    }

    #[test]
    fn phase_transition_many_remaining() {
        let remaining: Vec<String> = (0..10).map(|i| format!("phase_{i}")).collect();
        let pt = PhaseTransition {
            from_phase: "start".into(),
            to_phase: "phase_0".into(),
            phases_remaining: remaining,
            timestamp: fixed_now(),
        };
        let json = serde_json::to_string(&pt).unwrap();
        let parsed: PhaseTransition = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.phases_remaining.len(), 10);
        assert_eq!(parsed.phases_remaining[9], "phase_9");
    }

    #[test]
    fn phase_transition_timestamp_preserved() {
        let ts = Utc.with_ymd_and_hms(2025, 12, 25, 8, 30, 0).unwrap();
        let pt = PhaseTransition {
            from_phase: "a".into(),
            to_phase: "b".into(),
            phases_remaining: vec![],
            timestamp: ts,
        };
        let json = serde_json::to_string(&pt).unwrap();
        let parsed: PhaseTransition = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.timestamp, ts);
    }

    // ── ProgressOptions: additional tests ──

    #[test]
    fn options_json_defaults_stream_progress_false() {
        let json = r"{}";
        let parsed: ProgressOptions = serde_json::from_str(json).unwrap();
        assert!(!parsed.stream_progress);
        assert_eq!(parsed.progress_interval_ms, 500);
    }

    #[test]
    fn options_custom_interval_roundtrip() {
        let opts = ProgressOptions {
            stream_progress: false,
            progress_interval_ms: 1000,
        };
        let json = serde_json::to_string(&opts).unwrap();
        let parsed: ProgressOptions = serde_json::from_str(&json).unwrap();
        assert!(!parsed.stream_progress);
        assert_eq!(parsed.progress_interval_ms, 1000);
    }

    #[test]
    fn options_zero_interval() {
        let opts = ProgressOptions {
            stream_progress: true,
            progress_interval_ms: 0,
        };
        let json = serde_json::to_string(&opts).unwrap();
        let parsed: ProgressOptions = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.progress_interval_ms, 0);
    }

    // ── ProgressController: register + deregister patterns ──

    #[test]
    fn stop_tracking_then_reregister_same_id() {
        let ctrl = ProgressController::new();
        ctrl.start_tracking("op1", 1, "alpha", &zero_throttle_opts());
        ctrl.record_update("op1", make_update("alpha", 50, Some(100)), fixed_now());
        let old_notifs = ctrl.stop_tracking("op1");
        assert_eq!(old_notifs.len(), 1);
        assert_eq!(ctrl.tracked_count(), 0);

        // Re-register same ID with new state
        ctrl.start_tracking("op1", 99, "beta", &zero_throttle_opts());
        assert_eq!(ctrl.tracked_count(), 1);
        assert_eq!(ctrl.current_phase("op1").unwrap(), "beta");
        assert!(ctrl.latest_update("op1").is_none()); // fresh, no update yet
        assert!(ctrl.notifications("op1").is_empty());
    }

    #[test]
    fn stop_tracking_unknown_id_is_noop() {
        let ctrl = ProgressController::new();
        ctrl.start_tracking("op1", 1, "a", &default_opts());
        let notifs = ctrl.stop_tracking("unknown_op");
        assert!(notifs.is_empty());
        assert_eq!(ctrl.tracked_count(), 1); // op1 still tracked
    }

    #[test]
    fn multiple_operations_tracked_simultaneously() {
        let ctrl = ProgressController::new();
        for i in 0u64..10 {
            ctrl.start_tracking(&format!("op_{i}"), i, "init", &zero_throttle_opts());
        }
        assert_eq!(ctrl.tracked_count(), 10);
        for i in 0u64..10 {
            ctrl.record_update(
                &format!("op_{i}"),
                make_update("init", i * 10, Some(100)),
                fixed_now(),
            );
        }
        // Verify each has its own progress
        assert_eq!(ctrl.latest_update("op_0").unwrap().current, 0);
        assert_eq!(ctrl.latest_update("op_5").unwrap().current, 50);
        assert_eq!(ctrl.latest_update("op_9").unwrap().current, 90);
    }

    #[test]
    fn update_with_phase_change_via_transition() {
        let ctrl = ProgressController::new();
        ctrl.start_tracking("op1", 1, "download", &zero_throttle_opts());
        ctrl.record_update("op1", make_update("download", 100, Some(100)), fixed_now());
        ctrl.record_phase_transition("op1", "process", &["upload"], fixed_now());
        ctrl.record_update("op1", make_update("process", 0, Some(50)), fixed_now());

        assert_eq!(ctrl.current_phase("op1").unwrap(), "process");
        let latest = ctrl.latest_update("op1").unwrap();
        assert_eq!(latest.phase, "process");
        assert_eq!(latest.current, 0);
        assert_eq!(latest.total, Some(50));
    }

    #[test]
    fn operation_ids_with_special_characters() {
        let ctrl = ProgressController::new();
        let special_ids = [
            "op/with/slashes",
            "op:with:colons",
            "op with spaces",
            "op\twith\ttabs",
            "op-with-dashes_and_underscores.and.dots",
            "\u{00e9}l\u{00e8}ve",
        ];
        for (i, id) in special_ids.iter().enumerate() {
            ctrl.start_tracking(id, i as u64, "init", &zero_throttle_opts());
            ctrl.record_update(id, make_update("init", 10, Some(100)), fixed_now());
        }
        assert_eq!(ctrl.tracked_count(), special_ids.len());
        for id in &special_ids {
            assert_eq!(ctrl.latest_update(id).unwrap().current, 10);
        }
    }

    // ── ProgressController: throttling behavior ──

    #[test]
    fn throttled_updates_still_recorded_internally() {
        let ctrl = ProgressController::new();
        let opts = ProgressOptions {
            stream_progress: true,
            progress_interval_ms: 60_000,
        };
        ctrl.start_tracking("op1", 1, "work", &opts);
        // First emits
        assert!(ctrl.record_update("op1", make_update("work", 10, Some(100)), fixed_now()));
        // Next few are throttled
        for i in 2..=5 {
            assert!(!ctrl.record_update(
                "op1",
                make_update("work", i * 10, Some(100)),
                fixed_now(),
            ));
        }
        // Latest still reflects last update
        assert_eq!(ctrl.latest_update("op1").unwrap().current, 50);
        // Only 1 notification emitted
        assert_eq!(ctrl.notifications("op1").len(), 1);
    }

    #[test]
    fn phase_transition_not_throttled_between_throttled_updates() {
        let ctrl = ProgressController::new();
        let opts = ProgressOptions {
            stream_progress: true,
            progress_interval_ms: 60_000,
        };
        ctrl.start_tracking("op1", 1, "a", &opts);
        // First update emits
        assert!(ctrl.record_update("op1", make_update("a", 10, Some(100)), fixed_now()));
        // Second update throttled
        assert!(!ctrl.record_update("op1", make_update("a", 20, Some(100)), fixed_now()));
        // Phase transition is never throttled
        assert!(ctrl.record_phase_transition("op1", "b", &[], fixed_now()));
        // Next update still throttled (timer based on update emission, not transition)
        // But phase transition notification is present
        let notifs = ctrl.notifications("op1");
        assert_eq!(notifs.len(), 2); // 1 update + 1 transition
        assert!(matches!(notifs[1].payload, ProgressPayload::Phase(_)));
    }

    // ── ProgressController: snapshot retrieval ──

    #[test]
    fn latest_update_before_any_update_returns_none() {
        let ctrl = ProgressController::new();
        ctrl.start_tracking("op1", 1, "init", &default_opts());
        assert!(ctrl.latest_update("op1").is_none());
    }

    #[test]
    fn current_phase_after_multiple_transitions() {
        let ctrl = ProgressController::new();
        ctrl.start_tracking("op1", 1, "phase_0", &default_opts());
        for i in 1..=5 {
            ctrl.record_phase_transition("op1", &format!("phase_{i}"), &[], fixed_now());
        }
        assert_eq!(ctrl.current_phase("op1").unwrap(), "phase_5");
        let completed = ctrl.completed_phases("op1");
        assert_eq!(completed.len(), 5);
        assert_eq!(completed[0], "phase_0");
        assert_eq!(completed[4], "phase_4");
    }

    #[test]
    fn elapsed_ms_increases_over_time() {
        let ctrl = ProgressController::new();
        ctrl.start_tracking("op1", 1, "init", &default_opts());
        let e1 = ctrl.elapsed_ms("op1").unwrap();
        // Elapsed should be very small (just started), but at least 0
        assert!(e1 < 1000);
    }

    // ── AggregatedProgress: additional scenarios ──

    #[test]
    fn aggregate_all_completed() {
        let ctrl = ProgressController::new();
        for i in 0u64..5 {
            let id = format!("op_{i}");
            ctrl.start_tracking(&id, i, "work", &zero_throttle_opts());
            ctrl.record_update(&id, make_update("work", 100, Some(100)), fixed_now());
        }
        let agg = ctrl.aggregate();
        assert_eq!(agg.total_operations, 5);
        assert_eq!(agg.completed_operations, 5);
        assert_eq!(agg.in_progress_operations, 0);
        assert!((agg.overall_percentage.unwrap() - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn aggregate_none_started_no_updates() {
        let ctrl = ProgressController::new();
        for i in 0u64..3 {
            ctrl.start_tracking(&format!("op_{i}"), i, "init", &default_opts());
        }
        let agg = ctrl.aggregate();
        assert_eq!(agg.total_operations, 3);
        assert_eq!(agg.completed_operations, 0);
        assert_eq!(agg.in_progress_operations, 3);
        // No updates => no percentage calculable
        assert!(agg.overall_percentage.is_none());
    }

    #[test]
    fn aggregate_mixed_indeterminate_and_determinate() {
        let ctrl = ProgressController::new();
        ctrl.start_tracking("det", 1, "work", &zero_throttle_opts());
        ctrl.record_update("det", make_update("work", 50, Some(100)), fixed_now());

        ctrl.start_tracking("indet", 2, "scan", &zero_throttle_opts());
        ctrl.record_update("indet", make_update("scan", 999, None), fixed_now());

        let agg = ctrl.aggregate();
        assert_eq!(agg.total_operations, 2);
        assert_eq!(agg.completed_operations, 0);
        assert_eq!(agg.in_progress_operations, 2);
        // Only determinate op contributes to percentage => 50.0
        assert!((agg.overall_percentage.unwrap() - 50.0).abs() < f64::EPSILON);
    }

    #[test]
    fn aggregate_after_stop_tracking() {
        let ctrl = ProgressController::new();
        ctrl.start_tracking("op1", 1, "work", &zero_throttle_opts());
        ctrl.start_tracking("op2", 2, "work", &zero_throttle_opts());
        ctrl.record_update("op1", make_update("work", 100, Some(100)), fixed_now());
        ctrl.record_update("op2", make_update("work", 50, Some(100)), fixed_now());

        ctrl.stop_tracking("op1");
        let agg = ctrl.aggregate();
        assert_eq!(agg.total_operations, 1);
        assert_eq!(agg.completed_operations, 0);
        assert_eq!(agg.in_progress_operations, 1);
        assert!((agg.overall_percentage.unwrap() - 50.0).abs() < f64::EPSILON);
    }

    // ── Edge cases: large values ──

    #[test]
    fn update_u64_max_current_and_total() {
        let u = ProgressUpdate {
            phase: "massive".into(),
            current: u64::MAX,
            total: Some(u64::MAX),
            unit: ProgressUnit::Bytes,
            percentage: None,
            rate: None,
            eta_ms: None,
            message: None,
        };
        assert!(u.is_complete());
        let pct = u.computed_percentage().unwrap();
        assert!((pct - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn update_u64_max_json_roundtrip() {
        let u = ProgressUpdate {
            phase: "huge".into(),
            current: u64::MAX,
            total: Some(u64::MAX),
            unit: ProgressUnit::Items,
            percentage: None,
            rate: Some(u64::MAX),
            eta_ms: Some(u64::MAX),
            message: None,
        };
        let json = serde_json::to_string(&u).unwrap();
        let parsed: ProgressUpdate = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.current, u64::MAX);
        assert_eq!(parsed.total, Some(u64::MAX));
        assert_eq!(parsed.rate, Some(u64::MAX));
        assert_eq!(parsed.eta_ms, Some(u64::MAX));
    }

    #[test]
    fn update_zero_total_is_complete() {
        // current=0, total=0 means current>=total so is_complete=true
        let u = make_update("zero", 0, Some(0));
        assert!(u.is_complete());
    }

    #[test]
    fn update_zero_current_zero_total_is_indeterminate_false() {
        let u = make_update("zero", 0, Some(0));
        assert!(!u.is_indeterminate());
    }

    // ── Serialization: ProgressPayload tag-based ──

    #[test]
    fn payload_update_tagged_serialization() {
        let payload = ProgressPayload::Update(make_update("test", 5, Some(10)));
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains(r#""type":"update""#));
    }

    #[test]
    fn payload_phase_tagged_serialization() {
        let payload = ProgressPayload::Phase(PhaseTransition {
            from_phase: "a".into(),
            to_phase: "b".into(),
            phases_remaining: vec![],
            timestamp: fixed_now(),
        });
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains(r#""type":"phase""#));
    }

    #[test]
    fn payload_update_json_roundtrip() {
        let payload = ProgressPayload::Update(make_update("work", 25, Some(50)));
        let json = serde_json::to_string(&payload).unwrap();
        let parsed: ProgressPayload = serde_json::from_str(&json).unwrap();
        if let ProgressPayload::Update(u) = parsed {
            assert_eq!(u.current, 25);
            assert_eq!(u.total, Some(50));
        } else {
            panic!("expected Update variant");
        }
    }

    #[test]
    fn payload_phase_json_roundtrip() {
        let payload = ProgressPayload::Phase(PhaseTransition {
            from_phase: "x".into(),
            to_phase: "y".into(),
            phases_remaining: vec!["z".into()],
            timestamp: fixed_now(),
        });
        let json = serde_json::to_string(&payload).unwrap();
        let parsed: ProgressPayload = serde_json::from_str(&json).unwrap();
        if let ProgressPayload::Phase(pt) = parsed {
            assert_eq!(pt.from_phase, "x");
            assert_eq!(pt.to_phase, "y");
            assert_eq!(pt.phases_remaining, vec!["z"]);
        } else {
            panic!("expected Phase variant");
        }
    }

    // ── AggregatedProgress: serialization edge cases ──

    #[test]
    fn aggregated_progress_all_zero() {
        let agg = AggregatedProgress {
            total_operations: 0,
            completed_operations: 0,
            in_progress_operations: 0,
            overall_percentage: None,
        };
        let json = serde_json::to_string(&agg).unwrap();
        let parsed: AggregatedProgress = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.total_operations, 0);
        assert!(parsed.overall_percentage.is_none());
        assert!(!json.contains("overall_percentage"));
    }

    #[test]
    fn aggregated_progress_with_percentage_roundtrip() {
        let agg = AggregatedProgress {
            total_operations: 10,
            completed_operations: 7,
            in_progress_operations: 3,
            overall_percentage: Some(85.123_456_789),
        };
        let json = serde_json::to_string(&agg).unwrap();
        let parsed: AggregatedProgress = serde_json::from_str(&json).unwrap();
        assert!((parsed.overall_percentage.unwrap() - 85.123_456_789).abs() < 1e-9);
    }

    // ── ProgressController: notification ordering and content ──

    #[test]
    fn notifications_preserve_chronological_order() {
        let ctrl = ProgressController::new();
        ctrl.start_tracking("op1", 1, "a", &zero_throttle_opts());

        let t1 = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let t2 = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 1).unwrap();
        let t3 = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 2).unwrap();

        ctrl.record_update("op1", make_update("a", 10, Some(100)), t1);
        ctrl.record_phase_transition("op1", "b", &[], t2);
        ctrl.record_update("op1", make_update("b", 50, Some(100)), t3);

        let notifs = ctrl.notifications("op1");
        assert_eq!(notifs.len(), 3);
        assert_eq!(notifs[0].timestamp, t1);
        assert_eq!(notifs[1].timestamp, t2);
        assert_eq!(notifs[2].timestamp, t3);
    }

    #[test]
    fn notification_operation_id_matches_tracked() {
        let ctrl = ProgressController::new();
        ctrl.start_tracking("my-op-id", 7, "init", &zero_throttle_opts());
        ctrl.record_update("my-op-id", make_update("init", 1, Some(10)), fixed_now());
        let notifs = ctrl.notifications("my-op-id");
        assert_eq!(notifs[0].operation_id, "my-op-id");
    }

    #[test]
    fn stop_tracking_returns_all_notification_types() {
        let ctrl = ProgressController::new();
        ctrl.start_tracking("op1", 1, "a", &zero_throttle_opts());
        ctrl.record_update("op1", make_update("a", 10, Some(100)), fixed_now());
        ctrl.record_phase_transition("op1", "b", &[], fixed_now());
        ctrl.record_update("op1", make_update("b", 100, Some(100)), fixed_now());

        let notifs = ctrl.stop_tracking("op1");
        assert_eq!(notifs.len(), 3);
        assert!(matches!(notifs[0].payload, ProgressPayload::Update(_)));
        assert!(matches!(notifs[1].payload, ProgressPayload::Phase(_)));
        assert!(matches!(notifs[2].payload, ProgressPayload::Update(_)));
        assert_eq!(ctrl.tracked_count(), 0);
    }

    // ── ProgressNotification: serialization ──

    #[test]
    fn notification_json_contains_all_fields() {
        let n = ProgressNotification {
            operation_id: "abc-123".into(),
            request_id: 999,
            payload: ProgressPayload::Update(make_update("work", 5, Some(10))),
            timestamp: fixed_now(),
        };
        let json = serde_json::to_string(&n).unwrap();
        assert!(json.contains("\"operation_id\":\"abc-123\""));
        assert!(json.contains("\"request_id\":999"));
        assert!(json.contains("\"type\":\"update\""));
    }

    #[test]
    fn notification_with_phase_payload_serialization() {
        let n = ProgressNotification {
            operation_id: "op-phase".into(),
            request_id: 1,
            payload: ProgressPayload::Phase(PhaseTransition {
                from_phase: "download".into(),
                to_phase: "parse".into(),
                phases_remaining: vec!["validate".into(), "store".into()],
                timestamp: fixed_now(),
            }),
            timestamp: fixed_now(),
        };
        let json = serde_json::to_string(&n).unwrap();
        let parsed: ProgressNotification = serde_json::from_str(&json).unwrap();
        if let ProgressPayload::Phase(pt) = &parsed.payload {
            assert_eq!(pt.from_phase, "download");
            assert_eq!(pt.to_phase, "parse");
            assert_eq!(pt.phases_remaining.len(), 2);
        } else {
            panic!("expected Phase payload");
        }
    }

    // ── ProgressController: aggregate edge scenarios ──

    #[test]
    fn aggregate_single_op_no_update_counts_as_in_progress() {
        let ctrl = ProgressController::new();
        ctrl.start_tracking("op1", 1, "init", &default_opts());
        let agg = ctrl.aggregate();
        assert_eq!(agg.total_operations, 1);
        assert_eq!(agg.in_progress_operations, 1);
        assert_eq!(agg.completed_operations, 0);
    }

    #[test]
    fn aggregate_percentage_is_average_not_sum() {
        let ctrl = ProgressController::new();
        ctrl.start_tracking("op1", 1, "w", &zero_throttle_opts());
        ctrl.start_tracking("op2", 2, "w", &zero_throttle_opts());
        ctrl.start_tracking("op3", 3, "w", &zero_throttle_opts());

        ctrl.record_update("op1", make_update("w", 10, Some(100)), fixed_now()); // 10%
        ctrl.record_update("op2", make_update("w", 20, Some(100)), fixed_now()); // 20%
        ctrl.record_update("op3", make_update("w", 30, Some(100)), fixed_now()); // 30%

        let agg = ctrl.aggregate();
        // Average = (10+20+30)/3 = 20%
        assert!((agg.overall_percentage.unwrap() - 20.0).abs() < f64::EPSILON);
    }

    // ── ProgressUpdate: clone behavior ──

    #[test]
    fn update_clone_is_independent() {
        let original = ProgressUpdate {
            phase: "uploading".into(),
            current: 50,
            total: Some(100),
            unit: ProgressUnit::Bytes,
            percentage: Some(50.0),
            rate: Some(1000),
            eta_ms: Some(5000),
            message: Some("half done".into()),
        };
        let cloned = original.clone();
        assert_eq!(cloned.phase, original.phase);
        assert_eq!(cloned.current, original.current);
        assert_eq!(cloned.total, original.total);
        assert_eq!(cloned.unit, original.unit);
        assert_eq!(cloned.percentage, original.percentage);
        assert_eq!(cloned.rate, original.rate);
        assert_eq!(cloned.eta_ms, original.eta_ms);
        assert_eq!(cloned.message, original.message);
    }

    // ── ProgressController: rapid successive updates ──

    #[test]
    fn rapid_updates_all_recorded_with_zero_throttle() {
        let ctrl = ProgressController::new();
        ctrl.start_tracking("op1", 1, "work", &zero_throttle_opts());
        for i in 0..100 {
            let emitted = ctrl.record_update("op1", make_update("work", i, Some(100)), fixed_now());
            assert!(emitted);
        }
        assert_eq!(ctrl.notifications("op1").len(), 100);
        assert_eq!(ctrl.latest_update("op1").unwrap().current, 99);
    }

    #[test]
    fn rapid_updates_throttled_only_first_emits() {
        let ctrl = ProgressController::new();
        let opts = ProgressOptions {
            stream_progress: true,
            progress_interval_ms: 60_000,
        };
        ctrl.start_tracking("op1", 1, "work", &opts);
        let mut emitted_count = 0;
        for i in 0..50 {
            if ctrl.record_update("op1", make_update("work", i, Some(100)), fixed_now()) {
                emitted_count += 1;
            }
        }
        assert_eq!(emitted_count, 1); // only first
        assert_eq!(ctrl.latest_update("op1").unwrap().current, 49); // latest is always stored
    }

    // ── Multiple phases with remaining tracking ──

    #[test]
    fn phase_transition_remaining_phases_updated() {
        let ctrl = ProgressController::new();
        ctrl.start_tracking("op1", 1, "a", &zero_throttle_opts());
        ctrl.record_phase_transition("op1", "b", &["c", "d", "e"], fixed_now());

        let notifs = ctrl.notifications("op1");
        if let ProgressPayload::Phase(pt) = &notifs[0].payload {
            assert_eq!(pt.from_phase, "a");
            assert_eq!(pt.to_phase, "b");
            assert_eq!(pt.phases_remaining, vec!["c", "d", "e"]);
        } else {
            panic!("expected phase payload");
        }

        ctrl.record_phase_transition("op1", "c", &["d", "e"], fixed_now());
        let notifs2 = ctrl.notifications("op1");
        if let ProgressPayload::Phase(pt) = &notifs2[1].payload {
            assert_eq!(pt.from_phase, "b");
            assert_eq!(pt.to_phase, "c");
            assert_eq!(pt.phases_remaining, vec!["d", "e"]);
        } else {
            panic!("expected phase payload");
        }
    }
}
