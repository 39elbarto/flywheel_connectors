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
}
