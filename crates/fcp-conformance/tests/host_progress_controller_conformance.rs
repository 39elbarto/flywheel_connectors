//! `ProgressController` tracking + throttle + phase-transition
//! conformance.
//!
//! `fcp_host::ProgressController` (br-w82c) tracks long-running
//! operation progress with throttled emission. Zero conformance
//! coverage today. The contract callers depend on:
//!
//! 1. `start_tracking` initializes state for an operation_id.
//! 2. `record_update` on an unknown operation returns `false` (no
//!    panic) and does NOT allocate a new tracking entry.
//! 3. The FIRST update for a tracked operation always emits
//!    (last_emitted is None — there is no prior emission to
//!    throttle against).
//! 4. A second update WITHIN the configured throttle interval
//!    returns `false` (throttled), but `latest_update` still
//!    reflects it (callers pulling latest snapshot get the most
//!    recent value regardless of throttle).
//! 5. A second update AFTER the throttle interval emits.
//! 6. `record_phase_transition` moves `current_phase` into
//!    `completed_phases` and sets the new `current_phase`.
//! 7. `stop_tracking` removes the operation and returns its
//!    captured notifications.
//! 8. `ProgressUpdate::computed_percentage` returns None when
//!    total is None or 0; otherwise current/total*100.
//! 9. `is_indeterminate` returns true iff total is None.

use std::thread::sleep;
use std::time::Duration;

use chrono::Utc;
use fcp_host::{
    ProgressController, ProgressOptions, ProgressPayload, ProgressUnit, ProgressUpdate,
};

fn options(interval_ms: u64) -> ProgressOptions {
    ProgressOptions {
        stream_progress: true,
        progress_interval_ms: interval_ms,
    }
}

fn update_at(current: u64, total: Option<u64>) -> ProgressUpdate {
    ProgressUpdate {
        phase: "uploading".to_string(),
        current,
        total,
        unit: ProgressUnit::Bytes,
        percentage: None,
        rate: None,
        eta_ms: None,
        message: None,
    }
}

#[test]
fn start_tracking_initializes_state() {
    let ctrl = ProgressController::new();
    ctrl.start_tracking("op-1", 42, "uploading", &options(100));

    assert_eq!(ctrl.tracked_count(), 1);
    assert_eq!(
        ctrl.current_phase("op-1").as_deref(),
        Some("uploading"),
        "current_phase MUST reflect initial phase"
    );
    assert!(
        ctrl.latest_update("op-1").is_none(),
        "no updates yet -> latest_update is None"
    );
}

#[test]
fn record_update_on_unknown_operation_returns_false_and_does_not_allocate() {
    let ctrl = ProgressController::new();
    let emitted = ctrl.record_update("op-unknown", update_at(10, Some(100)), Utc::now());
    assert!(
        !emitted,
        "record_update on un-tracked op MUST return false"
    );
    assert_eq!(
        ctrl.tracked_count(),
        0,
        "record_update on unknown id MUST NOT allocate a tracking entry"
    );
}

#[test]
fn first_update_for_tracked_operation_always_emits() {
    let ctrl = ProgressController::new();
    ctrl.start_tracking("op-first", 1, "phase-a", &options(60_000));

    let emitted = ctrl.record_update("op-first", update_at(1, Some(100)), Utc::now());
    assert!(
        emitted,
        "first update MUST emit even with a long throttle interval — last_emitted is None"
    );
}

#[test]
fn second_update_within_throttle_interval_is_not_emitted_but_latest_still_tracks() {
    let ctrl = ProgressController::new();
    // 60-second throttle: any second update must be throttled.
    ctrl.start_tracking("op-throttle", 1, "phase-a", &options(60_000));

    ctrl.record_update("op-throttle", update_at(1, Some(100)), Utc::now());
    let emitted = ctrl.record_update("op-throttle", update_at(50, Some(100)), Utc::now());
    assert!(
        !emitted,
        "second update within throttle interval MUST return false (throttled)"
    );

    // But latest_update STILL tracks the throttled update.
    let latest = ctrl
        .latest_update("op-throttle")
        .expect("latest_update must reflect the throttled update");
    assert_eq!(
        latest.current, 50,
        "latest_update MUST hold the most recent value regardless of throttle"
    );
}

#[test]
fn second_update_after_throttle_interval_is_emitted() {
    let ctrl = ProgressController::new();
    // Tight throttle so test is fast.
    ctrl.start_tracking("op-tight", 1, "phase-a", &options(20));

    ctrl.record_update("op-tight", update_at(1, Some(100)), Utc::now());
    sleep(Duration::from_millis(40));
    let emitted = ctrl.record_update("op-tight", update_at(50, Some(100)), Utc::now());
    assert!(
        emitted,
        "second update after the throttle interval (20 ms config, 40 ms sleep) MUST emit"
    );
}

#[test]
fn record_phase_transition_moves_current_into_completed() {
    let ctrl = ProgressController::new();
    ctrl.start_tracking("op-phase", 1, "uploading", &options(100));

    let ok = ctrl.record_phase_transition(
        "op-phase",
        "verifying",
        &["finalizing"],
        Utc::now(),
    );
    assert!(ok);

    assert_eq!(ctrl.current_phase("op-phase").as_deref(), Some("verifying"));
    let completed = ctrl.completed_phases("op-phase");
    assert_eq!(
        completed,
        vec!["uploading"],
        "phase transition MUST move the prior phase into completed_phases"
    );
}

#[test]
fn record_phase_transition_on_unknown_op_returns_false() {
    let ctrl = ProgressController::new();
    let ok = ctrl.record_phase_transition("op-unknown", "next", &[], Utc::now());
    assert!(
        !ok,
        "phase transition on un-tracked op MUST return false (no panic, no allocation)"
    );
    assert_eq!(ctrl.tracked_count(), 0);
}

#[test]
fn notifications_capture_emitted_updates_and_phase_transitions() {
    let ctrl = ProgressController::new();
    ctrl.start_tracking("op-notif", 7, "phase-a", &options(100));

    ctrl.record_update("op-notif", update_at(10, Some(100)), Utc::now());
    ctrl.record_phase_transition("op-notif", "phase-b", &[], Utc::now());

    let notifications = ctrl.notifications("op-notif");
    let update_count = notifications
        .iter()
        .filter(|n| matches!(n.payload, ProgressPayload::Update(_)))
        .count();
    let phase_count = notifications
        .iter()
        .filter(|n| matches!(n.payload, ProgressPayload::Phase(_)))
        .count();
    assert_eq!(update_count, 1, "exactly one Update notification expected");
    assert_eq!(phase_count, 1, "exactly one Phase notification expected");
    for n in &notifications {
        assert_eq!(n.operation_id, "op-notif");
        assert_eq!(n.request_id, 7);
    }
}

#[test]
fn stop_tracking_removes_operation_and_returns_notifications() {
    let ctrl = ProgressController::new();
    ctrl.start_tracking("op-stop", 1, "phase-a", &options(100));
    ctrl.record_update("op-stop", update_at(10, Some(100)), Utc::now());

    let notifications = ctrl.stop_tracking("op-stop");
    assert!(
        !notifications.is_empty(),
        "stop_tracking MUST return the captured notifications"
    );
    assert_eq!(
        ctrl.tracked_count(),
        0,
        "stop_tracking MUST remove the operation entry"
    );
    assert!(
        ctrl.latest_update("op-stop").is_none(),
        "after stop_tracking, latest_update returns None"
    );
}

#[test]
fn stop_tracking_on_unknown_op_returns_empty() {
    let ctrl = ProgressController::new();
    let notifications = ctrl.stop_tracking("op-unknown");
    assert!(
        notifications.is_empty(),
        "stop_tracking on un-tracked op MUST return empty (not panic)"
    );
}

#[test]
fn computed_percentage_returns_none_when_total_is_none() {
    let u = update_at(50, None);
    assert!(
        u.computed_percentage().is_none(),
        "computed_percentage MUST return None when total is None (indeterminate progress)"
    );
    assert!(
        u.is_indeterminate(),
        "is_indeterminate MUST return true when total is None"
    );
}

#[test]
fn computed_percentage_returns_none_when_total_is_zero() {
    // Edge case: a zero total would otherwise cause division-by-zero.
    let u = update_at(0, Some(0));
    assert!(
        u.computed_percentage().is_none(),
        "computed_percentage MUST return None when total is zero (avoid div-by-zero)"
    );
}

#[test]
fn computed_percentage_returns_correct_fraction() {
    let u = update_at(25, Some(100));
    let pct = u.computed_percentage().expect("percentage must be Some");
    assert!(
        (pct - 25.0).abs() < 1e-9,
        "25/100 -> 25.0; got {pct}"
    );

    let u_done = update_at(100, Some(100));
    let pct_done = u_done.computed_percentage().expect("percentage");
    assert!(
        (pct_done - 100.0).abs() < 1e-9,
        "100/100 -> 100.0; got {pct_done}"
    );
}

#[test]
fn aggregate_reports_total_operations_and_in_progress() {
    let ctrl = ProgressController::new();
    ctrl.start_tracking("op-1", 1, "phase-a", &options(100));
    ctrl.start_tracking("op-2", 2, "phase-a", &options(100));
    ctrl.record_update("op-1", update_at(50, Some(100)), Utc::now());

    let agg = ctrl.aggregate();
    assert_eq!(
        agg.total_operations, 2,
        "aggregate.total_operations MUST equal tracked_count"
    );
    assert!(
        agg.in_progress_operations >= 1,
        "at least one operation should be reported in progress; got {agg:?}"
    );
}
