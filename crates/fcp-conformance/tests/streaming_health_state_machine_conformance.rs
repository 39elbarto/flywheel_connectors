//! `StreamHealthTracker` heartbeat-timeout state-machine conformance.
//!
//! `fcp_streaming::StreamHealthTracker` drives connector health
//! classification across all streaming connectors:
//!
//! ```text
//! Connected ──(heartbeat overdue ─after─ heartbeat_timeout)──▶ Degraded
//! Degraded  ──(zombie ─after─ zombie_timeout)──▶ Unhealthy
//! Degraded  ──(heartbeat received)──▶ Connected     (recovery)
//! Connected ──(record_disconnect)──▶ Reconnecting
//! Reconnecting ──(reconnect_count >= max)──▶ Unhealthy
//! Reconnecting | Unhealthy ──▶  (no automatic transitions; needs reset())
//! ```
//!
//! Inline tests in fcp-streaming exercise these transitions, but no
//! cross-crate conformance pinned them. A regression that fired
//! Connected→Degraded *at* the timeout (instead of strictly after),
//! or that let `evaluate()` walk *out* of `Unhealthy` automatically,
//! would silently corrupt every connector's health telemetry.
//!
//! These tests use very short timeouts (30 / 90 ms) so the suite
//! runs in well under a second yet still exercises the real
//! Instant-based clock — no fake clock substitution.

use std::thread::sleep;
use std::time::Duration;

use fcp_streaming::{StreamHealthConfig, StreamHealthState, StreamHealthTracker};

fn fast_config() -> StreamHealthConfig {
    StreamHealthConfig {
        heartbeat_timeout: Duration::from_millis(30),
        zombie_timeout: Duration::from_millis(90),
        max_reconnect_attempts: 3,
    }
}

#[test]
fn fresh_tracker_starts_in_connected_state() {
    let tracker = StreamHealthTracker::new(fast_config());
    assert_eq!(
        tracker.state(),
        StreamHealthState::Connected,
        "a freshly-constructed tracker MUST start in Connected"
    );
}

#[test]
fn record_heartbeat_keeps_state_connected() {
    let mut tracker = StreamHealthTracker::new(fast_config());
    tracker.record_heartbeat();
    assert_eq!(
        tracker.evaluate(),
        StreamHealthState::Connected,
        "a recent heartbeat must keep the tracker in Connected"
    );
}

#[test]
fn missed_heartbeat_after_timeout_transitions_connected_to_degraded() {
    let mut tracker = StreamHealthTracker::new(fast_config());
    tracker.record_heartbeat();
    sleep(Duration::from_millis(50)); // > heartbeat_timeout (30 ms)
    assert_eq!(
        tracker.evaluate(),
        StreamHealthState::Degraded,
        "Connected MUST transition to Degraded once heartbeat_timeout has elapsed"
    );
}

#[test]
fn heartbeat_after_degraded_recovers_to_connected() {
    // Recovery causality: a heartbeat received while in Degraded
    // MUST promote the tracker back to Connected. Without this,
    // a connector could never recover from a transient hiccup.
    let mut tracker = StreamHealthTracker::new(fast_config());
    tracker.record_heartbeat();
    sleep(Duration::from_millis(50));
    assert_eq!(tracker.evaluate(), StreamHealthState::Degraded);

    tracker.record_heartbeat();
    assert_eq!(
        tracker.state(),
        StreamHealthState::Connected,
        "heartbeat receipt MUST recover Degraded -> Connected"
    );
}

#[test]
fn zombie_timeout_transitions_degraded_to_unhealthy() {
    let mut tracker = StreamHealthTracker::new(fast_config());
    tracker.record_heartbeat();
    sleep(Duration::from_millis(50));
    assert_eq!(tracker.evaluate(), StreamHealthState::Degraded);

    sleep(Duration::from_millis(50)); // total > zombie_timeout (90 ms)
    assert_eq!(
        tracker.evaluate(),
        StreamHealthState::Unhealthy,
        "Degraded MUST transition to Unhealthy once zombie_timeout has elapsed"
    );
}

#[test]
fn evaluate_does_not_automatically_recover_from_unhealthy() {
    // Critical invariant: once a tracker is Unhealthy, calling
    // evaluate() repeatedly MUST NOT walk it out automatically. The
    // operator must explicitly call record_reconnected() or reset().
    // A regression here would let zombie connections silently
    // self-heal in telemetry without any underlying reconnection.
    let mut tracker = StreamHealthTracker::new(fast_config());
    tracker.record_heartbeat();
    sleep(Duration::from_millis(100));
    let _ = tracker.evaluate(); // Connected -> Degraded
    sleep(Duration::from_millis(50));
    assert_eq!(tracker.evaluate(), StreamHealthState::Unhealthy);

    // Several more evaluate() calls and a heartbeat — none should
    // walk Unhealthy back to a healthier state. (Note: per the
    // record_heartbeat impl in fcp-streaming/src/health.rs the
    // recovery is Degraded -> Connected only; it deliberately does
    // not recover Unhealthy.)
    tracker.record_heartbeat();
    for _ in 0..5 {
        let _ = tracker.evaluate();
    }
    assert_eq!(
        tracker.state(),
        StreamHealthState::Unhealthy,
        "Unhealthy MUST NOT recover automatically; record_heartbeat alone does NOT \
         walk Unhealthy back (only Degraded -> Connected). Operator must call \
         record_reconnected or reset."
    );
}

#[test]
fn record_disconnect_transitions_to_reconnecting_under_max_attempts() {
    let mut tracker = StreamHealthTracker::new(fast_config());
    tracker.record_disconnect();
    assert_eq!(
        tracker.state(),
        StreamHealthState::Reconnecting,
        "first disconnect (1/3 attempts) MUST set state to Reconnecting"
    );
}

#[test]
fn record_disconnect_at_max_attempts_transitions_to_unhealthy() {
    let mut tracker = StreamHealthTracker::new(fast_config()); // max_reconnect_attempts = 3
    tracker.record_disconnect();
    tracker.record_disconnect();
    tracker.record_disconnect();
    assert_eq!(
        tracker.state(),
        StreamHealthState::Unhealthy,
        "reconnect_count reaching max_reconnect_attempts MUST escalate to Unhealthy"
    );
}

#[test]
fn record_reconnected_returns_to_connected_and_clears_attempts() {
    let mut tracker = StreamHealthTracker::new(fast_config());
    tracker.record_disconnect();
    tracker.record_disconnect();
    assert_eq!(tracker.state(), StreamHealthState::Reconnecting);

    tracker.record_reconnected();
    assert_eq!(
        tracker.state(),
        StreamHealthState::Connected,
        "record_reconnected MUST return state to Connected"
    );

    // After clearing, a new disconnect must restart the count from
    // 1 (not 3) — otherwise reconnect_count is sticky and a single
    // future disconnect would re-fire Unhealthy.
    tracker.record_disconnect();
    assert_eq!(
        tracker.state(),
        StreamHealthState::Reconnecting,
        "reconnect_count MUST reset on record_reconnected; one disconnect after recovery \
         must not re-escalate to Unhealthy"
    );
}

#[test]
fn reset_returns_to_connected_from_any_state() {
    // reset() is the operator-intervention escape hatch — it MUST
    // work even from Unhealthy.
    let mut tracker = StreamHealthTracker::new(fast_config());
    tracker.record_heartbeat();
    sleep(Duration::from_millis(110));
    let _ = tracker.evaluate();
    let _ = tracker.evaluate();
    assert_eq!(tracker.state(), StreamHealthState::Unhealthy);

    tracker.reset();
    assert_eq!(
        tracker.state(),
        StreamHealthState::Connected,
        "reset() MUST recover even from Unhealthy"
    );
}

#[test]
fn snapshot_reports_state_consistent_with_state_method() {
    let mut tracker = StreamHealthTracker::new(fast_config());
    tracker.record_heartbeat();
    sleep(Duration::from_millis(50));
    let _ = tracker.evaluate(); // -> Degraded

    let snap = tracker.snapshot();
    assert_eq!(
        snap.state,
        tracker.state(),
        "snapshot.state MUST match StreamHealthTracker::state at the moment of capture"
    );
    assert_eq!(snap.state, StreamHealthState::Degraded);
    assert!(
        snap.last_heartbeat_ms_ago.is_some(),
        "snapshot must report time since last heartbeat once one has been recorded"
    );
}
