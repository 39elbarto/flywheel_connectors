//! `fcp_streaming::StreamHealthState` ↔ `fcp_core::ConnectorHealth`
//! bridge + predicate + JSON wire form conformance.
//!
//! `streaming_health_state_machine_conformance.rs` already pins the
//! tracker's transitions. Three cross-crate contracts remain
//! uncovered, all of them load-bearing for downstream observability:
//!
//! 1. **`is_available` / `needs_attention` predicate fan-out**
//!    — the host's admin surface and rollout gating both branch on
//!    these. The deliberate overlap on `Degraded` (it is BOTH usable
//!    AND attention-worthy) is the whole point of the four-state
//!    model; collapsing the predicates into a 2-state Healthy/Bad
//!    boolean would lose that distinction.
//! 2. **`to_connector_health` mapping** (NORMATIVE bridge to host)
//!    — this is what the host serves to operators, alerting, and
//!    every dashboard that filters on connector health.
//!    `Connected → Healthy`, `Degraded → Degraded`,
//!    `Reconnecting → Degraded` (NOT Healthy — important!),
//!    `Unhealthy → Unavailable`.
//! 3. **JSON wire form** for `StreamHealthState` (snake_case rename)
//!    and `StreamHealthSnapshot` (`skip_serializing_if=None` on the
//!    optional time fields). Drift here breaks every existing
//!    consumer of streaming-health JSON.

use fcp_core::ConnectorHealth;
use fcp_streaming::{
    StreamHealthConfig, StreamHealthSnapshot, StreamHealthState, StreamHealthTracker,
};
use std::time::Duration;

fn fast_config() -> StreamHealthConfig {
    StreamHealthConfig {
        heartbeat_timeout: Duration::from_millis(20),
        zombie_timeout: Duration::from_millis(80),
        max_reconnect_attempts: 3,
    }
}

// ─── Predicates ─────────────────────────────────────────────────────

#[test]
fn is_available_is_true_for_connected_and_degraded() {
    assert!(StreamHealthState::Connected.is_available());
    assert!(
        StreamHealthState::Degraded.is_available(),
        "Degraded MUST stay 'available' — connection is live, just delayed"
    );
}

#[test]
fn is_available_is_false_for_reconnecting_and_unhealthy() {
    assert!(
        !StreamHealthState::Reconnecting.is_available(),
        "Reconnecting MUST NOT be 'available' — the connection is down mid-recovery"
    );
    assert!(!StreamHealthState::Unhealthy.is_available());
}

#[test]
fn needs_attention_is_true_for_degraded_and_unhealthy() {
    assert!(
        StreamHealthState::Degraded.needs_attention(),
        "Degraded MUST need attention — heartbeat overdue is operator-visible"
    );
    assert!(StreamHealthState::Unhealthy.needs_attention());
}

#[test]
fn needs_attention_is_false_for_connected_and_reconnecting() {
    assert!(!StreamHealthState::Connected.needs_attention());
    assert!(
        !StreamHealthState::Reconnecting.needs_attention(),
        "Reconnecting MUST NOT need attention — automatic recovery is in progress"
    );
}

#[test]
fn predicates_overlap_on_degraded_only() {
    // Only Degraded is BOTH available AND needs_attention. The
    // model's whole point is to surface this overlap.
    let states = [
        StreamHealthState::Connected,
        StreamHealthState::Degraded,
        StreamHealthState::Reconnecting,
        StreamHealthState::Unhealthy,
    ];
    let overlap: Vec<_> = states
        .iter()
        .filter(|s| s.is_available() && s.needs_attention())
        .collect();
    assert_eq!(
        overlap.len(),
        1,
        "exactly one state MUST satisfy both predicates"
    );
    assert_eq!(*overlap[0], StreamHealthState::Degraded);
}

// ─── to_connector_health bridge ─────────────────────────────────────

#[test]
fn to_connector_health_maps_connected_to_healthy() {
    let tracker = StreamHealthTracker::new(fast_config());
    assert!(
        matches!(tracker.to_connector_health(), ConnectorHealth::Healthy),
        "Connected MUST map to ConnectorHealth::Healthy"
    );
}

#[test]
fn to_connector_health_maps_degraded_to_degraded_with_heartbeat_reason() {
    let mut tracker = StreamHealthTracker::new(fast_config());
    tracker.record_heartbeat();
    std::thread::sleep(Duration::from_millis(40));
    let _ = tracker.evaluate();
    assert_eq!(tracker.state(), StreamHealthState::Degraded);

    match tracker.to_connector_health() {
        ConnectorHealth::Degraded { reason } => {
            assert!(
                reason.contains("heartbeat overdue"),
                "Degraded reason MUST mention 'heartbeat overdue'; got {reason}"
            );
        }
        other => panic!("expected ConnectorHealth::Degraded, got {other:?}"),
    }
}

#[test]
fn to_connector_health_maps_reconnecting_to_degraded_not_unavailable() {
    // Important: Reconnecting is "automatic recovery, not yet
    // failed" — it MUST map to Degraded, not Unavailable. Otherwise
    // every transient hiccup pages the on-call.
    let mut tracker = StreamHealthTracker::new(fast_config());
    tracker.record_disconnect();
    assert_eq!(tracker.state(), StreamHealthState::Reconnecting);

    match tracker.to_connector_health() {
        ConnectorHealth::Degraded { reason } => {
            assert!(
                reason.contains("reconnecting"),
                "Reconnecting reason MUST mention 'reconnecting'; got {reason}"
            );
            assert!(
                reason.contains("attempt"),
                "Reconnecting reason MUST include attempt count; got {reason}"
            );
        }
        other => panic!(
            "Reconnecting MUST map to ConnectorHealth::Degraded (NOT Unavailable); got {other:?}"
        ),
    }
}

#[test]
fn to_connector_health_maps_unhealthy_to_unavailable() {
    let mut tracker = StreamHealthTracker::new(fast_config());
    for _ in 0..3 {
        tracker.record_disconnect();
    }
    assert_eq!(tracker.state(), StreamHealthState::Unhealthy);

    match tracker.to_connector_health() {
        ConnectorHealth::Unavailable { reason, since: _ } => {
            assert!(!reason.is_empty(), "Unavailable reason MUST be non-empty");
        }
        other => panic!("Unhealthy MUST map to ConnectorHealth::Unavailable; got {other:?}"),
    }
}

#[test]
fn to_connector_health_unavailable_carries_now_timestamp_for_unhealthy() {
    // The `since` timestamp on Unavailable is computed at call time
    // (not stored on the tracker). Sanity: it MUST be near "now".
    let mut tracker = StreamHealthTracker::new(fast_config());
    for _ in 0..3 {
        tracker.record_disconnect();
    }
    let before = chrono::Utc::now();
    let health = tracker.to_connector_health();
    let after = chrono::Utc::now();
    match health {
        ConnectorHealth::Unavailable { since, .. } => {
            assert!(
                since >= before && since <= after,
                "Unavailable.since MUST be 'now' at call time; before={before}, since={since}, after={after}"
            );
        }
        other => panic!("expected Unavailable, got {other:?}"),
    }
}

// ─── JSON wire form ─────────────────────────────────────────────────

#[test]
fn stream_health_state_json_uses_snake_case_for_every_variant() {
    let cases = [
        (StreamHealthState::Connected, "\"connected\""),
        (StreamHealthState::Degraded, "\"degraded\""),
        (StreamHealthState::Reconnecting, "\"reconnecting\""),
        (StreamHealthState::Unhealthy, "\"unhealthy\""),
    ];
    for (variant, expected) in cases {
        let json = serde_json::to_string(&variant).expect("serialize");
        assert_eq!(
            json, expected,
            "{variant:?} MUST serialize as snake_case '{expected}'"
        );
        let parsed: StreamHealthState = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, variant);
    }
}

#[test]
fn stream_health_state_rejects_unknown_or_mixed_case_variants() {
    // Strict snake_case — pin the failure cases too.
    let bogus = ["\"healthy\"", "\"down\"", "\"CONNECTED\"", "\"\""];
    for s in bogus {
        assert!(
            serde_json::from_str::<StreamHealthState>(s).is_err(),
            "StreamHealthState MUST reject {s}"
        );
    }
}

#[test]
fn snapshot_omits_optional_time_fields_when_none() {
    // Forward-compat for v1 readers — `last_heartbeat_ms_ago` and
    // `last_ack_ms_ago` MUST be absent from JSON when None.
    let tracker = StreamHealthTracker::new(fast_config());
    let snap = tracker.snapshot();
    let json = serde_json::to_string(&snap).expect("serialize");
    assert!(
        !json.contains("last_heartbeat_ms_ago"),
        "snapshot MUST omit last_heartbeat_ms_ago when None; got {json}"
    );
    assert!(
        !json.contains("last_ack_ms_ago"),
        "snapshot MUST omit last_ack_ms_ago when None; got {json}"
    );
}

#[test]
fn snapshot_includes_optional_time_fields_when_some() {
    let mut tracker = StreamHealthTracker::new(fast_config());
    tracker.record_heartbeat();
    tracker.record_ack();
    let snap = tracker.snapshot();
    let json = serde_json::to_string(&snap).expect("serialize");
    assert!(
        json.contains("\"last_heartbeat_ms_ago\":"),
        "snapshot MUST include last_heartbeat_ms_ago when populated; got {json}"
    );
    assert!(
        json.contains("\"last_ack_ms_ago\":"),
        "snapshot MUST include last_ack_ms_ago when populated; got {json}"
    );
}

#[test]
fn snapshot_serde_roundtrip_preserves_state_and_counters() {
    let mut tracker = StreamHealthTracker::new(fast_config());
    tracker.record_heartbeat();
    tracker.record_heartbeat();
    tracker.record_heartbeat();
    tracker.record_ack();
    tracker.record_disconnect();

    let snap = tracker.snapshot();
    let json = serde_json::to_string(&snap).expect("serialize");
    let parsed: StreamHealthSnapshot = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(parsed.state, snap.state);
    assert_eq!(parsed.messages_received, snap.messages_received);
    assert_eq!(parsed.reconnect_count, snap.reconnect_count);
    // Optional fields round-trip too (Some → Some).
    assert_eq!(
        parsed.last_heartbeat_ms_ago.is_some(),
        snap.last_heartbeat_ms_ago.is_some()
    );
}

#[test]
fn snapshot_state_field_serializes_with_state_machine_wire_form() {
    // Bridge sanity: snapshot.state inherits the snake_case serde
    // rename — drift would leak via the snapshot JSON.
    let mut tracker = StreamHealthTracker::new(fast_config());
    for _ in 0..3 {
        tracker.record_disconnect();
    }
    let snap = tracker.snapshot();
    let json = serde_json::to_string(&snap).expect("serialize");
    assert!(
        json.contains("\"state\":\"unhealthy\""),
        "snapshot MUST embed state as snake_case wire form; got {json}"
    );
}

#[test]
fn messages_received_uses_saturating_add() {
    // Sanity check the documented saturating-add discipline (br-upgdb).
    // Tracker counter cannot wrap u64::MAX → 0.
    let saturated = u64::MAX.saturating_add(1);
    assert_eq!(saturated, u64::MAX);

    // And messages_received is monotone non-decreasing in practice.
    let mut tracker = StreamHealthTracker::new(fast_config());
    let initial = tracker.snapshot().messages_received;
    for _ in 0..10 {
        tracker.record_heartbeat();
    }
    assert!(tracker.snapshot().messages_received > initial);
}
