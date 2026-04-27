//! `AdmissionController::record_auth_failure` + `gc_stale_peers`
//! conformance.
//!
//! Two surfaces that complement br-d2uly (byte/symbol budgets) and
//! br-uekoy (decode-slot + amplification):
//!
//! 1. **`record_auth_failure`** tracks failed-auth attempts per peer
//!    in a sliding window and surfaces `AuthFailureBudgetExceeded`
//!    with `retry_after` once the per-peer cap is hit. Distinct from
//!    byte/symbol/decode budgets — protects against credential-
//!    stuffing brute force at the admission layer before any
//!    cryptographic verification.
//!
//! 2. **`gc_stale_peers`** is the periodic memory-bound cleanup
//!    documented to prevent the per-peer tracking table from growing
//!    unboundedly across attacker-controlled NodeIds. Critical
//!    invariant: peers with `inflight_decodes > 0` MUST be kept
//!    regardless of staleness — otherwise an active decode would
//!    lose its tracked inflight count and a future
//!    `release_decode` would be a no-op.

use fcp_mesh::admission::{
    AdmissionController, AdmissionError, AdmissionPolicy, PeerBudget,
};
use fcp_tailscale::NodeId;

fn permissive_no_auth_required() -> AdmissionPolicy {
    AdmissionPolicy {
        per_peer: PeerBudget::new(
            u64::MAX, // bytes
            u32::MAX, // symbols
            5,        // failed auth — small so we can saturate
            8,        // decode slots
            u64::MAX, // decode cpu
        ),
        require_authenticated_requests: false,
        ..AdmissionPolicy::default()
    }
}

#[test]
fn record_auth_failure_succeeds_under_budget() {
    let mut ctrl = AdmissionController::new(permissive_no_auth_required());
    let peer = NodeId::new("node-auth-under");

    for _ in 0..3 {
        ctrl.record_auth_failure(&peer, 0)
            .expect("3 failures (limit=5) MUST succeed");
    }
}

#[test]
fn record_auth_failure_above_budget_returns_retry_after() {
    let mut ctrl = AdmissionController::new(permissive_no_auth_required());
    let peer = NodeId::new("node-auth-over");

    // Drive past the limit. limit=5 → 6th failure must trip.
    for _ in 0..5 {
        let _ = ctrl.record_auth_failure(&peer, 0);
    }
    let err = ctrl
        .record_auth_failure(&peer, 0)
        .expect_err("6th failure (limit=5) MUST be rejected");
    match err {
        AdmissionError::AuthFailureBudgetExceeded {
            current: _,
            limit,
            retry_after,
        } => {
            assert_eq!(limit, 5, "limit must reflect the configured cap");
            assert!(
                !retry_after.is_zero(),
                "AuthFailureBudgetExceeded.retry_after MUST be positive — \
                 the back-pressure signal callers honour to avoid a tight retry loop"
            );
        }
        other => panic!("expected AuthFailureBudgetExceeded, got {other:?}"),
    }
}

#[test]
fn record_auth_failure_per_peer_isolation() {
    // One noisy peer hitting the auth-failure cap MUST NOT affect
    // a polite peer's budget. Otherwise a credential-stuffing
    // attacker could rate-limit legitimate users by association.
    let mut ctrl = AdmissionController::new(permissive_no_auth_required());
    let noisy = NodeId::new("node-noisy");
    let polite = NodeId::new("node-polite");

    for _ in 0..10 {
        let _ = ctrl.record_auth_failure(&noisy, 0);
    }
    // polite peer should still have a clean budget.
    for _ in 0..5 {
        ctrl.record_auth_failure(&polite, 0)
            .expect("polite peer's budget must be independent of noisy peer's");
    }
}

#[test]
fn gc_stale_peers_removes_idle_old_peers() {
    let mut ctrl = AdmissionController::new(permissive_no_auth_required());
    let stale_peer = NodeId::new("node-stale");

    // Create a tracking entry by recording usage.
    ctrl.record_bytes(&stale_peer, 100, 0);
    assert_eq!(
        ctrl.peer_count(),
        1,
        "fixture sanity: peer is tracked after record_bytes"
    );

    // Run gc with now_ms far in the future and a 1000 ms staleness
    // threshold. The stale peer has no inflight decodes and its
    // window_start_ms is at 0; it MUST be evicted.
    ctrl.gc_stale_peers(60_000, 1_000);
    assert_eq!(
        ctrl.peer_count(),
        0,
        "stale, idle peer MUST be GC'd when (now - window_start) >= threshold"
    );
}

#[test]
fn gc_stale_peers_keeps_recent_peers() {
    let mut ctrl = AdmissionController::new(permissive_no_auth_required());
    let recent = NodeId::new("node-recent");
    ctrl.record_bytes(&recent, 100, 1_000);

    // Run gc with now_ms only slightly later — within the staleness
    // threshold. Peer MUST be kept.
    ctrl.gc_stale_peers(1_500, 1_000);
    assert_eq!(
        ctrl.peer_count(),
        1,
        "recent peer (within staleness threshold) MUST NOT be GC'd"
    );
}

#[test]
fn gc_stale_peers_keeps_peers_with_inflight_decodes_regardless_of_staleness() {
    // CRITICAL invariant: an active decoder MUST be kept across GC
    // even when its window is stale. Otherwise an active decode
    // would lose its inflight_decodes counter and a future
    // release_decode would silently no-op, eventually allowing the
    // same peer to over-allocate decode slots.
    let mut ctrl = AdmissionController::new(permissive_no_auth_required());
    let active = NodeId::new("node-active-decoder");

    // Acquire a decode slot first (this also creates the tracking
    // entry with inflight_decodes = 1).
    ctrl.try_acquire_decode(&active, 0)
        .expect("decode slot acquired");
    assert_eq!(ctrl.peer_count(), 1);

    // Run gc far in the future with a tiny staleness threshold —
    // by stale-window reasoning alone the peer would be evicted.
    ctrl.gc_stale_peers(60_000, 100);

    // But inflight_decodes>0 keeps the peer alive.
    assert_eq!(
        ctrl.peer_count(),
        1,
        "peer with inflight_decodes>0 MUST be kept by gc_stale_peers regardless of \
         window staleness — losing the inflight count would corrupt decode tracking"
    );
}

#[test]
fn gc_stale_peers_evicts_after_release_when_window_is_stale() {
    // Counterpart to the prior test: once inflight_decodes drops
    // to zero AND the window is stale, the peer becomes eligible
    // for GC.
    let mut ctrl = AdmissionController::new(permissive_no_auth_required());
    let peer = NodeId::new("node-released");

    ctrl.try_acquire_decode(&peer, 0).expect("acquire");
    ctrl.release_decode(&peer, 0);
    // Now inflight_decodes == 0 and window_start_ms is at 0.

    ctrl.gc_stale_peers(60_000, 100);
    assert_eq!(
        ctrl.peer_count(),
        0,
        "peer with inflight_decodes=0 AND stale window MUST be evicted"
    );
}

#[test]
fn gc_stale_peers_on_empty_table_is_a_no_op() {
    let mut ctrl = AdmissionController::new(permissive_no_auth_required());
    assert_eq!(ctrl.peer_count(), 0);
    ctrl.gc_stale_peers(60_000, 100);
    assert_eq!(
        ctrl.peer_count(),
        0,
        "gc on empty table is a no-op (no panic)"
    );
}

#[test]
fn gc_stale_peers_preserves_other_peers_when_one_is_evicted() {
    let mut ctrl = AdmissionController::new(permissive_no_auth_required());
    let stale = NodeId::new("node-stale");
    let fresh = NodeId::new("node-fresh");

    ctrl.record_bytes(&stale, 1, 0); // window starts at 0
    ctrl.record_bytes(&fresh, 1, 50_000); // window starts at 50_000

    // Threshold = 30_000 ms.
    // stale: now_ms - window_start = 60_000 - 0 = 60_000 (>= 30_000) -> evict.
    // fresh: now_ms - window_start = 60_000 - 50_000 = 10_000 (< 30_000) -> keep.
    ctrl.gc_stale_peers(60_000, 30_000);
    assert_eq!(
        ctrl.peer_count(),
        1,
        "fresh peer must remain; stale peer must be evicted"
    );
    assert!(
        ctrl.get_usage(&fresh).is_some(),
        "fresh peer entry MUST persist"
    );
    assert!(
        ctrl.get_usage(&stale).is_none(),
        "stale peer entry MUST be evicted"
    );
}

#[test]
fn record_auth_failure_does_not_allocate_for_unrelated_peer() {
    // Sanity: incrementing one peer's failure count does NOT
    // allocate entries for unrelated peers (per-peer isolation
    // applies to allocation too).
    let mut ctrl = AdmissionController::new(permissive_no_auth_required());
    let alice = NodeId::new("alice");
    let _ = ctrl.record_auth_failure(&alice, 0);
    assert_eq!(
        ctrl.peer_count(),
        1,
        "auth failure must allocate for the calling peer only"
    );
    assert!(ctrl.get_usage(&NodeId::new("bob")).is_none());
}
