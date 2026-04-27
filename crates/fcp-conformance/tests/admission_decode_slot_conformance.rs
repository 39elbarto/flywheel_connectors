//! `AdmissionController` decode-slot + amplification back-pressure
//! conformance.
//!
//! This pins the part of the AdmissionController contract that is
//! distinct from the bytes/symbols budget covered by br-d2uly:
//!
//! 1. **Decode-slot acquire/release** — `try_acquire_decode` tracks
//!    concurrent inflight decodes per peer; `DecodeCapacityExceeded`
//!    is raised when the peer exceeds `max_inflight_decodes`.
//! 2. **Saturating release** — `release_decode` decrements the
//!    inflight count without underflow. Extra releases on a peer at
//!    zero are no-ops (br-llfi4: same discipline as `clear_authenticated`).
//! 3. **No-allocate-on-unknown-peer release** — `release_decode` for
//!    a peer never tracked must NOT allocate a tracking entry. The
//!    fix from br-llfi4 prevents an attacker who triggers many
//!    `MeshNode::remove_peer` calls from filling the per-peer table
//!    via the release path.
//! 4. **Per-peer isolation** — one peer saturating their decode
//!    slots MUST NOT block another peer.
//! 5. **Anti-amplification** — `check_amplification` rejects
//!    response_symbols > request_symbols * max_amplification_factor
//!    for unauthenticated requests, but exempts authenticated peers
//!    with proof-of-need.
//!
//! These tests use a deliberately-small `max_inflight_decodes` (3) so
//! the saturation/release semantics surface in a few iterations.

use fcp_mesh::admission::{
    AdmissionController, AdmissionError, AdmissionPolicy, PeerBudget,
};
use fcp_tailscale::NodeId;

fn three_slot_policy() -> AdmissionPolicy {
    AdmissionPolicy {
        per_peer: PeerBudget::new(
            u64::MAX, // bytes
            u32::MAX, // symbols
            u32::MAX, // failed auth
            3,        // max_inflight_decodes — small so we can saturate
            u64::MAX, // decode cpu ms
        ),
        require_authenticated_requests: false,
        max_amplification_factor: 4,
        strict_unauthenticated_limits: false,
        ..AdmissionPolicy::default()
    }
}

#[test]
fn try_acquire_decode_succeeds_under_limit() {
    let mut controller = AdmissionController::new(three_slot_policy());
    let peer = NodeId::new("node-decode-1");

    controller
        .try_acquire_decode(&peer, 0)
        .expect("first decode slot must be acquired");
    controller
        .try_acquire_decode(&peer, 0)
        .expect("second decode slot must be acquired");
    controller
        .try_acquire_decode(&peer, 0)
        .expect("third decode slot — exact limit — must be acquired");
}

#[test]
fn try_acquire_decode_at_limit_returns_decode_capacity_exceeded() {
    let mut controller = AdmissionController::new(three_slot_policy());
    let peer = NodeId::new("node-decode-saturated");

    for _ in 0..3 {
        controller.try_acquire_decode(&peer, 0).unwrap();
    }

    let err = controller
        .try_acquire_decode(&peer, 0)
        .expect_err("4th decode slot above limit=3 must reject");
    match err {
        AdmissionError::DecodeCapacityExceeded { current, limit } => {
            assert_eq!(current, 3, "current must reflect the saturated state");
            assert_eq!(limit, 3, "limit must reflect the configured cap");
        }
        other => panic!("expected DecodeCapacityExceeded, got {other:?}"),
    }
}

#[test]
fn release_decode_frees_a_slot() {
    let mut controller = AdmissionController::new(three_slot_policy());
    let peer = NodeId::new("node-decode-release");

    for _ in 0..3 {
        controller.try_acquire_decode(&peer, 0).unwrap();
    }

    // Saturated. Release one slot.
    controller.release_decode(&peer, 0);

    // Now we should be able to acquire one more.
    controller
        .try_acquire_decode(&peer, 0)
        .expect("release_decode must free a slot for a subsequent acquire");
}

#[test]
fn release_decode_is_saturating_at_zero() {
    // Extra release calls when inflight_decodes == 0 must NOT
    // underflow to u32::MAX. Otherwise an attacker triggering
    // mismatched release calls could permanently mark a peer as
    // having "infinite" inflight decodes and block legitimate
    // future requests.
    let mut controller = AdmissionController::new(three_slot_policy());
    let peer = NodeId::new("node-decode-saturating");

    controller.try_acquire_decode(&peer, 0).unwrap();
    controller.release_decode(&peer, 0); // back to 0

    // Several extra releases — each must saturate at 0.
    for _ in 0..10 {
        controller.release_decode(&peer, 0);
    }

    // We should still be able to acquire 3 slots cleanly. If the
    // counter had wrapped to u32::MAX, every acquire would reject.
    for _ in 0..3 {
        controller
            .try_acquire_decode(&peer, 0)
            .expect("saturating-at-zero release must not corrupt the counter");
    }
}

#[test]
fn release_decode_does_not_allocate_for_unknown_peer() {
    // br-llfi4 discipline: release_decode for a peer that was never
    // tracked must NOT allocate a fresh PeerUsage entry. Pin this
    // by checking that get_usage returns None after a release on an
    // untracked peer.
    let mut controller = AdmissionController::new(three_slot_policy());
    let unknown = NodeId::new("node-never-tracked");

    controller.release_decode(&unknown, 0);

    assert!(
        controller.get_usage(&unknown).is_none(),
        "release_decode on an untracked peer MUST NOT allocate a tracking entry \
         (br-llfi4: prevents fill attacks via the release path)"
    );
}

#[test]
fn per_peer_decode_slot_isolation() {
    // Peer A saturates their decode slots; peer B must remain able
    // to acquire freely. Otherwise a single noisy peer could DoS
    // every other peer's decode capacity.
    let mut controller = AdmissionController::new(three_slot_policy());
    let saturated = NodeId::new("node-saturated");
    let polite = NodeId::new("node-polite");

    for _ in 0..3 {
        controller.try_acquire_decode(&saturated, 0).unwrap();
    }
    assert!(
        controller.try_acquire_decode(&saturated, 0).is_err(),
        "fixture sanity: saturated peer is at capacity"
    );

    for _ in 0..3 {
        controller
            .try_acquire_decode(&polite, 0)
            .expect("per-peer decode-slot isolation broken: polite peer rejected");
    }
}

#[test]
fn check_amplification_rejects_unauthenticated_oversized_response() {
    // max_amplification_factor = 4. A request for 10 symbols
    // can yield at most 40 response symbols for an unauthenticated
    // peer. Asking for 100 must fail.
    let controller = AdmissionController::new(three_slot_policy());
    let peer = NodeId::new("node-amp");

    let err = controller
        .check_amplification(&peer, 10, 100, false, false)
        .expect_err("response above amplification factor for unauthenticated peer must reject");
    match err {
        AdmissionError::AmplificationViolation {
            request_symbols,
            response_symbols,
            max_factor,
        } => {
            assert_eq!(request_symbols, 10);
            assert_eq!(response_symbols, 100);
            assert_eq!(max_factor, 4);
        }
        other => panic!("expected AmplificationViolation, got {other:?}"),
    }
}

#[test]
fn check_amplification_accepts_response_at_factor_boundary() {
    // Exactly request * factor must be allowed (the cap is inclusive).
    let controller = AdmissionController::new(three_slot_policy());
    let peer = NodeId::new("node-amp-boundary");

    controller
        .check_amplification(&peer, 10, 40, false, false)
        .expect("response at exactly request*max_factor MUST be allowed (inclusive cap)");
}

#[test]
fn check_amplification_exempts_authenticated_with_proof_of_need() {
    // Authenticated peers WITH proof-of-need bypass the
    // amplification cap entirely. This is the documented escape
    // hatch for legitimate large-fanout repair: trust the peer to
    // state a proof-of-need and let the actual budget enforcement
    // happen via try_acquire_decode + record_decode_cpu instead.
    let controller = AdmissionController::new(three_slot_policy());
    let peer = NodeId::new("node-amp-trusted");

    controller
        .check_amplification(&peer, 10, 10_000, true, true)
        .expect(
            "authenticated peer with proof-of-need must be exempt from the amplification \
             cap regardless of how large the response is",
        );
}

#[test]
fn check_amplification_does_not_exempt_authenticated_without_proof_of_need() {
    // The exemption requires BOTH authenticated AND proof-of-need.
    // An authenticated peer without proof-of-need still hits the
    // cap. Pins that the exemption is a conjunction, not a
    // disjunction.
    let controller = AdmissionController::new(three_slot_policy());
    let peer = NodeId::new("node-amp-half-trust");

    let err = controller
        .check_amplification(&peer, 10, 100, true, false)
        .expect_err("authenticated WITHOUT proof-of-need must still hit the amplification cap");
    assert!(
        matches!(err, AdmissionError::AmplificationViolation { .. }),
        "expected AmplificationViolation, got {err:?}"
    );
}
