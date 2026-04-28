//! `AdmissionController` back-pressure conformance.
//!
//! `fcp_mesh::admission::AdmissionController` is the per-peer
//! back-pressure gate every connector sits behind. It enforces
//! NORMATIVE PeerBudget caps on bytes/min, symbols/min, decode
//! capacity, and authentication state. Zero conformance coverage
//! today (123 inline tests cover internals; the cross-crate
//! contract has been unpinned).
//!
//! Properties pinned (NORMATIVE):
//!
//! 1. **Within-budget admission succeeds.** A request whose
//!    (bytes, symbols) fit under the per-peer caps must return
//!    Ok(()).
//! 2. **Byte-budget exceeded surfaces `retry_after`.** The
//!    documented back-pressure signal: callers must honour the
//!    suggested retry delay rather than spinning.
//! 3. **Symbol-budget exceeded surfaces `retry_after`.**
//! 4. **AuthenticationRequired fires when the policy demands it
//!    and the peer is unauthenticated.** This is the cheap
//!    short-circuit reject path — admission never spends budget
//!    cycles on unauthenticated peers when authentication is
//!    required.
//! 5. **Per-peer isolation.** One peer exhausting their budget
//!    MUST NOT affect another peer's admission status.
//! 6. **Restrictive vs permissive presets give contrasting
//!    limits.** PeerBudget::restrictive() must reject what
//!    PeerBudget::permissive() admits.
//!
//! These tests use freshly-constructed AdmissionControllers so
//! state from prior tests cannot leak.

use std::time::Duration;

use fcp_mesh::admission::{AdmissionController, AdmissionError, AdmissionPolicy, PeerBudget};
use fcp_tailscale::NodeId;

fn permissive_policy() -> AdmissionPolicy {
    AdmissionPolicy {
        per_peer: PeerBudget::permissive(),
        require_authenticated_requests: false,
        ..AdmissionPolicy::default()
    }
}

fn restrictive_policy() -> AdmissionPolicy {
    AdmissionPolicy {
        per_peer: PeerBudget::restrictive(),
        require_authenticated_requests: false,
        ..AdmissionPolicy::default()
    }
}

#[test]
fn within_budget_admission_succeeds() {
    let mut controller = AdmissionController::new(permissive_policy());
    let peer = NodeId::new("node-within");

    controller
        .check_admission(&peer, 1024, 16, true, 0)
        .expect("within-budget request must be admitted");
}

#[test]
fn byte_budget_exceeded_returns_retry_after() {
    // Permissive byte cap is 512 MB/min; submit 600 MB to force the
    // ByteBudgetExceeded path. The retry_after MUST be > 0 so the
    // caller has a usable back-pressure signal rather than a busy
    // loop.
    let mut controller = AdmissionController::new(permissive_policy());
    let peer = NodeId::new("node-byte-overrun");
    let oversized = 600 * 1024 * 1024;

    let err = controller
        .check_admission(&peer, oversized, 1, true, 0)
        .expect_err("oversized byte request must be rejected");
    match err {
        AdmissionError::ByteBudgetExceeded {
            current,
            limit,
            retry_after,
        } => {
            // `current` is the in-window usage that EXISTED before
            // this request (saturating_add is the trigger for the
            // overrun, but the error reports the pre-request total).
            // For a fresh peer, current == 0; the test still
            // verifies the cap was enforced because (current + bytes
            // > limit) is implicit in the rejection path.
            assert!(
                limit > 0,
                "ByteBudgetExceeded.limit must reflect the per-peer cap"
            );
            assert!(
                current.saturating_add(oversized) > limit,
                "rejection invariant: current ({current}) + oversized ({oversized}) > limit ({limit}) \
                 must hold for ByteBudgetExceeded to be the right variant"
            );
            assert!(
                retry_after > Duration::ZERO,
                "ByteBudgetExceeded.retry_after MUST be positive — the back-pressure \
                 signal callers depend on; got {retry_after:?}"
            );
        }
        other => panic!("expected ByteBudgetExceeded, got {other:?}"),
    }
}

#[test]
fn symbol_budget_exceeded_returns_retry_after() {
    // Restrictive caps: 10_000 symbols/min. Submit 20_000.
    let mut controller = AdmissionController::new(restrictive_policy());
    let peer = NodeId::new("node-sym-overrun");

    let err = controller
        .check_admission(&peer, 0, 20_000, true, 0)
        .expect_err("oversized symbol request must be rejected");
    match err {
        AdmissionError::SymbolBudgetExceeded {
            current: _,
            limit,
            retry_after,
        } => {
            assert!(limit > 0);
            assert!(
                retry_after > Duration::ZERO,
                "SymbolBudgetExceeded.retry_after MUST be positive; got {retry_after:?}"
            );
        }
        other => panic!("expected SymbolBudgetExceeded, got {other:?}"),
    }
}

#[test]
fn authentication_required_short_circuits_before_budget_checks() {
    // When the policy requires authenticated requests and the peer
    // is_authenticated=false, the admission MUST short-circuit with
    // AuthenticationRequired regardless of how small or oversized
    // the resource request is. This pins the cheap-reject ordering.
    let mut policy = AdmissionPolicy::default();
    policy.require_authenticated_requests = true;
    policy.per_peer = PeerBudget::permissive();
    let mut controller = AdmissionController::new(policy);
    let peer = NodeId::new("node-unauth");

    // Even a tiny request must be rejected.
    let err = controller
        .check_admission(&peer, 1, 1, false, 0)
        .expect_err("unauth peer must be rejected when require_authenticated_requests=true");
    assert!(
        matches!(err, AdmissionError::AuthenticationRequired),
        "expected AuthenticationRequired (cheap short-circuit), got {err:?}"
    );

    // And an oversized one too — same error variant; the budget
    // check is NOT reached.
    let err = controller
        .check_admission(&peer, u64::MAX / 2, u32::MAX / 2, false, 0)
        .expect_err("oversized unauth peer also rejected");
    assert!(
        matches!(err, AdmissionError::AuthenticationRequired),
        "AuthenticationRequired must short-circuit BEFORE budget checks even on oversized \
         requests; got {err:?}"
    );
}

#[test]
fn authentication_required_passes_through_when_peer_is_authenticated() {
    let mut policy = AdmissionPolicy::default();
    policy.require_authenticated_requests = true;
    policy.per_peer = PeerBudget::permissive();
    let mut controller = AdmissionController::new(policy);
    let peer = NodeId::new("node-authed");

    controller
        .check_admission(&peer, 1024, 8, true, 0)
        .expect("authenticated peer must pass when policy demands authentication");
}

#[test]
fn per_peer_isolation_one_peer_overrun_does_not_affect_another() {
    // Critical: per-peer budgets MUST be tracked independently.
    // Otherwise a noisy neighbour could DoS every other peer.
    let mut controller = AdmissionController::new(restrictive_policy());
    let noisy = NodeId::new("node-noisy");
    let polite = NodeId::new("node-polite");

    // Drive `noisy` to overrun. Restrictive byte cap is 1 MiB/min.
    let _ = controller
        .check_admission(&noisy, 2 * 1024 * 1024, 1, true, 0)
        .expect_err("noisy peer overruns byte budget");

    // `polite` must still be admitted at a reasonable request size.
    controller
        .check_admission(&polite, 1024, 8, true, 0)
        .expect("per-peer isolation broken: polite peer rejected after noisy peer's overrun");
}

#[test]
fn restrictive_preset_rejects_what_permissive_admits() {
    // Same request, two different policies: a 4 MiB/100 symbols
    // request fits under permissive (512 MiB/1 M-symbol caps) but
    // not under restrictive (1 MiB/10 k-symbol caps).
    let bytes = 4 * 1024 * 1024;
    let symbols = 100;
    let peer = NodeId::new("node-shared");

    let mut permissive_ctl = AdmissionController::new(permissive_policy());
    permissive_ctl
        .check_admission(&peer, bytes, symbols, true, 0)
        .expect("permissive policy MUST admit a 4 MiB / 100-symbol request");

    let mut restrictive_ctl = AdmissionController::new(restrictive_policy());
    let err = restrictive_ctl
        .check_admission(&peer, bytes, symbols, true, 0)
        .expect_err("restrictive policy MUST reject a 4 MiB request");
    assert!(
        matches!(err, AdmissionError::ByteBudgetExceeded { .. }),
        "expected ByteBudgetExceeded under restrictive policy; got {err:?}"
    );
}

#[test]
fn budget_check_is_first_byte_then_symbol_when_both_would_exceed() {
    // When BOTH bytes and symbols exceed at once, the implementation
    // checks byte budget FIRST. This pins the ordering so callers
    // and metrics can rely on a deterministic error variant when
    // multiple caps would simultaneously fail.
    let mut controller = AdmissionController::new(restrictive_policy());
    let peer = NodeId::new("node-both-overrun");

    let err = controller
        .check_admission(&peer, 5 * 1024 * 1024, 50_000, true, 0)
        .expect_err("simultaneous byte+symbol overrun must be rejected");
    assert!(
        matches!(err, AdmissionError::ByteBudgetExceeded { .. }),
        "byte check MUST run before symbol check; got {err:?}"
    );
}

#[test]
fn fresh_peer_within_budget_does_not_count_against_others() {
    // Three peers each making small requests — admission must
    // succeed for each without mutual interference. Pins that
    // tracking is per-peer keyed, not aggregated globally.
    let mut controller = AdmissionController::new(restrictive_policy());
    for label in ["alpha", "bravo", "charlie"] {
        let peer = NodeId::new(format!("node-{label}"));
        controller
            .check_admission(&peer, 1024, 8, true, 0)
            .unwrap_or_else(|err| {
                panic!("peer {label} rejected: {err:?} — per-peer keying broken")
            });
    }
}
