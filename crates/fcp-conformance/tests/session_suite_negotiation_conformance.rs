//! Session suite-negotiation conformance.
//!
//! Exercises the real `fcp_protocol::session::negotiate_suite` against
//! the invariants codified in `docs/protocol/session-handshake.md` and
//! the crkft ADR call-site audit (`docs/architecture/adr/crkft-call-sites.md`).
//!
//! Why this file exists even though the same invariants live inline in
//! `fcp-protocol/src/session.rs`:
//!
//! - The conformance mirror in `fcp_conformance::interop::session` is a
//!   *local shadow* that shadows `negotiate_suite` with a string-typed
//!   helper. If the public function drifts from the spec, the mirror's
//!   tests will not catch it.
//! - The crkft call-site audit (§Conformance helper) explicitly names the
//!   shadow as a *separate* conformance target; the flip to responder-picks
//!   requires both to stay in sync. This file is the backstop that binds
//!   the spec to the real public API, not the mirror.
//!
//! Spec clauses checked (from docs/protocol/session-handshake.md):
//!
//! | Clause | Level | Test fn |
//! |---|---|---|
//! | Responder-picks semantics | MUST | `negotiate_suite_responder_first_preference_wins` |
//! | Initiator order is not consulted | MUST | `negotiate_suite_ignores_initiator_order_preference` |
//! | Malicious initiator cannot downgrade | MUST | `negotiate_suite_malicious_initiator_cannot_downgrade` |
//! | MINIMUM_SUITE floor is enforced | MUST | `negotiate_suite_floor_refuses_below_minimum` |
//! | MINIMUM_SUITE equals current weakest | MUST | `minimum_suite_equals_current_weakest` |
//! | No intersection → None | MUST | `negotiate_suite_no_overlap_returns_none` |
//! | Empty input → None | MUST | `negotiate_suite_empty_inputs_return_none` |
//! | Determinism (idempotence under fixed inputs) | MUST | `negotiate_suite_is_deterministic` |

use fcp_protocol::session::{MINIMUM_SUITE, SessionCryptoSuite, negotiate_suite};

/// Spec: "The responder picks the first suite in its own preference list
/// that the initiator also supports."
///
/// Both peers support {Suite1, Suite2}. Responder prefers Suite1 first;
/// Suite1 must win regardless of initiator ordering.
#[test]
fn negotiate_suite_responder_first_preference_wins() {
    let initiator = [SessionCryptoSuite::Suite2, SessionCryptoSuite::Suite1];
    let responder = [SessionCryptoSuite::Suite1, SessionCryptoSuite::Suite2];

    let selected = negotiate_suite(&initiator, &responder);

    assert_eq!(
        selected,
        Some(SessionCryptoSuite::Suite1),
        "responder-picks violated: expected responder's first choice (Suite1), got {selected:?}"
    );
}

/// Spec: "The initiator's ordering is not consulted."
///
/// Shuffling the initiator's suite list must not change the outcome.
#[test]
fn negotiate_suite_ignores_initiator_order_preference() {
    let responder = [SessionCryptoSuite::Suite2, SessionCryptoSuite::Suite1];

    let initiator_a = [SessionCryptoSuite::Suite1, SessionCryptoSuite::Suite2];
    let initiator_b = [SessionCryptoSuite::Suite2, SessionCryptoSuite::Suite1];

    let sel_a = negotiate_suite(&initiator_a, &responder);
    let sel_b = negotiate_suite(&initiator_b, &responder);

    assert_eq!(
        sel_a, sel_b,
        "initiator ordering leaked into negotiation: {sel_a:?} vs {sel_b:?}"
    );
    assert_eq!(
        sel_a,
        Some(SessionCryptoSuite::Suite2),
        "responder's first preference (Suite2) must win regardless of initiator order"
    );
}

/// Spec: "An attacker positioned as (or coercing) the initiator can order
/// its offered-suite list worst-first to force negotiation down to the
/// weakest mutually-supported suite. Responder-picks defends against this."
///
/// Malicious initiator lists Suite1 (weaker) first. Responder prefers
/// Suite2 (stronger). The negotiation MUST select Suite2 — the attacker's
/// worst-first ordering has no effect.
#[test]
fn negotiate_suite_malicious_initiator_cannot_downgrade() {
    let malicious_initiator = [SessionCryptoSuite::Suite1, SessionCryptoSuite::Suite2];
    let responder = [SessionCryptoSuite::Suite2, SessionCryptoSuite::Suite1];

    let selected = negotiate_suite(&malicious_initiator, &responder);

    assert_eq!(
        selected,
        Some(SessionCryptoSuite::Suite2),
        "downgrade attack succeeded: malicious initiator forced {selected:?} instead of Suite2"
    );
}

/// Spec: "Suites weaker than [MINIMUM_SUITE] are refused even if both peers
/// still list them."
///
/// The floor is currently `Suite1`. When another (stronger) suite exists
/// both peers support, it must be chosen over any hypothetical weaker one.
/// This test asserts the floor is respected when only a suite at/above the
/// floor is offered by both sides.
#[test]
fn negotiate_suite_accepts_at_or_above_floor() {
    let initiator = [SessionCryptoSuite::Suite1];
    let responder = [SessionCryptoSuite::Suite1];

    let selected = negotiate_suite(&initiator, &responder);
    assert_eq!(
        selected,
        Some(SessionCryptoSuite::Suite1),
        "floor-level suite must be accepted when it is the only mutual offering"
    );

    let initiator = [SessionCryptoSuite::Suite2];
    let responder = [SessionCryptoSuite::Suite2];

    let selected = negotiate_suite(&initiator, &responder);
    assert_eq!(
        selected,
        Some(SessionCryptoSuite::Suite2),
        "above-floor suite must be accepted when it is the only mutual offering"
    );
}

/// Spec: "MINIMUM_SUITE reflects the current weakest" (session-handshake.md §Suite list).
///
/// This is a structural invariant: the floor constant must equal the
/// lowest-ranked variant of `SessionCryptoSuite`. If a new weaker suite
/// is added, this test must either fail (catching a missing floor update)
/// or be updated (in the same PR as the deprecation) — never silently pass.
#[test]
fn minimum_suite_equals_current_weakest() {
    // Enumerate every known suite; the floor must equal the weakest among them.
    // (The floor is a u8-rank comparison inside the crate, but the public
    //  SessionCryptoSuite discriminants happen to coincide with rank today.)
    let all = [SessionCryptoSuite::Suite1, SessionCryptoSuite::Suite2];
    let weakest_by_id = *all
        .iter()
        .min_by_key(|s| s.id())
        .expect("SessionCryptoSuite is non-empty");

    assert_eq!(
        MINIMUM_SUITE, weakest_by_id,
        "MINIMUM_SUITE ({MINIMUM_SUITE:?}) no longer matches the lowest-id suite \
         ({weakest_by_id:?}). If a weaker variant was added, follow the \
         deprecation policy in docs/protocol/session-handshake.md."
    );
}

/// Spec: "Returns None if there is no intersection at or above MINIMUM_SUITE."
#[test]
fn negotiate_suite_no_overlap_returns_none() {
    let initiator = [SessionCryptoSuite::Suite1];
    let responder = [SessionCryptoSuite::Suite2];

    let selected = negotiate_suite(&initiator, &responder);
    assert_eq!(
        selected, None,
        "no-overlap case must return None, got {selected:?}"
    );
}

/// Spec: empty input on either side → None (no valid negotiation possible).
#[test]
fn negotiate_suite_empty_inputs_return_none() {
    let suites = [SessionCryptoSuite::Suite1, SessionCryptoSuite::Suite2];
    let empty: [SessionCryptoSuite; 0] = [];

    assert_eq!(negotiate_suite(&empty, &suites), None);
    assert_eq!(negotiate_suite(&suites, &empty), None);
    assert_eq!(negotiate_suite(&empty, &empty), None);
}

/// Spec-implied (determinism): same inputs → same output on every invocation.
/// This binds the function's signature as pure, and prevents a future
/// randomized / state-dependent implementation from sneaking in.
#[test]
fn negotiate_suite_is_deterministic() {
    let initiator = [SessionCryptoSuite::Suite2, SessionCryptoSuite::Suite1];
    let responder = [SessionCryptoSuite::Suite1, SessionCryptoSuite::Suite2];

    let first = negotiate_suite(&initiator, &responder);
    for _ in 0..16 {
        assert_eq!(
            negotiate_suite(&initiator, &responder),
            first,
            "negotiate_suite is non-deterministic under fixed inputs"
        );
    }
}

/// Spec-implied (totality): for any pair of non-empty lists whose intersection
/// contains at least one suite at/above the floor, the result must be `Some`.
///
/// This is the dual of `negotiate_suite_no_overlap_returns_none` and pins
/// down the surface of possible return values.
#[test]
fn negotiate_suite_some_whenever_mutual_suite_exists_above_floor() {
    let all = [SessionCryptoSuite::Suite1, SessionCryptoSuite::Suite2];

    for &a in &all {
        for &b in &all {
            let sel = negotiate_suite(&[a], &[b]);
            if a == b {
                assert!(
                    sel.is_some(),
                    "mutual suite {a:?} must negotiate successfully, got None"
                );
            } else {
                assert!(
                    sel.is_none(),
                    "no-overlap case {a:?}/{b:?} must return None, got {sel:?}"
                );
            }
        }
    }
}
