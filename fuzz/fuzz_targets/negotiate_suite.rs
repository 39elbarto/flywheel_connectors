#![no_main]

//! Fuzz target for `negotiate_suite` responder-preference selection
//! with `MINIMUM_SUITE` floor (session.rs:957-966).
//!
//! `negotiate_suite(initiator_suites, responder_suites)` picks the
//! first entry in `responder_suites` that ALSO appears in
//! `initiator_suites` AND ranks at or above `MINIMUM_SUITE`
//! (currently `Suite1` rank 1). Returns `None` if no such suite
//! exists. This is the downgrade-resistant negotiation primitive
//! protecting against a malicious or coerced initiator that orders
//! its offers worst-first; transcript binding handles in-flight
//! rewriting separately.
//!
//! NOT directly fuzzed: existing session_metamorphic exercises round-
//! trips on a fixed suite, not the negotiation function itself, so a
//! regression that flipped to initiator-preference ordering or
//! disabled the floor would slip through.
//!
//! Properties asserted:
//!
//!   1. **Membership**: when `Some(s)` is returned, `s` is in BOTH
//!      `initiator_suites` AND `responder_suites`.
//!   2. **Floor**: when `Some(s)` is returned, the suite rank
//!      (1=Suite1, 2=Suite2) is ≥ 1 (i.e. it's a valid known suite
//!      passing the floor).
//!   3. **Responder preference**: the result is the FIRST entry in
//!      `responder_suites` (left-to-right) that appears in
//!      `initiator_suites` AND meets the floor — verified by an
//!      independent linear scan.
//!   4. **None correctness**: `None` is returned iff no element in
//!      responder_suites is in initiator_suites AND ≥ floor.
//!   5. **Determinism**: repeated calls on the same inputs return
//!      the same result.
//!
//!   Once-gated anchors verify hand-picked downgrade scenarios.

use arbitrary::{Arbitrary, Unstructured};
use fcp_protocol::{MINIMUM_SUITE, SessionCryptoSuite, negotiate_suite};
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

static NEGOTIATE_ANCHOR: Once = Once::new();

const MAX_LIST_LEN: usize = 16;

#[derive(Arbitrary, Debug)]
struct Input {
    initiator_discs: Vec<u8>,
    responder_discs: Vec<u8>,
}

fn pick_suite(disc: u8) -> SessionCryptoSuite {
    if disc.is_multiple_of(2) {
        SessionCryptoSuite::Suite1
    } else {
        SessionCryptoSuite::Suite2
    }
}

fn rank(s: SessionCryptoSuite) -> u8 {
    match s {
        SessionCryptoSuite::Suite1 => 1,
        SessionCryptoSuite::Suite2 => 2,
    }
}

/// Reference implementation: linear scan over responder_suites for the
/// first entry that's in initiator_suites and ≥ MINIMUM_SUITE rank.
fn reference_negotiate(
    initiator: &[SessionCryptoSuite],
    responder: &[SessionCryptoSuite],
) -> Option<SessionCryptoSuite> {
    let floor = rank(MINIMUM_SUITE);
    responder
        .iter()
        .copied()
        .find(|&s| initiator.contains(&s) && rank(s) >= floor)
}

fuzz_target!(|data: &[u8]| {
    NEGOTIATE_ANCHOR.call_once(assert_negotiate_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };
    if input.initiator_discs.len() > MAX_LIST_LEN || input.responder_discs.len() > MAX_LIST_LEN {
        return;
    }

    let initiator: Vec<SessionCryptoSuite> = input
        .initiator_discs
        .iter()
        .map(|&d| pick_suite(d))
        .collect();
    let responder: Vec<SessionCryptoSuite> = input
        .responder_discs
        .iter()
        .map(|&d| pick_suite(d))
        .collect();

    let result = negotiate_suite(&initiator, &responder);

    // ── PROPERTY 5: determinism ──────────────────────────────────────
    let result2 = negotiate_suite(&initiator, &responder);
    assert_eq!(result, result2, "negotiate_suite is non-deterministic");

    match result {
        Some(s) => {
            // ── PROPERTY 1: membership in BOTH lists ─────────────────
            assert!(
                initiator.contains(&s),
                "result {s:?} not in initiator list {initiator:?}"
            );
            assert!(
                responder.contains(&s),
                "result {s:?} not in responder list {responder:?}"
            );

            // ── PROPERTY 2: floor ────────────────────────────────────
            assert!(
                rank(s) >= rank(MINIMUM_SUITE),
                "result {s:?} below MINIMUM_SUITE floor"
            );

            // ── PROPERTY 3: responder-preference ordering ────────────
            let expected = reference_negotiate(&initiator, &responder);
            assert_eq!(
                Some(s),
                expected,
                "negotiate_suite picked {s:?} but reference scan picked \
                 {expected:?} — responder-preference ordering broken",
            );
        }
        None => {
            // ── PROPERTY 4: None ⇔ no qualifying intersection ─────────
            let expected = reference_negotiate(&initiator, &responder);
            assert_eq!(
                expected, None,
                "negotiate_suite returned None but reference scan found \
                 a valid candidate {expected:?}"
            );
        }
    }
});

/// Once-gated anchors verifying hand-picked downgrade scenarios and the
/// responder-picks-first invariant.
fn assert_negotiate_anchored() {
    use SessionCryptoSuite::{Suite1, Suite2};

    // (a) Empty inputs → None.
    assert_eq!(
        negotiate_suite(&[], &[]),
        None,
        "ANCHOR: empty lists must yield None"
    );
    assert_eq!(
        negotiate_suite(&[Suite1, Suite2], &[]),
        None,
        "ANCHOR: empty responder list must yield None"
    );
    assert_eq!(
        negotiate_suite(&[], &[Suite1, Suite2]),
        None,
        "ANCHOR: empty initiator list must yield None"
    );

    // (b) Single-suite agreement.
    assert_eq!(
        negotiate_suite(&[Suite1], &[Suite1]),
        Some(Suite1),
        "ANCHOR: both Suite1 → Suite1"
    );
    assert_eq!(
        negotiate_suite(&[Suite2], &[Suite2]),
        Some(Suite2),
        "ANCHOR: both Suite2 → Suite2"
    );

    // (c) Responder-preference: responder lists Suite2 first, both
    // support Suite1 and Suite2 → result is Suite2 (responder's first).
    assert_eq!(
        negotiate_suite(&[Suite1, Suite2], &[Suite2, Suite1]),
        Some(Suite2),
        "ANCHOR REGRESSION: responder-preference ordering broken \
         (responder lists Suite2 first; result must be Suite2)"
    );

    // (d) Downgrade defense: initiator orders Suite1-first, responder
    // orders Suite2-first → responder picks Suite2 (NOT Suite1, which
    // a malicious initiator might prefer).
    assert_eq!(
        negotiate_suite(&[Suite1, Suite2], &[Suite2, Suite1]),
        Some(Suite2),
        "ANCHOR REGRESSION: malicious initiator with Suite1-first \
         offer order must not force Suite1 when responder prefers Suite2"
    );

    // (e) Disjoint sets at floor → None (no responder entry in initiator).
    // (Both Suite1/Suite2 are ≥ floor today, so a true disjoint test
    // must use only one variant on each side.)
    assert_eq!(
        negotiate_suite(&[Suite1], &[Suite2]),
        None,
        "ANCHOR: disjoint initiator/responder sets must yield None"
    );
    assert_eq!(
        negotiate_suite(&[Suite2], &[Suite1]),
        None,
        "ANCHOR: disjoint initiator/responder sets must yield None"
    );

    // (f) Duplicates in responder list don't shift selection.
    assert_eq!(
        negotiate_suite(&[Suite1, Suite2], &[Suite2, Suite2, Suite1]),
        Some(Suite2),
        "ANCHOR: duplicates in responder list don't shift selection"
    );

    // (g) MINIMUM_SUITE is Suite1 today; both known suites must clear
    // the floor.
    assert_eq!(
        MINIMUM_SUITE, Suite1,
        "ANCHOR REGRESSION: MINIMUM_SUITE changed"
    );
}
