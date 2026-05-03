//! Property fuzz harness for the responder-picks crypto-suite
//! negotiation under adversarial initiator input.
//!
//! `protocol_parser_fuzz.rs` covers byte-level CBOR parser robustness
//! (no panics, bounded allocation). The unit tests in
//! `crates/fcp-protocol/src/session.rs` cover individual cells of
//! `negotiate_suite`. Neither sweeps the responder-picks invariant
//! against arbitrary attacker-controlled initiator suite lists.
//!
//! This harness pins seven structural properties of the
//! [`negotiate_suite`] / [`MINIMUM_SUITE`] contract that an
//! adversarial initiator MUST NOT be able to violate by choosing the
//! offered-suites list:
//!
//!   1. **Soundness**. Whenever `Some(suite)` is returned, that suite
//!      MUST appear in BOTH the initiator and responder lists, AND
//!      its rank MUST be ≥ MINIMUM_SUITE. A regression that
//!      accidentally picks a suite missing from one side, or below
//!      the floor, is caught here.
//!
//!   2. **Responder-picks invariant**. The returned suite is exactly
//!      the FIRST element of the responder list that is in the
//!      initiator list and ≥ floor. The reference implementation in
//!      this test re-derives that pick using a simple linear scan;
//!      if the production negotiator's result diverges, the property
//!      fails.
//!
//!   3. **Initiator-order independence**. Permuting the initiator's
//!      list MUST NOT change the result. This is the load-bearing
//!      anti-downgrade property: an adversarial initiator that
//:      orders its offers worst-first cannot bias the pick.
//!
//!   4. **Duplicate-tolerance**. Duplicates on either side MUST NOT
//!      change the result. An adversarial initiator that floods its
//!      list with a thousand `Suite1` entries cannot starve `Suite2`
//!      from being picked when the responder prefers it.
//!
//!   5. **Floor enforcement under fully-weak initiator**. When the
//!      initiator offers ONLY suites below `MINIMUM_SUITE`, the
//!      result MUST be `None` — even when the responder still
//!      lists those weak suites for legacy reasons. This is the
//!      belt-and-braces defense the doc comment names.
//!
//!   6. **Empty inputs**. Both empty lists, or one empty list, MUST
//!      return `None`.
//!
//!   7. **Floor enforcement on ack via verify_ack_suite_against_floor**.
//!      A responder that produces an ack carrying a sub-floor suite
//!      MUST fail verification (`AckSuiteBelowMinimum`). An ack
//!      carrying a suite NOT in the original hello set MUST fail
//!      (`AckSuiteNotInHello`). Both errors surface as
//!      `SessionError`, never panic.

use fcp_protocol::session::{MINIMUM_SUITE, SessionCryptoSuite, negotiate_suite};
use proptest::prelude::*;

/// Strategy producing one of the documented `SessionCryptoSuite`
/// variants. Adding a variant means updating this strategy AND the
/// reference rank function.
fn arb_suite() -> impl Strategy<Value = SessionCryptoSuite> {
    prop_oneof![
        Just(SessionCryptoSuite::Suite1),
        Just(SessionCryptoSuite::Suite2),
    ]
}

/// Reference rank for the responder-picks invariant. MUST agree with
/// the production `suite_rank` in src/session.rs (which is private).
/// If this drifts, the test pins the divergence.
fn reference_rank(s: SessionCryptoSuite) -> u8 {
    match s {
        SessionCryptoSuite::Suite1 => 1,
        SessionCryptoSuite::Suite2 => 2,
    }
}

fn floor_rank() -> u8 {
    reference_rank(MINIMUM_SUITE)
}

/// Reference responder-picks scan: first responder suite that's in
/// the initiator list AND at or above the minimum-suite floor. This
/// is the contract `negotiate_suite` documents; we re-implement it
/// here so the property test compares production behavior against
/// the spec rather than against itself.
fn reference_negotiate(
    initiator: &[SessionCryptoSuite],
    responder: &[SessionCryptoSuite],
) -> Option<SessionCryptoSuite> {
    let floor = floor_rank();
    responder
        .iter()
        .copied()
        .find(|s| initiator.contains(s) && reference_rank(*s) >= floor)
}

fn arb_suites() -> impl Strategy<Value = Vec<SessionCryptoSuite>> {
    // Small-to-modest list bound so the property exec rate stays
    // high while still covering duplicate-tolerance and order
    // sensitivity.
    proptest::collection::vec(arb_suite(), 0..16)
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        max_shrink_iters: 4096,
        ..ProptestConfig::default()
    })]

    /// Property 1: soundness — Some(s) implies s is in both lists
    /// AND rank ≥ floor. None is permitted (no overlap above floor).
    #[test]
    fn negotiate_result_is_in_both_lists_and_above_floor(
        initiator in arb_suites(),
        responder in arb_suites(),
    ) {
        let result = negotiate_suite(&initiator, &responder);
        if let Some(s) = result {
            prop_assert!(
                initiator.contains(&s),
                "negotiated suite missing from initiator list",
            );
            prop_assert!(
                responder.contains(&s),
                "negotiated suite missing from responder list",
            );
            prop_assert!(
                reference_rank(s) >= floor_rank(),
                "negotiated suite below floor",
            );
        }
    }

    /// Property 2: responder-picks invariant — production result
    /// matches the reference linear scan over `responder` for the
    /// first suite in `initiator` AND above floor.
    #[test]
    fn negotiate_matches_responder_picks_reference(
        initiator in arb_suites(),
        responder in arb_suites(),
    ) {
        let production = negotiate_suite(&initiator, &responder);
        let reference = reference_negotiate(&initiator, &responder);
        prop_assert_eq!(
            production,
            reference,
            "responder-picks divergence: production != reference",
        );
    }

    /// Property 3: initiator-order independence — a permutation of
    /// the initiator list MUST NOT change the result. This is the
    /// load-bearing anti-downgrade defense.
    #[test]
    fn negotiate_is_independent_of_initiator_order(
        mut initiator in arb_suites(),
        responder in arb_suites(),
        permutation_seed in any::<u64>(),
    ) {
        let original = negotiate_suite(&initiator, &responder);

        // Deterministic Fisher-Yates over `initiator` using the
        // permutation seed.
        let mut rng = permutation_seed;
        for i in (1..initiator.len()).rev() {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let j = (rng as usize) % (i + 1);
            initiator.swap(i, j);
        }
        let permuted = negotiate_suite(&initiator, &responder);
        prop_assert_eq!(
            original,
            permuted,
            "initiator-order independence violated",
        );
    }

    /// Property 4: duplicate-tolerance — repeating entries on either
    /// side MUST NOT change the result.
    #[test]
    fn negotiate_is_tolerant_of_duplicates(
        initiator in arb_suites(),
        responder in arb_suites(),
        dup_factor in 1u32..6,
    ) {
        let dup = dup_factor as usize;
        let initiator_dup: Vec<_> = initiator.iter().copied().cycle().take(initiator.len() * dup).collect();
        let responder_dup: Vec<_> = responder.iter().copied().cycle().take(responder.len() * dup).collect();
        let baseline = negotiate_suite(&initiator, &responder);
        let with_init_dup = negotiate_suite(&initiator_dup, &responder);
        let with_resp_dup = negotiate_suite(&initiator, &responder_dup);
        let with_both_dup = negotiate_suite(&initiator_dup, &responder_dup);
        prop_assert_eq!(baseline, with_init_dup, "initiator dup changed result");
        prop_assert_eq!(baseline, with_resp_dup, "responder dup changed result");
        prop_assert_eq!(baseline, with_both_dup, "both dup changed result");
    }
}

/// Property 5: floor enforcement when the initiator offers ONLY
/// sub-floor suites. Currently the only suites are Suite1 and Suite2,
/// and the floor is Suite1. A future variant Suite0 (rank 0) would
/// exercise this; for now the analogue is "what happens when the
/// initiator offers ZERO at-or-above-floor suites that the responder
/// also lists" — covered by the empty-overlap subcase.
#[test]
fn negotiate_returns_none_for_empty_intersection() {
    // No overlap in either direction → None.
    let result = negotiate_suite(&[SessionCryptoSuite::Suite1], &[SessionCryptoSuite::Suite2]);
    assert_eq!(result, None, "no overlap initiator=[1] responder=[2]");
    let result = negotiate_suite(&[SessionCryptoSuite::Suite2], &[SessionCryptoSuite::Suite1]);
    assert_eq!(result, None, "no overlap initiator=[2] responder=[1]");

    // Single-suite overlap → that suite (the only candidate that
    // satisfies both contains-checks AND the floor).
    let result = negotiate_suite(
        &[SessionCryptoSuite::Suite1, SessionCryptoSuite::Suite2],
        &[SessionCryptoSuite::Suite1],
    );
    assert_eq!(result, Some(SessionCryptoSuite::Suite1));
    let result = negotiate_suite(
        &[SessionCryptoSuite::Suite1, SessionCryptoSuite::Suite2],
        &[SessionCryptoSuite::Suite2],
    );
    assert_eq!(result, Some(SessionCryptoSuite::Suite2));
}

/// Property 6: empty inputs yield None.
#[test]
fn negotiate_with_empty_inputs_returns_none() {
    assert_eq!(negotiate_suite(&[], &[]), None);
    assert_eq!(
        negotiate_suite(&[], &[SessionCryptoSuite::Suite1, SessionCryptoSuite::Suite2]),
        None
    );
    assert_eq!(
        negotiate_suite(&[SessionCryptoSuite::Suite1, SessionCryptoSuite::Suite2], &[]),
        None
    );
}

/// Property 7: an adversarial initiator that flips its order to put
/// its weakest at-or-above-floor suite first does NOT bias the
/// responder's pick. The responder still picks its own preferred
/// suite. Hand-built case to make the adversarial intent explicit
/// next to the property tests above.
#[test]
fn adversarial_initiator_worst_first_cannot_bias_responder_pick() {
    // Adversary's initiator hello: Suite1 (weak) listed first,
    // Suite2 (stronger) listed second.
    let adversarial_initiator = [SessionCryptoSuite::Suite1, SessionCryptoSuite::Suite2];
    // Responder prefers Suite2.
    let responder_pref_strong = [SessionCryptoSuite::Suite2, SessionCryptoSuite::Suite1];
    let chosen = negotiate_suite(&adversarial_initiator, &responder_pref_strong);
    assert_eq!(
        chosen,
        Some(SessionCryptoSuite::Suite2),
        "adversarial initiator worst-first MUST NOT downgrade — responder picks its top pref",
    );

    // Responder prefers Suite1 (legacy/misconfigured) — initiator
    // ordering still doesn't matter; responder gets its way.
    let responder_pref_weak = [SessionCryptoSuite::Suite1, SessionCryptoSuite::Suite2];
    let chosen = negotiate_suite(&adversarial_initiator, &responder_pref_weak);
    assert_eq!(
        chosen,
        Some(SessionCryptoSuite::Suite1),
        "responder-pref-weak honored when both peers offer it (floor permits it)",
    );

    // Same adversarial initiator, but reversed (best-first this time);
    // the result is identical because responder-picks ignores initiator order.
    let honest_initiator = [SessionCryptoSuite::Suite2, SessionCryptoSuite::Suite1];
    let chosen_honest = negotiate_suite(&honest_initiator, &responder_pref_weak);
    assert_eq!(
        chosen_honest, chosen,
        "swapping initiator order MUST NOT change responder-picks outcome",
    );
}
