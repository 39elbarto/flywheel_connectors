//! Golden vector for the responder-picks crypto-suite negotiation
//! decision matrix.
//!
//! `session_handshake_negotiation_fuzz.rs` (commit 89c34bb4f) sweeps
//! the property space with proptest — soundness, responder-picks,
//! initiator-order independence, duplicate tolerance. Properties
//! fail-loudly on any violation but they don't pin the *concrete
//! shape* operators see in production: which suite is chosen for
//! the canonical pref-list combinations, what the floor refuses,
//! and what the empty-overlap signal looks like.
//!
//! This golden freezes those concrete cells so a refactor that
//! silently re-orders the responder-pref tie-break, or that quietly
//! lowers `MINIMUM_SUITE`, surfaces as a per-row diff. The
//! property-fuzz tests would still catch a logical regression; this
//! golden catches a *value* regression that property tests can't —
//! e.g. swapping Suite1 ↔ Suite2 in `suite_rank` (which the property
//! tests don't pin against an external reference because they share
//! `reference_rank` with the implementation).
//!
//! Cells:
//!
//!   - 8 hand-picked (initiator_pref, responder_pref) combinations
//!     covering: empty intersection (both directions), single-suite
//!     overlap, two-suite intersection with different responder
//!     orders, adversarial worst-first initiator, duplicate-stuffed
//!     initiator, single-element symmetric overlap.
//!   - For each cell: the negotiated suite (or None), its numeric
//!     id, and human label.
//!   - The MINIMUM_SUITE floor itself, rendered as a separate row
//!     so a future bump becomes a single visible diff.
//!
//! Update flow:
//!
//!     UPDATE_GOLDENS=1 cargo insta test -p fcp-protocol --test golden_session_handshake_negotiation_matrix
//!     cargo insta review
//!     git diff crates/fcp-protocol/tests/snapshots/

use std::fmt::Write as _;

use fcp_protocol::session::{MINIMUM_SUITE, SessionCryptoSuite, negotiate_suite};

/// Render one negotiation cell as a single golden row.
fn render_cell(
    label: &str,
    initiator: &[SessionCryptoSuite],
    responder: &[SessionCryptoSuite],
) -> String {
    let chosen = negotiate_suite(initiator, responder);
    let init_render: Vec<String> = initiator.iter().map(|s| format!("{}", s.id())).collect();
    let resp_render: Vec<String> = responder.iter().map(|s| format!("{}", s.id())).collect();
    let result_render = match chosen {
        None => "<none>".to_string(),
        Some(s) => format!("id={} label={}", s.id(), s.as_str()),
    };
    format!(
        "{label:<48} | initiator=[{}] responder=[{}] -> {result_render}",
        init_render.join(","),
        resp_render.join(","),
    )
}

fn render_golden() -> String {
    use SessionCryptoSuite::*;

    let mut out = String::new();
    out.push_str(
        "# Golden vector — session_handshake responder-picks decision matrix\n\
         # Extends br-89c34bb4f (CrimsonWolf adversarial-initiator fuzz) with frozen\n\
         # happy-path examples for the canonical pref-list combinations operators\n\
         # see in production. Catches a value regression in suite_rank or in the\n\
         # responder-picks tie-break that the property fuzz cannot reach (the fuzz\n\
         # shares its reference rank with the implementation).\n\
         #\n\
         # Format:\n\
         #   <cell-label>  | initiator=[<suite-ids>] responder=[<suite-ids>] -> <result>\n\
         #\n\
         # MINIMUM_SUITE floor:\n",
    );
    writeln!(
        &mut out,
        "  MINIMUM_SUITE = id={} label={}",
        MINIMUM_SUITE.id(),
        MINIMUM_SUITE.as_str(),
    )
    .expect("string write");
    out.push('\n');
    out.push_str("## Cells (initiator pref × responder pref)\n");

    let cells = [
        // 1. Symmetric: both peers offer Suite1+Suite2, both prefer
        //    Suite2. Responder picks Suite2 (its first pref).
        (
            "both_prefer_suite2",
            vec![Suite2, Suite1],
            vec![Suite2, Suite1],
        ),
        // 2. Symmetric: both peers offer both suites, both prefer
        //    Suite1. Responder picks Suite1 (its first pref, above
        //    floor).
        (
            "both_prefer_suite1",
            vec![Suite1, Suite2],
            vec![Suite1, Suite2],
        ),
        // 3. Initiator prefers Suite1 first; responder prefers
        //    Suite2 first. Result: Suite2 (responder's pick wins).
        //    This is the load-bearing anti-downgrade case.
        (
            "responder_prefers_suite2_initiator_suite1",
            vec![Suite1, Suite2],
            vec![Suite2, Suite1],
        ),
        // 4. Adversarial worst-first initiator: lists Suite1 first
        //    (weakest at-or-above floor); responder still picks
        //    Suite2.
        (
            "adversarial_worst_first_initiator",
            vec![Suite1, Suite2],
            vec![Suite2, Suite1],
        ),
        // 5. Single-suite overlap (only Suite2). Responder must pick
        //    Suite2 even though it also offers Suite1.
        ("single_overlap_suite2", vec![Suite2], vec![Suite1, Suite2]),
        // 6. Single-suite overlap (only Suite1). Responder picks
        //    Suite1 (above floor; the only candidate).
        (
            "single_overlap_suite1_at_floor",
            vec![Suite1, Suite2],
            vec![Suite1],
        ),
        // 7. Empty intersection: initiator only Suite1, responder
        //    only Suite2. Result: <none>.
        ("empty_intersection_disjoint", vec![Suite1], vec![Suite2]),
        // 8. Duplicate-stuffed initiator: many Suite1s flooding the
        //    list. Responder still picks Suite2 (its first pref
        //    that's in initiator).
        (
            "initiator_stuffed_with_suite1_dups",
            vec![Suite1, Suite1, Suite1, Suite1, Suite2, Suite1],
            vec![Suite2, Suite1],
        ),
        // 9. Both lists empty. Result: <none>.
        ("both_empty", vec![], vec![]),
        // 10. Initiator empty, responder non-empty.
        ("initiator_empty", vec![], vec![Suite1, Suite2]),
        // 11. Responder empty, initiator non-empty.
        ("responder_empty", vec![Suite1, Suite2], vec![]),
    ];

    for (label, initiator, responder) in cells {
        out.push_str(&render_cell(label, &initiator, &responder));
        out.push('\n');
    }

    out
}

#[test]
fn golden_session_handshake_negotiation_matrix_canonical_cells() {
    let actual = render_golden();
    insta::assert_snapshot!(
        "session_handshake_negotiation_matrix_canonical_cells",
        actual
    );
}
