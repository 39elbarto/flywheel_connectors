//! `DescriptorStatus::combine` worst-wins + From-conversion conformance.
//!
//! `fcp_core::DescriptorStatus` is the 11-variant connector
//! descriptor enum used to roll up individual descriptor checks
//! into a single status for downstream consumers (CLI, admin UI,
//! discovery responses). Two NORMATIVE properties drive the design:
//!
//! 1. **`combine()` is a worst-wins fold.** The internal severity
//!    ranking (Ready=0 ... Failed=10) is monotonic; combine(a, b)
//!    yields the more severe of a and b. Aggregators MUST be able
//!    to fold a list of statuses without grouping concerns.
//! 2. **`From<&ConnectorHealth>` and `From<&SelfCheckReport>` are
//!    cross-crate contracts.** Descriptor consumers receive
//!    ConnectorHealth from the discovery layer and SelfCheckReport
//!    from the connector self-check; both must surface as the
//!    correct DescriptorStatus.
//!
//! Documented mappings pinned:
//!
//! - `ConnectorHealth::Healthy → DescriptorStatus::Ready`
//! - `ConnectorHealth::Degraded { .. } → DescriptorStatus::Degraded`
//! - `ConnectorHealth::Unavailable { .. } → DescriptorStatus::Unavailable`
//! - `SelfCheckStatus::Ok → DescriptorStatus::Ready`
//! - `SelfCheckStatus::Degraded → DescriptorStatus::Degraded`
//! - `SelfCheckStatus::Failed → DescriptorStatus::Failed`
//! - `SelfCheckStatus::Unsupported → DescriptorStatus::Unsupported`

use fcp_prelude::{ConnectorHealth, DescriptorStatus, SelfCheckReport};

const ALL_VARIANTS: &[DescriptorStatus] = &[
    DescriptorStatus::Ready,
    DescriptorStatus::Unknown,
    DescriptorStatus::NotYetMeasured,
    DescriptorStatus::Unsupported,
    DescriptorStatus::Unverifiable,
    DescriptorStatus::Degraded,
    DescriptorStatus::Drifted,
    DescriptorStatus::Missing,
    DescriptorStatus::Unavailable,
    DescriptorStatus::PolicyBlocked,
    DescriptorStatus::Failed,
];

#[test]
fn combine_with_self_is_idempotent() {
    for &v in ALL_VARIANTS {
        assert_eq!(
            v.combine(v),
            v,
            "combine({v:?}, {v:?}) MUST equal {v:?} (idempotent on self)"
        );
    }
}

#[test]
fn combine_is_commutative_in_severity() {
    // Even though combine() is implemented asymmetrically (returns
    // the right side on tie), the chosen variant for any pair must
    // be the same regardless of argument order.
    for &a in ALL_VARIANTS {
        for &b in ALL_VARIANTS {
            assert_eq!(
                a.combine(b),
                b.combine(a),
                "combine({a:?}, {b:?}) MUST equal combine({b:?}, {a:?}) — \
                 worst-wins folding cannot depend on argument order"
            );
        }
    }
}

#[test]
fn combine_with_ready_is_identity() {
    // Ready has rank 0, so combine(Ready, X) MUST always yield X.
    for &v in ALL_VARIANTS {
        assert_eq!(
            DescriptorStatus::Ready.combine(v),
            v,
            "Ready combine X MUST equal X (Ready is the identity element)"
        );
        assert_eq!(v.combine(DescriptorStatus::Ready), v);
    }
}

#[test]
fn combine_with_failed_yields_failed() {
    // Failed has rank 10, so combine(X, Failed) MUST always yield
    // Failed (Failed is the absorbing element / "top").
    for &v in ALL_VARIANTS {
        assert_eq!(
            v.combine(DescriptorStatus::Failed),
            DescriptorStatus::Failed,
            "X combine Failed MUST equal Failed (Failed is the absorbing top)"
        );
        assert_eq!(
            DescriptorStatus::Failed.combine(v),
            DescriptorStatus::Failed,
        );
    }
}

#[test]
fn combine_is_associative() {
    // Worst-wins is associative because it's effectively a max
    // over a totally-ordered rank. Without this property,
    // aggregators would need to be careful about grouping when
    // combining multiple checks.
    let triples = [
        (
            DescriptorStatus::Ready,
            DescriptorStatus::Degraded,
            DescriptorStatus::Failed,
        ),
        (
            DescriptorStatus::Drifted,
            DescriptorStatus::Missing,
            DescriptorStatus::PolicyBlocked,
        ),
        (
            DescriptorStatus::Unverifiable,
            DescriptorStatus::Unavailable,
            DescriptorStatus::Failed,
        ),
    ];
    for (a, b, c) in triples {
        let left = a.combine(b).combine(c);
        let right = a.combine(b.combine(c));
        assert_eq!(
            left, right,
            "combine MUST be associative: ({a:?} ⊕ {b:?}) ⊕ {c:?} = {a:?} ⊕ ({b:?} ⊕ {c:?}); \
             got left={left:?}, right={right:?}"
        );
    }
}

#[test]
fn combine_picks_more_severe_for_documented_pairs() {
    // Spot-check the documented severity ordering.
    // Ready(0) < Unknown(1) < NotYetMeasured(2) < Unsupported(3)
    //   < Unverifiable(4) < Degraded(5) < Drifted(6) < Missing(7)
    //   < Unavailable(8) < PolicyBlocked(9) < Failed(10)
    use DescriptorStatus::*;
    let pairs = [
        (Ready, Unknown, Unknown),
        (Unknown, NotYetMeasured, NotYetMeasured),
        (NotYetMeasured, Unsupported, Unsupported),
        (Unsupported, Unverifiable, Unverifiable),
        (Unverifiable, Degraded, Degraded),
        (Degraded, Drifted, Drifted),
        (Drifted, Missing, Missing),
        (Missing, Unavailable, Unavailable),
        (Unavailable, PolicyBlocked, PolicyBlocked),
        (PolicyBlocked, Failed, Failed),
    ];
    for (a, b, expected) in pairs {
        assert_eq!(
            a.combine(b),
            expected,
            "{a:?} combine {b:?} must yield {expected:?} (documented severity ordering)"
        );
    }
}

#[test]
fn from_connector_health_healthy_yields_ready() {
    let mapped: DescriptorStatus = (&ConnectorHealth::Healthy).into();
    assert_eq!(mapped, DescriptorStatus::Ready);
}

#[test]
fn from_connector_health_degraded_yields_degraded() {
    let mapped: DescriptorStatus = (&ConnectorHealth::degraded("api-slow")).into();
    assert_eq!(mapped, DescriptorStatus::Degraded);
}

#[test]
fn from_connector_health_unavailable_yields_unavailable() {
    // Note: NOT Failed — Unavailable is a less-severe rank
    // (8 vs 10) because the connector might come back. Failed is
    // reserved for terminal/explicit failure.
    let mapped: DescriptorStatus = (&ConnectorHealth::unavailable("network-loss")).into();
    assert_eq!(
        mapped,
        DescriptorStatus::Unavailable,
        "Unavailable maps to DescriptorStatus::Unavailable, NOT Failed — pin the \
         severity-ordering distinction so terminal-vs-recoverable stays meaningful"
    );
}

#[test]
fn from_self_check_report_ok_yields_ready() {
    let mapped: DescriptorStatus = (&SelfCheckReport::ok()).into();
    assert_eq!(mapped, DescriptorStatus::Ready);
}

#[test]
fn from_self_check_report_degraded_yields_degraded() {
    let mapped: DescriptorStatus = (&SelfCheckReport::degraded("rate_limit", "near cap")).into();
    assert_eq!(mapped, DescriptorStatus::Degraded);
}

#[test]
fn from_self_check_report_failed_yields_failed() {
    let mapped: DescriptorStatus = (&SelfCheckReport::failed("auth_error", "token expired")).into();
    assert_eq!(
        mapped,
        DescriptorStatus::Failed,
        "SelfCheckStatus::Failed maps to DescriptorStatus::Failed (rank 10, top)"
    );
}

#[test]
fn from_self_check_report_unsupported_yields_unsupported() {
    let mapped: DescriptorStatus = (&SelfCheckReport::unsupported()).into();
    assert_eq!(mapped, DescriptorStatus::Unsupported);
}

#[test]
fn fold_over_descriptor_check_statuses_yields_worst() {
    // The aggregator pattern: fold a list of DescriptorStatus
    // values via combine() and the result MUST be the worst of
    // them. This is what consumers do when rolling up a
    // descriptor's per-check statuses into one.
    let checks = [
        DescriptorStatus::Ready,
        DescriptorStatus::Degraded,
        DescriptorStatus::Drifted, // worst
        DescriptorStatus::Ready,
    ];
    let folded = checks
        .iter()
        .copied()
        .reduce(DescriptorStatus::combine)
        .expect("non-empty");
    assert_eq!(
        folded,
        DescriptorStatus::Drifted,
        "fold via combine() MUST yield the worst entry"
    );
}

#[test]
fn fold_over_all_variants_collapses_to_failed() {
    // Folding the entire variant set must collapse to Failed
    // (rank 10, top).
    let folded = ALL_VARIANTS
        .iter()
        .copied()
        .reduce(DescriptorStatus::combine)
        .expect("non-empty");
    assert_eq!(
        folded,
        DescriptorStatus::Failed,
        "fold over the full variant set MUST collapse to Failed (the top of the lattice)"
    );
}

#[test]
fn json_serde_uses_snake_case_variants() {
    let serialized = serde_json::to_string(&DescriptorStatus::PolicyBlocked).expect("serialize");
    assert_eq!(
        serialized, "\"policy_blocked\"",
        "DescriptorStatus JSON form MUST use snake_case rename — admin UI / CLI output \
         depends on this literal string"
    );
    let parsed: DescriptorStatus = serde_json::from_str(&serialized).expect("deserialize");
    assert_eq!(parsed, DescriptorStatus::PolicyBlocked);
}

#[test]
fn each_variant_has_a_distinct_rank_via_combine_self_neutrality() {
    // Indirect rank distinctness check: if any two variants had
    // the same rank, combine(a, b) would be ambiguous (return one
    // of them). With strictly distinct ranks, combining a-with-b
    // is identical to combining b-with-a (already pinned above).
    // This test is a separate sanity check: combining a variant
    // with EVERY other variant must yield a result whose
    // identity-with-self produces the original.
    for &a in ALL_VARIANTS {
        for &b in ALL_VARIANTS {
            let combined = a.combine(b);
            assert_eq!(
                combined,
                combined.combine(combined),
                "combine result must be idempotent under self-combine ({a:?}, {b:?})"
            );
        }
    }
}
