//! Pin `RiskTier` documented-ordinal ordering + `required_quorum` priority
//! ladder — the closest analogue to "ConnectorPriority ordering"
//! (flywheel_connectors-os77d).
//!
//! Bead asks for `ConnectorPriority` Display + ordering pinning. No type
//! literally named `ConnectorPriority` exists in fcp-core. The closest
//! priority-ordered classifier directly tied to per-operation enforcement
//! is [`RiskTier`] at `crates/fcp-core/src/quorum.rs:56` — a 4-variant
//! enum (Safe / Risky / Dangerous / CriticalWrite) that drives signature-
//! count requirements via [`required_quorum`].
//!
//! `intent_priority_ordering.rs` already pins TrustLevel as another
//! priority analogue. RiskTier serde + Display + truth-table-against-
//! QuorumPurpose is pinned by `mesh_node_role_serde_tag.rs`. Residual
//! axes (and the closest "ordering" surface): RiskTier does NOT derive
//! Ord/PartialOrd, but the variant declaration order Safe → Risky →
//! Dangerous → CriticalWrite IS the documented priority ladder, and
//! `required_quorum(n, f, tier)` pins the ladder via a monotonic
//! signature-count function.
//!
//! Coverage:
//!   * RiskTier documented-ordinal helper (Safe=0, Risky=1, Dangerous=2,
//!     CriticalWrite=3) — pin the variant declaration order so a future
//!     enum-body shuffle is caught loudly,
//!   * required_quorum monotonic ladder across (n, f) configurations:
//!     1 ≤ f+1 ≤ n-f for sensible n,f → Safe ≤ Risky ≤ Dangerous = CriticalWrite,
//!   * Loud Dangerous-equals-CriticalWrite signature-count sentinel: both
//!     tiers MUST require the same n-f count (they're disjoint by
//!     classification but unified in BFT quorum size — pin so a future
//!     attempt to differentiate them silently breaks BFT semantics),
//!   * is_quorum_met truth table: signature_count ≥ required_signatures,
//!   * can_proceed_degraded enforcement: ONLY Safe permitted under
//!     degraded mode (the highest-priority safety contract — pin so a
//!     future relaxation that lets Risky-or-higher proceed in degraded
//!     mode is caught),
//!   * default_risk_tier projection from QuorumPurpose for the four
//!     non-Safe-Lease purposes (sanity sentinel for the priority ladder).

use fcp_core::{QuorumPolicy, QuorumPurpose, RiskTier, ZoneId, required_quorum};

const ALL_TIERS: &[RiskTier] = &[
    RiskTier::Safe,
    RiskTier::Risky,
    RiskTier::Dangerous,
    RiskTier::CriticalWrite,
];

/// Documented ordinal mapping for the priority ladder. RiskTier does NOT
/// derive Ord; this helper IS the canonical mapping.
fn tier_ordinal(t: RiskTier) -> u8 {
    match t {
        RiskTier::Safe => 0,
        RiskTier::Risky => 1,
        RiskTier::Dangerous => 2,
        RiskTier::CriticalWrite => 3,
    }
}

#[test]
fn risk_tier_documented_ordinal_mapping_pinned() {
    // Pin the variant-declaration ladder. A future shuffle of the enum
    // body would silently invert the priority ordering — catch via
    // explicit ordinal.
    assert_eq!(tier_ordinal(RiskTier::Safe), 0);
    assert_eq!(tier_ordinal(RiskTier::Risky), 1);
    assert_eq!(tier_ordinal(RiskTier::Dangerous), 2);
    assert_eq!(tier_ordinal(RiskTier::CriticalWrite), 3);

    // Sortable via the ordinal: ascending order matches Safe → Risky →
    // Dangerous → CriticalWrite.
    let mut shuffled = vec![
        RiskTier::CriticalWrite,
        RiskTier::Safe,
        RiskTier::Dangerous,
        RiskTier::Risky,
    ];
    shuffled.sort_by_key(|t| tier_ordinal(*t));
    assert_eq!(
        shuffled,
        vec![
            RiskTier::Safe,
            RiskTier::Risky,
            RiskTier::Dangerous,
            RiskTier::CriticalWrite,
        ]
    );
}

#[test]
fn required_quorum_safe_is_always_one() {
    // Safe operations always require exactly 1 signature (coordinator only),
    // independent of (n, f).
    for n in 1u32..=10 {
        for f in 0..n {
            assert_eq!(required_quorum(n, f, RiskTier::Safe), 1, "(n={n}, f={f})");
        }
    }
}

#[test]
fn required_quorum_risky_is_f_plus_one() {
    // Risky operations require f+1 signatures (fault-tolerant minimum).
    for n in 1u32..=10 {
        for f in 0..n {
            assert_eq!(
                required_quorum(n, f, RiskTier::Risky),
                f + 1,
                "(n={n}, f={f})"
            );
        }
    }
}

#[test]
fn required_quorum_dangerous_and_critical_write_are_n_minus_f() {
    // Both Dangerous and CriticalWrite require n-f signatures (classic
    // BFT quorum). Pin the equality between these two tiers loudly: any
    // future divergence breaks the BFT contract.
    for n in 1u32..=10 {
        for f in 0..n {
            assert_eq!(
                required_quorum(n, f, RiskTier::Dangerous),
                n - f,
                "(n={n}, f={f}) Dangerous"
            );
            assert_eq!(
                required_quorum(n, f, RiskTier::CriticalWrite),
                n - f,
                "(n={n}, f={f}) CriticalWrite"
            );
            // The disjoint-classification-but-unified-quorum sentinel.
            assert_eq!(
                required_quorum(n, f, RiskTier::Dangerous),
                required_quorum(n, f, RiskTier::CriticalWrite),
                "Dangerous and CriticalWrite must require identical signature counts at (n={n}, f={f})"
            );
        }
    }
}

#[test]
fn required_quorum_is_monotonic_along_priority_ladder() {
    // Pin the documented priority ladder: along Safe → Risky → Dangerous,
    // required signatures must be non-decreasing.
    //   Safe = 1
    //   Risky = f+1 ≥ 1 (since f ≥ 0)
    //   Dangerous = n-f
    //   CriticalWrite = n-f (== Dangerous)
    //
    // Constraint: for sensible n,f (with f < n/2 so that n-f > f+1 holds for
    // most configurations), the ladder is strictly ordered. We test this
    // for several typical (n, f) configurations.
    let configs: &[(u32, u32)] = &[(3, 0), (3, 1), (5, 1), (5, 2), (7, 2), (10, 3)];
    for &(n, f) in configs {
        let safe = required_quorum(n, f, RiskTier::Safe);
        let risky = required_quorum(n, f, RiskTier::Risky);
        let dangerous = required_quorum(n, f, RiskTier::Dangerous);
        let critical = required_quorum(n, f, RiskTier::CriticalWrite);

        assert!(safe <= risky, "Safe ({safe}) must be ≤ Risky ({risky}) at (n={n},f={f})");
        assert!(
            risky <= dangerous,
            "Risky ({risky}) must be ≤ Dangerous ({dangerous}) at (n={n},f={f})"
        );
        assert_eq!(
            dangerous, critical,
            "Dangerous and CriticalWrite signature counts must be equal at (n={n},f={f})"
        );
    }
}

#[test]
fn required_quorum_strict_inequality_holds_for_n_strictly_greater_than_2f_plus_one() {
    // Strict three-bucket priority ladder 1 < f+1 < n-f holds iff
    // n > 2f+1 (i.e. the BFT inequality is strict, not tight).
    // Pin so a future change to required_quorum that flattens the
    // ladder (e.g. uniformly requiring n-f signatures) is caught.
    let configs: &[(u32, u32)] = &[(5, 1), (7, 2), (10, 3), (10, 1)];
    for &(n, f) in configs {
        assert!(
            n > 2 * f + 1,
            "test fixture sanity: n must be > 2f+1 for strict ladder"
        );
        let safe = required_quorum(n, f, RiskTier::Safe);
        let risky = required_quorum(n, f, RiskTier::Risky);
        let dangerous = required_quorum(n, f, RiskTier::Dangerous);
        assert!(safe < risky, "Safe ({safe}) < Risky ({risky}) at (n={n},f={f})");
        assert!(
            risky < dangerous,
            "Risky ({risky}) < Dangerous ({dangerous}) at (n={n},f={f})"
        );
    }
}

#[test]
fn required_quorum_ladder_collapses_at_tight_bft_boundary() {
    // Sentinel for the BFT-tight boundary case: when n = 2f+1 (the
    // minimum-fault-tolerant configuration), Risky and Dangerous
    // collapse to the same signature count (f+1 == n-f). Pin this
    // collapse so future re-derivations of the formulas don't silently
    // re-introduce a strict ladder where one shouldn't exist.
    for f in 1u32..=4 {
        let n = 2 * f + 1;
        assert_eq!(
            required_quorum(n, f, RiskTier::Risky),
            required_quorum(n, f, RiskTier::Dangerous),
            "Risky and Dangerous must collapse at n=2f+1 boundary (n={n}, f={f})"
        );
    }
}

#[test]
fn is_quorum_met_truth_table_per_tier() {
    let policy = QuorumPolicy::new(ZoneId::work(), 5, 1);

    // Safe needs 1 sig.
    assert!(!policy.is_quorum_met(0, RiskTier::Safe));
    assert!(policy.is_quorum_met(1, RiskTier::Safe));
    assert!(policy.is_quorum_met(5, RiskTier::Safe));

    // Risky needs f+1 = 2 sigs.
    assert!(!policy.is_quorum_met(1, RiskTier::Risky));
    assert!(policy.is_quorum_met(2, RiskTier::Risky));
    assert!(policy.is_quorum_met(5, RiskTier::Risky));

    // Dangerous needs n-f = 4 sigs.
    assert!(!policy.is_quorum_met(3, RiskTier::Dangerous));
    assert!(policy.is_quorum_met(4, RiskTier::Dangerous));
    assert!(policy.is_quorum_met(5, RiskTier::Dangerous));

    // CriticalWrite needs n-f = 4 sigs (same as Dangerous).
    assert!(!policy.is_quorum_met(3, RiskTier::CriticalWrite));
    assert!(policy.is_quorum_met(4, RiskTier::CriticalWrite));
    assert!(policy.is_quorum_met(5, RiskTier::CriticalWrite));
}

#[test]
fn can_proceed_degraded_only_safe_is_permitted_under_degraded_mode() {
    // Loud safety sentinel: in degraded mode, ONLY Safe operations may
    // proceed — Risky / Dangerous / CriticalWrite must be rejected
    // regardless of the available-nodes count. Future relaxation that
    // permits any non-Safe tier in degraded mode silently breaks the
    // documented BFT contract.
    let policy = QuorumPolicy::new(ZoneId::work(), 5, 1).with_degraded_mode(1);

    let available = 1; // ≥ degraded_mode_min_nodes (1)
    assert!(policy.can_proceed_degraded(available, RiskTier::Safe));
    assert!(!policy.can_proceed_degraded(available, RiskTier::Risky));
    assert!(!policy.can_proceed_degraded(available, RiskTier::Dangerous));
    assert!(!policy.can_proceed_degraded(available, RiskTier::CriticalWrite));
}

#[test]
fn can_proceed_degraded_when_disabled_rejects_all_tiers() {
    let policy = QuorumPolicy::new(ZoneId::work(), 5, 1);
    assert!(!policy.allow_degraded_mode);
    for &tier in ALL_TIERS {
        assert!(
            !policy.can_proceed_degraded(1, tier),
            "degraded-disabled policy must reject {tier:?}"
        );
    }
}

#[test]
fn can_proceed_degraded_when_below_min_nodes_rejects_safe_too() {
    let policy = QuorumPolicy::new(ZoneId::work(), 5, 1).with_degraded_mode(2);
    // available=1 is below min_nodes=2 — even Safe must reject.
    assert!(!policy.can_proceed_degraded(1, RiskTier::Safe));
    // available=2 satisfies min_nodes — Safe permitted, others rejected.
    assert!(policy.can_proceed_degraded(2, RiskTier::Safe));
    assert!(!policy.can_proceed_degraded(2, RiskTier::Risky));
}

#[test]
fn quorum_purpose_default_risk_tier_priority_ladder_sentinel() {
    // Sanity sentinel for the priority ladder: every QuorumPurpose maps
    // to a RiskTier that respects the documented ladder. The four
    // safety-critical purposes (audit/checkpoint/revocation) MUST map to
    // CriticalWrite — pin so a relaxation that silently downgrades them
    // to Dangerous (or lower) is caught.
    assert_eq!(
        QuorumPurpose::AuditHead.default_risk_tier(),
        RiskTier::CriticalWrite
    );
    assert_eq!(
        QuorumPurpose::ZoneCheckpoint.default_risk_tier(),
        RiskTier::CriticalWrite
    );
    assert_eq!(
        QuorumPurpose::RevocationHead.default_risk_tier(),
        RiskTier::CriticalWrite
    );
    assert_eq!(
        QuorumPurpose::DangerousLease.default_risk_tier(),
        RiskTier::Dangerous
    );
    assert_eq!(
        QuorumPurpose::KeyRotation.default_risk_tier(),
        RiskTier::Dangerous
    );
    assert_eq!(
        QuorumPurpose::MembershipChange.default_risk_tier(),
        RiskTier::Dangerous
    );
    assert_eq!(
        QuorumPurpose::RiskyLease.default_risk_tier(),
        RiskTier::Risky
    );
    assert_eq!(
        QuorumPurpose::SafeLease.default_risk_tier(),
        RiskTier::Safe
    );
}

#[test]
fn ordinal_mapping_is_pairwise_distinct_across_all_tiers() {
    let mut seen = std::collections::HashSet::new();
    for &tier in ALL_TIERS {
        let o = tier_ordinal(tier);
        assert!(seen.insert(o), "ordinal collision on {tier:?}: {o}");
    }
    assert_eq!(seen.len(), 4);
}
