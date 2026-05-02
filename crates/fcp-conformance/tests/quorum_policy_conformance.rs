//! `QuorumPolicy` + `required_quorum` Byzantine-quorum conformance.
//!
//! `fcp_core::QuorumPolicy` and the free function
//! `fcp_core::required_quorum` are the BFT primitives that drive
//! AuditHead / ZoneCheckpoint signature verification, zone lease
//! grants, and degraded-mode admission. Zero conformance coverage
//! today even though the quorum thresholds are NORMATIVE and any
//! drift would silently weaken Byzantine resilience.
//!
//! Properties pinned (NORMATIVE):
//!
//! 1. **`required_quorum` thresholds**:
//!    - `Safe → 1` (coordinator only)
//!    - `Risky → f + 1` (fault-tolerant minimum)
//!    - `Dangerous → n - f` (classic BFT)
//!    - `CriticalWrite → n - f` (audit, checkpoint)
//! 2. **`is_quorum_met` is `signatures >= required`** for the
//!    given risk tier.
//! 3. **`is_degraded(available)` returns `available < eligible_nodes`.**
//! 4. **`can_proceed_degraded`** is the conjunction of three
//!    documented gates: `allow_degraded_mode == true`,
//!    `available_nodes >= degraded_mode_min_nodes`, and
//!    `risk_tier == Safe`. ALL three must hold; any one false
//!    rejects.
//! 5. **`required_quorum` is monotone in tier**: Safe ≤ Risky ≤
//!    Dangerous = CriticalWrite. The lattice is what makes the
//!    risk classification meaningful.

use fcp_prelude::{QuorumPolicy, RiskTier, ZoneId, required_quorum};

#[test]
fn safe_tier_requires_one_signature_regardless_of_n_and_f() {
    // Coordinator-only path. Even with n=100, f=33, Safe only
    // needs 1 signature.
    for (n, f) in [(1, 0), (3, 1), (10, 3), (100, 33)] {
        assert_eq!(
            required_quorum(n, f, RiskTier::Safe),
            1,
            "Safe tier MUST require exactly 1 signature; got {} for n={n}, f={f}",
            required_quorum(n, f, RiskTier::Safe)
        );
    }
}

#[test]
fn risky_tier_requires_f_plus_one_signatures() {
    for (n, f) in [(3, 1), (5, 2), (10, 3), (100, 33)] {
        assert_eq!(
            required_quorum(n, f, RiskTier::Risky),
            f + 1,
            "Risky tier MUST require f+1 signatures (fault-tolerant minimum); got {} for n={n}, f={f}",
            required_quorum(n, f, RiskTier::Risky)
        );
    }
}

#[test]
fn dangerous_tier_requires_n_minus_f_signatures() {
    for (n, f) in [(3, 1), (5, 2), (10, 3), (100, 33)] {
        assert_eq!(
            required_quorum(n, f, RiskTier::Dangerous),
            n - f,
            "Dangerous tier MUST require n-f signatures (classic BFT); got {} for n={n}, f={f}",
            required_quorum(n, f, RiskTier::Dangerous)
        );
    }
}

#[test]
fn critical_write_tier_requires_n_minus_f_signatures() {
    // CriticalWrite is the audit-head + zone-checkpoint tier;
    // shares the same threshold as Dangerous.
    for (n, f) in [(3, 1), (5, 2), (10, 3), (100, 33)] {
        assert_eq!(
            required_quorum(n, f, RiskTier::CriticalWrite),
            n - f,
            "CriticalWrite tier MUST share the n-f threshold with Dangerous; got {} for n={n}, f={f}",
            required_quorum(n, f, RiskTier::CriticalWrite)
        );
    }
}

#[test]
fn dangerous_and_critical_write_thresholds_are_equal() {
    // The documented invariant — both tiers use n-f. Any drift
    // would silently weaken one of them.
    for (n, f) in [(3, 1), (5, 2), (10, 3), (100, 33)] {
        assert_eq!(
            required_quorum(n, f, RiskTier::Dangerous),
            required_quorum(n, f, RiskTier::CriticalWrite),
            "Dangerous and CriticalWrite MUST yield identical thresholds (both n-f); drift \
             would silently weaken one of them"
        );
    }
}

#[test]
fn required_quorum_is_monotone_across_tiers() {
    // Safe(1) <= Risky(f+1) <= Dangerous(n-f) = CriticalWrite(n-f).
    // For non-trivial n, the chain MUST be strictly ordered;
    // for n=2, f=0 we have Safe=1, Risky=1, Dangerous=2 — Safe == Risky there.
    for (n, f) in [(3, 1), (5, 2), (10, 3), (100, 33)] {
        let safe = required_quorum(n, f, RiskTier::Safe);
        let risky = required_quorum(n, f, RiskTier::Risky);
        let dangerous = required_quorum(n, f, RiskTier::Dangerous);
        assert!(
            safe <= risky,
            "Safe ({safe}) MUST NOT exceed Risky ({risky}) for n={n}, f={f}"
        );
        assert!(
            risky <= dangerous,
            "Risky ({risky}) MUST NOT exceed Dangerous ({dangerous}) for n={n}, f={f}"
        );
    }
}

#[test]
fn is_quorum_met_returns_true_when_signatures_meet_threshold() {
    let policy = QuorumPolicy::new(ZoneId::work(), 5, 1);
    let dangerous_required = policy.required_signatures(RiskTier::Dangerous);
    assert_eq!(dangerous_required, 4); // n-f = 5-1

    assert!(
        policy.is_quorum_met(4, RiskTier::Dangerous),
        "exactly threshold (4) MUST satisfy quorum"
    );
    assert!(
        policy.is_quorum_met(5, RiskTier::Dangerous),
        "above threshold (5) MUST satisfy quorum"
    );
}

#[test]
fn is_quorum_met_returns_false_when_signatures_below_threshold() {
    let policy = QuorumPolicy::new(ZoneId::work(), 5, 1);
    assert!(
        !policy.is_quorum_met(3, RiskTier::Dangerous),
        "3 signatures (below n-f=4 threshold) MUST NOT satisfy Dangerous quorum"
    );
}

#[test]
fn is_degraded_returns_true_when_available_below_eligible() {
    let policy = QuorumPolicy::new(ZoneId::work(), 5, 1);
    assert!(
        policy.is_degraded(3),
        "available (3) < eligible (5) MUST report degraded"
    );
    assert!(
        !policy.is_degraded(5),
        "available == eligible MUST NOT report degraded"
    );
    assert!(
        !policy.is_degraded(7),
        "available > eligible (over-provisioned, unusual but legal) MUST NOT report degraded"
    );
}

#[test]
fn can_proceed_degraded_rejects_when_degraded_mode_disabled() {
    let policy = QuorumPolicy::new(ZoneId::work(), 5, 1);
    // Default is allow_degraded_mode = false.
    assert!(
        !policy.can_proceed_degraded(3, RiskTier::Safe),
        "policy without with_degraded_mode() MUST reject can_proceed_degraded"
    );
}

#[test]
fn can_proceed_degraded_rejects_when_available_below_min() {
    let policy = QuorumPolicy::new(ZoneId::work(), 5, 1).with_degraded_mode(3);
    assert!(
        !policy.can_proceed_degraded(2, RiskTier::Safe),
        "available (2) < degraded_mode_min_nodes (3) MUST reject can_proceed_degraded"
    );
}

#[test]
fn can_proceed_degraded_rejects_non_safe_risk_tiers() {
    // Documented restriction: only Safe operations are allowed in
    // degraded mode. Risky/Dangerous/CriticalWrite all reject.
    let policy = QuorumPolicy::new(ZoneId::work(), 5, 1).with_degraded_mode(2);
    for tier in [
        RiskTier::Risky,
        RiskTier::Dangerous,
        RiskTier::CriticalWrite,
    ] {
        assert!(
            !policy.can_proceed_degraded(3, tier),
            "{tier:?} MUST be rejected in degraded mode — only Safe operations are \
             permitted"
        );
    }
}

#[test]
fn can_proceed_degraded_accepts_safe_when_all_gates_pass() {
    let policy = QuorumPolicy::new(ZoneId::work(), 5, 1).with_degraded_mode(2);
    assert!(
        policy.can_proceed_degraded(3, RiskTier::Safe),
        "all three gates pass (allow_degraded_mode=true, available>=min, tier==Safe) — MUST accept"
    );
}

#[test]
fn quorum_policy_required_signatures_matches_required_quorum_free_fn() {
    // The QuorumPolicy method MUST delegate to the free function;
    // any divergence would fork the threshold semantics between
    // the policy-bound and policy-less paths.
    let policy = QuorumPolicy::new(ZoneId::work(), 7, 2);
    for tier in [
        RiskTier::Safe,
        RiskTier::Risky,
        RiskTier::Dangerous,
        RiskTier::CriticalWrite,
    ] {
        assert_eq!(
            policy.required_signatures(tier),
            required_quorum(policy.eligible_nodes, policy.max_faults, tier),
            "QuorumPolicy::required_signatures MUST match the free required_quorum function for {tier:?}"
        );
    }
}

#[test]
fn risk_tier_as_str_yields_human_readable_label() {
    // Stable label strings — admin tooling depends on these.
    assert_eq!(RiskTier::Safe.as_str(), "safe");
    assert_eq!(RiskTier::Risky.as_str(), "risky");
    assert_eq!(RiskTier::Dangerous.as_str(), "dangerous");
    assert_eq!(RiskTier::CriticalWrite.as_str(), "critical_write");
}

#[test]
fn quorum_policy_minimal_n_eq_1_f_eq_0_works_for_safe_tier() {
    // Edge case: a single-node zone (n=1, f=0). Safe tier still
    // needs 1 signature, which is met by the lone node.
    let policy = QuorumPolicy::new(ZoneId::work(), 1, 0);
    assert_eq!(policy.required_signatures(RiskTier::Safe), 1);
    assert!(policy.is_quorum_met(1, RiskTier::Safe));
    assert!(!policy.is_quorum_met(0, RiskTier::Safe));
}
