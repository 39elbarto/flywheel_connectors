#![no_main]

//! Fuzz target for `fcp_core::enforcement::EnforcementCheckOrder`,
//! `EnforcementCheckId`, and `CheckOutcome` (enforcement.rs:34-175).
//!
//! `EnforcementCheckOrder::canonical_order` defines the NORMATIVE
//! enforcement pipeline ordering all FCP runtimes MUST follow:
//! cheaper structural checks (decode, zone membership) before
//! expensive cryptographic checks (capability/holder), before
//! stateful budget/rate-limit checks. NOT covered as a discrete
//! unit by any existing fuzz target.
//!
//! A regression that:
//!   - reordered the check sequence would split the pipeline across
//!     implementations and expose either DoS amplification (running
//!     expensive checks first) or incorrect denials.
//!   - drifted `index_of` away from `canonical_order` would silently
//!     break `runs_before` and any partial-ordering enforcement.
//!   - made `as_str` collide between variants would fragment audit
//!     logs and break operator dashboards.
//!
//! Properties asserted:
//!
//!   1. **Length & COUNT**: `canonical_order().len() == COUNT == 11`.
//!   2. **Determinism**: repeated calls return identical arrays.
//!   3. **`index_of` ↔ array position**: `index_of(o[i]) == i`.
//!   4. **`runs_before` definition**: `runs_before(a, b) ==
//!      (index_of(a) < index_of(b))`.
//!   5. **Irreflexive**: `runs_before(a, a) == false`.
//!   6. **Antisymmetric**: at most one of
//!      `runs_before(a, b)` and `runs_before(b, a)` holds.
//!   7. **Transitive**: `a<b && b<c → a<c`.
//!   8. **`as_str` distinctness**: all 11 variants have distinct labels.
//!   9. **Display matches `as_str`**.
//!  10. **`CheckOutcome` predicates**: `is_allow` ⇔ Allow,
//!      `is_deny` ⇔ Deny, `Skip` is neither.
//!  11. **Cheap-before-expensive ordering** (NORMATIVE rationale):
//!      CanonicalDecode < CapabilityVerify < Budget;
//!      CapabilityVerify < HolderProof;
//!      CheckpointFreshness < RevocationFreshness;
//!      structural < stateful.
//!
//!   Once-gated anchors verify each property on the canonical order.

use arbitrary::{Arbitrary, Unstructured};
use fcp_core::{CheckOutcome, EnforcementCheckId, EnforcementCheckOrder};
use libfuzzer_sys::fuzz_target;
use std::collections::HashSet;
use std::sync::Once;

static ENFORCEMENT_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    /// Three discriminants used to pick three checks for transitivity.
    a_disc: u8,
    b_disc: u8,
    c_disc: u8,
}

const ALL_CHECKS: [EnforcementCheckId; 11] = [
    EnforcementCheckId::CanonicalDecode,
    EnforcementCheckId::ZoneMembership,
    EnforcementCheckId::CapabilityVerify,
    EnforcementCheckId::HolderProof,
    EnforcementCheckId::CheckpointFreshness,
    EnforcementCheckId::RevocationFreshness,
    EnforcementCheckId::TaintApproval,
    EnforcementCheckId::PolicyCeiling,
    EnforcementCheckId::ConnectorManifest,
    EnforcementCheckId::Budget,
    EnforcementCheckId::RateLimit,
];

fn pick(disc: u8) -> EnforcementCheckId {
    ALL_CHECKS[(disc as usize) % ALL_CHECKS.len()]
}

fuzz_target!(|data: &[u8]| {
    ENFORCEMENT_ANCHOR.call_once(assert_enforcement_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    let a = pick(input.a_disc);
    let b = pick(input.b_disc);
    let c = pick(input.c_disc);

    // ── PROPERTY 4: runs_before definition ──────────────────────────────
    let runs = EnforcementCheckOrder::runs_before(a, b);
    let by_index = EnforcementCheckOrder::index_of(a) < EnforcementCheckOrder::index_of(b);
    assert_eq!(
        runs, by_index,
        "runs_before({a:?}, {b:?}) = {runs}; expected {by_index} (index_of comparison)"
    );

    // ── PROPERTY 5: irreflexive ─────────────────────────────────────────
    assert!(
        !EnforcementCheckOrder::runs_before(a, a),
        "runs_before({a:?}, {a:?}) must be false"
    );

    // ── PROPERTY 6: antisymmetric ───────────────────────────────────────
    let ab = EnforcementCheckOrder::runs_before(a, b);
    let ba = EnforcementCheckOrder::runs_before(b, a);
    assert!(
        !(ab && ba),
        "runs_before is not antisymmetric: a<b={ab} && b<a={ba} both true"
    );

    // ── PROPERTY 7: transitive ──────────────────────────────────────────
    let bc = EnforcementCheckOrder::runs_before(b, c);
    let ac = EnforcementCheckOrder::runs_before(a, c);
    if ab && bc {
        assert!(
            ac,
            "transitivity violation: a<b<c but runs_before(a,c)=false"
        );
    }
});

/// Once-gated anchors: verify the canonical order's NORMATIVE properties.
fn assert_enforcement_anchored() {
    let order = EnforcementCheckOrder::canonical_order();

    // (a) Length & COUNT.
    assert_eq!(
        order.len(),
        EnforcementCheckOrder::COUNT,
        "canonical_order length != COUNT"
    );
    assert_eq!(
        EnforcementCheckOrder::COUNT,
        11,
        "ANCHOR REGRESSION: COUNT changed from documented 11"
    );

    // (b) Determinism.
    let order2 = EnforcementCheckOrder::canonical_order();
    assert_eq!(order, order2, "ANCHOR: canonical_order non-deterministic");

    // (c) index_of ↔ array position bijection.
    for (i, &check) in order.iter().enumerate() {
        assert_eq!(
            EnforcementCheckOrder::index_of(check),
            i,
            "ANCHOR REGRESSION: index_of({check:?}) != position {i}"
        );
    }

    // (d) as_str distinctness.
    let mut labels = HashSet::new();
    for check in order {
        let label = check.as_str();
        assert!(
            labels.insert(label),
            "ANCHOR REGRESSION: duplicate as_str label {label} for {check:?}"
        );
    }
    assert_eq!(
        labels.len(),
        EnforcementCheckOrder::COUNT,
        "ANCHOR: distinct labels count != 11"
    );

    // (e) Display matches as_str.
    for check in order {
        assert_eq!(
            format!("{check}"),
            check.as_str(),
            "ANCHOR REGRESSION: Display differs from as_str for {check:?}"
        );
    }

    // (f) Cheap-before-expensive NORMATIVE ordering.
    use EnforcementCheckId as E;
    assert!(
        EnforcementCheckOrder::runs_before(E::CanonicalDecode, E::CapabilityVerify),
        "ANCHOR REGRESSION: CanonicalDecode must run before CapabilityVerify (cheap-first)"
    );
    assert!(
        EnforcementCheckOrder::runs_before(E::CapabilityVerify, E::HolderProof),
        "ANCHOR: CapabilityVerify must run before HolderProof"
    );
    assert!(
        EnforcementCheckOrder::runs_before(E::CheckpointFreshness, E::RevocationFreshness),
        "ANCHOR: CheckpointFreshness must run before RevocationFreshness"
    );
    assert!(
        EnforcementCheckOrder::runs_before(E::CapabilityVerify, E::Budget),
        "ANCHOR: cryptographic check must precede stateful Budget check"
    );
    assert!(
        EnforcementCheckOrder::runs_before(E::Budget, E::RateLimit),
        "ANCHOR: Budget must run before RateLimit (canonical order)"
    );
    assert!(
        EnforcementCheckOrder::runs_before(E::ZoneMembership, E::CapabilityVerify),
        "ANCHOR: structural ZoneMembership must precede CapabilityVerify"
    );

    // (g) CheckOutcome predicates.
    let allow = CheckOutcome::Allow;
    assert!(allow.is_allow());
    assert!(!allow.is_deny());

    let deny = CheckOutcome::Deny {
        reason_code: "test".into(),
        explanation: "anchor".into(),
    };
    assert!(!deny.is_allow());
    assert!(deny.is_deny());

    let skip = CheckOutcome::Skip {
        reason: "anchor".into(),
    };
    assert!(!skip.is_allow(), "ANCHOR: Skip is not Allow");
    assert!(!skip.is_deny(), "ANCHOR: Skip is not Deny");

    // (h) Specific anchor: each canonical_order index has the expected
    // variant (locks down the array contents byte-for-byte).
    assert_eq!(order[0], E::CanonicalDecode, "ANCHOR: order[0]");
    assert_eq!(order[1], E::ZoneMembership, "ANCHOR: order[1]");
    assert_eq!(order[2], E::CapabilityVerify, "ANCHOR: order[2]");
    assert_eq!(order[3], E::HolderProof, "ANCHOR: order[3]");
    assert_eq!(order[4], E::CheckpointFreshness, "ANCHOR: order[4]");
    assert_eq!(order[5], E::RevocationFreshness, "ANCHOR: order[5]");
    assert_eq!(order[6], E::TaintApproval, "ANCHOR: order[6]");
    assert_eq!(order[7], E::PolicyCeiling, "ANCHOR: order[7]");
    assert_eq!(order[8], E::ConnectorManifest, "ANCHOR: order[8]");
    assert_eq!(order[9], E::Budget, "ANCHOR: order[9]");
    assert_eq!(order[10], E::RateLimit, "ANCHOR: order[10]");
}
