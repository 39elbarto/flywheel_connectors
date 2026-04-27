#![no_main]

//! Fuzz target for `fcp_core::provenance::TaintFlags` algebraic laws +
//! has_critical / reduce_with_proof semantics (provenance.rs:206-276).
//!
//! `TaintFlags::merge` is the OR-semantics taint propagation (NORMATIVE,
//! provenance.rs:157): "if any input is tainted, output is tainted". A
//! regression that broke commutativity, associativity, or idempotence
//! would silently lose taint context as data flows through the system,
//! defeating the audit invariant.
//!
//! `has_critical` (provenance.rs:239-241) gates Dangerous-tier
//! operations on three flags: PublicInput, PotentiallyMalicious,
//! CrossZoneUnapproved. An off-by-one in `is_critical`'s match arm
//! would either let an attacker route public-tainted input through a
//! Dangerous op (false negative) or block legitimate ops (false
//! positive).
//!
//! NOT covered by existing fuzz.
//!
//! Properties asserted:
//!
//!   1. **Commutativity**: a.merge(&b) == b.merge(&a).
//!   2. **Associativity**: (a.merge(&b)).merge(&c) == a.merge(&(b.merge(&c))).
//!   3. **Idempotence**: a.merge(&a) == a.
//!   4. **Identity**: a.merge(&empty) == a.
//!   5. **Superset**: result.contains(f) ⇔ a.contains(f) OR b.contains(f).
//!   6. **has_critical agreement**: has_critical() == iter().any(is_critical).
//!   7. **reduce_with_proof exclusion**: post-reduction set MUST NOT
//!      contain any flag from cleared_flags; and MUST contain every
//!      flag NOT in cleared_flags.
//!
//!   Once-gated regression anchors:
//!     (a) Critical-flag set is exactly {PublicInput, PotentiallyMalicious,
//!         CrossZoneUnapproved} — anchored against is_critical drift.
//!     (b) Empty merge identity: empty.merge(&empty) is empty.

use arbitrary::{Arbitrary, Unstructured};
use fcp_core::{ObjectId, TaintFlag, TaintFlags, TaintReduction};
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

const FLAG_VARIANTS: [TaintFlag; 8] = [
    TaintFlag::PublicInput,
    TaintFlag::UnverifiedLink,
    TaintFlag::UntrustedTransform,
    TaintFlag::WebhookInjected,
    TaintFlag::UserGenerated,
    TaintFlag::PotentiallyMalicious,
    TaintFlag::AiGenerated,
    TaintFlag::CrossZoneUnapproved,
];

static TAINT_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    /// Bitmask over FLAG_VARIANTS for set A.
    mask_a: u8,
    mask_b: u8,
    mask_c: u8,
    /// Cleared flags for the reduce_with_proof MR.
    cleared_mask: u8,
}

fn flags_from_mask(mask: u8) -> TaintFlags {
    let mut flags = TaintFlags::new();
    for (i, flag) in FLAG_VARIANTS.iter().enumerate() {
        if (mask >> i) & 1 == 1 {
            flags.insert(*flag);
        }
    }
    flags
}

fuzz_target!(|data: &[u8]| {
    TAINT_ANCHOR.call_once(assert_taint_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    let a = flags_from_mask(input.mask_a);
    let b = flags_from_mask(input.mask_b);
    let c = flags_from_mask(input.mask_c);

    // ── PROPERTY 1: commutativity ─────────────────────────────────────
    let ab = a.merge(&b);
    let ba = b.merge(&a);
    assert_eq!(
        ab, ba,
        "merge not commutative: a.merge(&b) != b.merge(&a) for masks \
         a=0x{:02x} b=0x{:02x}",
        input.mask_a, input.mask_b
    );

    // ── PROPERTY 2: associativity ────────────────────────────────────
    let left = a.merge(&b).merge(&c);
    let right = a.merge(&b.merge(&c));
    assert_eq!(
        left, right,
        "merge not associative for masks a=0x{:02x} b=0x{:02x} c=0x{:02x}",
        input.mask_a, input.mask_b, input.mask_c
    );

    // ── PROPERTY 3: idempotence ──────────────────────────────────────
    let aa = a.merge(&a);
    assert_eq!(aa, a, "merge not idempotent: a.merge(&a) != a");

    // ── PROPERTY 4: identity ─────────────────────────────────────────
    let empty = TaintFlags::new();
    let a_e = a.merge(&empty);
    assert_eq!(a_e, a, "merge with empty != a");

    // ── PROPERTY 5: superset ─────────────────────────────────────────
    for flag in FLAG_VARIANTS {
        let in_result = ab.contains(flag);
        let in_either = a.contains(flag) || b.contains(flag);
        assert_eq!(
            in_result, in_either,
            "merge superset broken for flag {flag:?}: in_result={in_result}, \
             in_either={in_either}"
        );
    }

    // ── PROPERTY 6: has_critical agreement ───────────────────────────
    let claimed = a.has_critical();
    let computed = a.iter().any(|f| f.is_critical());
    assert_eq!(
        claimed, computed,
        "has_critical ({claimed}) disagrees with iter().any(is_critical) ({computed}) \
         for mask=0x{:02x}",
        input.mask_a
    );

    // ── PROPERTY 7: reduce_with_proof exclusion ──────────────────────
    let mut reduced = a.clone();
    let cleared: Vec<TaintFlag> = FLAG_VARIANTS
        .iter()
        .enumerate()
        .filter(|(i, _)| (input.cleared_mask >> i) & 1 == 1)
        .map(|(_, f)| *f)
        .collect();

    let reduction = TaintReduction {
        timestamp_ms: 0,
        sanitizer_receipt_id: ObjectId::from_bytes([0u8; 32]),
        cleared_flags: cleared.clone(),
        covered_inputs: vec![],
    };
    reduced.reduce_with_proof(&reduction);

    for flag in FLAG_VARIANTS {
        let was_in_a = a.contains(flag);
        let in_cleared = cleared.contains(&flag);
        let in_reduced = reduced.contains(flag);
        let expected = was_in_a && !in_cleared;
        assert_eq!(
            in_reduced, expected,
            "reduce_with_proof contains({flag:?}) = {in_reduced}; expected \
             {expected} (was_in_a={was_in_a}, cleared={in_cleared})"
        );
    }
});

/// Once-gated regression anchors for is_critical's exact membership +
/// empty-merge identity.
fn assert_taint_anchored() {
    // (a) Critical-flag set is exactly the documented three.
    let critical = [
        TaintFlag::PublicInput,
        TaintFlag::PotentiallyMalicious,
        TaintFlag::CrossZoneUnapproved,
    ];
    let non_critical = [
        TaintFlag::UnverifiedLink,
        TaintFlag::UntrustedTransform,
        TaintFlag::WebhookInjected,
        TaintFlag::UserGenerated,
        TaintFlag::AiGenerated,
    ];
    for f in critical {
        assert!(
            f.is_critical(),
            "ANCHOR REGRESSION: {f:?} is documented as critical but \
             is_critical returns false — Dangerous-tier gate would let this \
             flag through, defeating audit"
        );
    }
    for f in non_critical {
        assert!(
            !f.is_critical(),
            "ANCHOR REGRESSION: {f:?} is non-critical but is_critical returns \
             true — Dangerous-tier gate would block legitimate ops bearing \
             this flag, false-positive DoS"
        );
    }

    // (b) Empty merge identity.
    let empty = TaintFlags::new();
    let empty2 = empty.merge(&empty);
    assert_eq!(empty, empty2, "ANCHOR: empty.merge(&empty) != empty");
    assert!(
        !empty.has_critical(),
        "ANCHOR: empty TaintFlags.has_critical() returned true"
    );
    assert!(empty.is_empty(), "ANCHOR: TaintFlags::new() not empty");
}
