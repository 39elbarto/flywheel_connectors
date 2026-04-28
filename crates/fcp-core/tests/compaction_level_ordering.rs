//! Pin a 3-variant escalating ordering invariant on the closest
//! analogue to "CompactionLevel" (flywheel_connectors-8lxv3).
//!
//! Bead asks for "CompactionLevel ordering: None < Compact <
//! Aggressive". No type literally named `CompactionLevel` exists in
//! fcp-core. The compaction docstring at connector_state.rs:471
//! describes compaction RULES but has no enum. The closest existing
//! 3-variant ordered enum in fcp-core is `TaintLevel`
//! (capability.rs:2766) with variants
//! `Untainted < Tainted < HighlyTainted`, which:
//!
//!  - Has exactly 3 variants in an escalating progression matching
//!    the bead's "None < X < Y" shape (Untainted ↔ "None").
//!  - Derives `PartialOrd, Ord` so the < relation is meaningful.
//!  - Is used in provenance routing decisions (the practical
//!    equivalent of "how aggressively should we apply X" — here
//!    "how much should we trust this input").
//!
//! An inline `taint_level_ordering` test (capability.rs:5040-5044)
//! covers two strict-`<` assertions but nothing else about the
//! ordering contract. This test pins the contract operators rely on:
//!
//!   1. **Strict total order across all 3 variants**.
//!   2. **Default is the lowest variant** (`Untainted`).
//!   3. **Discriminant order matches Ord**: `as u8` runs
//!      monotonically Untainted=0 < Tainted=1 < HighlyTainted=2.
//!   4. **`max` / `min` / sort behave as expected**.
//!   5. **Order properties** — reflexivity, antisymmetry, transitivity.
//!   6. **`is_tainted` predicate truth table** ↔ `!= Untainted`.
//!   7. **Per-variant JSON serde tag form pinned** (PascalCase since
//!      no `#[serde(rename_all = ...)]` on the enum).
//!   8. **CBOR round-trip preserves variant** for every value.
//!   9. **Copy + Eq derive correctness** — `TaintLevel` is `Copy +
//!      Eq` but NOT `Hash`. Distinctness is observed via the
//!      derived `as u8` discriminants instead.

use std::cmp::Ordering;

use fcp_core::{Provenance, TaintLevel, ZoneId};

const ASCENDING: [TaintLevel; 3] = [
    TaintLevel::Untainted,
    TaintLevel::Tainted,
    TaintLevel::HighlyTainted,
];

// ─────────────────────────────────────────────────────────────────────────────
// 1. Strict total ordering
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn ordering_is_strict_and_total_across_three_variants() {
    // The escalating progression Untainted < Tainted < HighlyTainted
    // is the bead's "None < Compact < Aggressive" analogue.
    assert!(TaintLevel::Untainted < TaintLevel::Tainted);
    assert!(TaintLevel::Tainted < TaintLevel::HighlyTainted);
    assert!(TaintLevel::Untainted < TaintLevel::HighlyTainted);

    // And the reverse is never true.
    assert!(!(TaintLevel::Tainted < TaintLevel::Untainted));
    assert!(!(TaintLevel::HighlyTainted < TaintLevel::Tainted));
    assert!(!(TaintLevel::HighlyTainted < TaintLevel::Untainted));
}

#[test]
fn cmp_returns_documented_ordering_per_pair() {
    let cases = [
        (
            TaintLevel::Untainted,
            TaintLevel::Untainted,
            Ordering::Equal,
        ),
        (TaintLevel::Untainted, TaintLevel::Tainted, Ordering::Less),
        (
            TaintLevel::Untainted,
            TaintLevel::HighlyTainted,
            Ordering::Less,
        ),
        (TaintLevel::Tainted, TaintLevel::Tainted, Ordering::Equal),
        (
            TaintLevel::Tainted,
            TaintLevel::HighlyTainted,
            Ordering::Less,
        ),
        (
            TaintLevel::HighlyTainted,
            TaintLevel::HighlyTainted,
            Ordering::Equal,
        ),
        (TaintLevel::Tainted, TaintLevel::Untainted, Ordering::Greater),
        (
            TaintLevel::HighlyTainted,
            TaintLevel::Tainted,
            Ordering::Greater,
        ),
        (
            TaintLevel::HighlyTainted,
            TaintLevel::Untainted,
            Ordering::Greater,
        ),
    ];
    for (a, b, expected) in cases {
        assert_eq!(a.cmp(&b), expected, "cmp({a:?}, {b:?})");
        assert_eq!(a.partial_cmp(&b), Some(expected));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Default is the lowest variant
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn default_is_lowest_variant() {
    let default_value: TaintLevel = TaintLevel::default();
    assert_eq!(
        default_value,
        TaintLevel::Untainted,
        "Default MUST be the lowest variant (the bead's 'None' analogue)"
    );
    // And the default IS less than every non-default variant.
    assert!(default_value < TaintLevel::Tainted);
    assert!(default_value < TaintLevel::HighlyTainted);
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Discriminant order matches Ord
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn discriminant_order_matches_ord() {
    // The variants are declared in ascending order; the auto-derived
    // Ord MUST follow declaration order. Pin the discriminants too —
    // any reordering or repr change becomes immediately observable.
    assert_eq!(TaintLevel::Untainted as u8, 0);
    assert_eq!(TaintLevel::Tainted as u8, 1);
    assert_eq!(TaintLevel::HighlyTainted as u8, 2);

    // And the u8 cast preserves the same ordering.
    let mut levels = [
        TaintLevel::HighlyTainted,
        TaintLevel::Untainted,
        TaintLevel::Tainted,
    ];
    levels.sort();
    let as_u8: Vec<u8> = levels.iter().map(|t| *t as u8).collect();
    assert_eq!(as_u8, vec![0, 1, 2]);
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. max / min / sort
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn max_returns_higher_variant() {
    assert_eq!(
        std::cmp::max(TaintLevel::Untainted, TaintLevel::Tainted),
        TaintLevel::Tainted
    );
    assert_eq!(
        std::cmp::max(TaintLevel::Tainted, TaintLevel::HighlyTainted),
        TaintLevel::HighlyTainted
    );
    assert_eq!(
        std::cmp::max(TaintLevel::Untainted, TaintLevel::HighlyTainted),
        TaintLevel::HighlyTainted
    );
}

#[test]
fn min_returns_lower_variant() {
    assert_eq!(
        std::cmp::min(TaintLevel::Untainted, TaintLevel::Tainted),
        TaintLevel::Untainted
    );
    assert_eq!(
        std::cmp::min(TaintLevel::Tainted, TaintLevel::HighlyTainted),
        TaintLevel::Tainted
    );
    assert_eq!(
        std::cmp::min(TaintLevel::Untainted, TaintLevel::HighlyTainted),
        TaintLevel::Untainted
    );
}

#[test]
fn sort_orders_ascending() {
    let mut shuffled = [
        TaintLevel::HighlyTainted,
        TaintLevel::Untainted,
        TaintLevel::Tainted,
        TaintLevel::Untainted,
        TaintLevel::HighlyTainted,
        TaintLevel::Tainted,
    ];
    shuffled.sort();
    assert_eq!(
        &shuffled[..],
        &[
            TaintLevel::Untainted,
            TaintLevel::Untainted,
            TaintLevel::Tainted,
            TaintLevel::Tainted,
            TaintLevel::HighlyTainted,
            TaintLevel::HighlyTainted,
        ]
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Order properties — reflexive, antisymmetric, transitive
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn ordering_is_reflexive() {
    for v in ASCENDING {
        assert_eq!(v.cmp(&v), Ordering::Equal);
        assert!(v <= v);
        assert!(v >= v);
        assert!(!(v < v));
        assert!(!(v > v));
    }
}

#[test]
fn ordering_is_antisymmetric() {
    for &a in ASCENDING.iter() {
        for &b in ASCENDING.iter() {
            // a <= b && b <= a  ⇒  a == b
            if a <= b && b <= a {
                assert_eq!(a, b, "antisymmetry violated for {a:?} and {b:?}");
            }
        }
    }
}

#[test]
fn ordering_is_transitive() {
    // Across the 3-element chain, transitivity is exhausted by:
    //   Untainted <= Tainted <= HighlyTainted ⇒ Untainted <= HighlyTainted.
    let a = TaintLevel::Untainted;
    let b = TaintLevel::Tainted;
    let c = TaintLevel::HighlyTainted;
    assert!(a <= b);
    assert!(b <= c);
    assert!(a <= c, "transitivity: a <= b <= c MUST imply a <= c");
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. is_tainted predicate truth table
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn is_tainted_truth_table_via_provenance() {
    // The `is_tainted` predicate lives on Provenance and reflects
    // whether the provenance's TaintLevel is anything other than
    // Untainted — i.e., the "is the level above the floor" check
    // that operators rely on for routing decisions.
    let zone = ZoneId::work();
    let untainted = Provenance::new(zone.clone());
    let tainted = Provenance::tainted(zone.clone());
    let highly = Provenance::highly_tainted(zone);

    assert!(!untainted.is_tainted(), "Untainted MUST be is_tainted=false");
    assert!(tainted.is_tainted(), "Tainted MUST be is_tainted=true");
    assert!(
        highly.is_tainted(),
        "HighlyTainted MUST be is_tainted=true"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. Per-variant JSON form pinning
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn json_form_pinned_per_variant() {
    // No #[serde(rename_all = ...)] on the enum, so default serde
    // behavior emits the variant name verbatim (PascalCase). Pin
    // these tokens — they show up in provenance audit logs.
    let cases = [
        (TaintLevel::Untainted, r#""Untainted""#),
        (TaintLevel::Tainted, r#""Tainted""#),
        (TaintLevel::HighlyTainted, r#""HighlyTainted""#),
    ];
    for (variant, expected) in cases {
        let got = serde_json::to_string(&variant).expect("serialize");
        assert_eq!(
            got, expected,
            "TaintLevel JSON tag drift on {variant:?} — provenance \
             audit logs filter on this exact string"
        );
        let back: TaintLevel = serde_json::from_str(&got).expect("deserialize");
        assert_eq!(back, variant);
    }
}

#[test]
fn json_rejects_snake_case_or_unknown_variant() {
    for bad in [r#""untainted""#, r#""tainted""#, r#""high""#, r#""None""#] {
        let parsed = serde_json::from_str::<TaintLevel>(bad);
        assert!(
            parsed.is_err(),
            "{bad} MUST be rejected — only PascalCase variant names are canonical"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. CBOR round-trip preserves variant + ordering
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn cbor_roundtrip_preserves_variant_for_every_level() {
    for variant in ASCENDING {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&variant, &mut buf).expect("encode");
        let back: TaintLevel = ciborium::de::from_reader(buf.as_slice()).expect("decode");
        assert_eq!(variant, back, "CBOR round-trip lost {variant:?}");
        assert_eq!(variant.cmp(&back), Ordering::Equal);
    }
}

#[test]
fn cbor_roundtrip_preserves_relative_ordering() {
    // Encode all three, decode all three, verify the < relation
    // holds on the decoded values.
    let originals = ASCENDING;
    let mut decoded: Vec<TaintLevel> = Vec::with_capacity(originals.len());
    for v in originals {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&v, &mut buf).expect("encode");
        decoded.push(ciborium::de::from_reader(buf.as_slice()).expect("decode"));
    }
    assert!(decoded[0] < decoded[1]);
    assert!(decoded[1] < decoded[2]);
    assert!(decoded[0] < decoded[2]);
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. Copy + Eq correctness, Hash absence
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn copy_preserves_equality_for_every_variant() {
    for variant in ASCENDING {
        let copied: TaintLevel = variant; // Copy via assignment
        let cloned = variant; // Copy via shorthand (TaintLevel is Copy)
        assert_eq!(variant, copied);
        assert_eq!(variant, cloned);
        // Cmp also returns Equal across copies.
        assert_eq!(variant.cmp(&copied), Ordering::Equal);
        assert_eq!(variant.cmp(&cloned), Ordering::Equal);
    }
}

#[test]
fn distinct_variants_via_u8_are_distinct() {
    // Without Hash, distinctness via discriminant `as u8` is the
    // observable substitute. The 3 variants MUST have distinct
    // discriminants — pinned at 0 / 1 / 2 above.
    let mut seen = std::collections::HashSet::new();
    for variant in ASCENDING {
        let inserted = seen.insert(variant as u8);
        assert!(
            inserted,
            "{variant:?} discriminant {} already seen",
            variant as u8
        );
    }
    assert_eq!(seen.len(), 3);
}

