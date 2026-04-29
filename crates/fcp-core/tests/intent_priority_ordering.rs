//! Pin `TrustLevel` ordering — the closest analogue to
//! "IntentPriority Low < Medium < High < Critical"
//! (flywheel_connectors-ljnej).
//!
//! Bead asks for `IntentPriority ordering: Low < Medium < High <
//! Critical, plus partial_cmp`. No type literally named
//! `IntentPriority` exists in fcp-core. The closest 4-variant
//! Low/Medium/High/Critical type is `RiskLevel` (capability.rs:2254)
//! BUT it does NOT derive `PartialOrd` or `Ord`, so the bead's
//! `partial_cmp` ask is structurally impossible there.
//!
//! The closest ORDERED priority-shaped classifier in fcp-core is
//! `TrustLevel` (capability.rs:2792) — 6 variants
//! (`Blocked < Anonymous < Untrusted < Paired < Admin < Owner`)
//! that DO derive `PartialOrd + Ord`, with a documented "from
//! lowest to highest trust" ordering. Pin that as the closest
//! analogue and document the RiskLevel mismatch alongside.
//!
//! Targets:
//!
//!   1. **Strict total ordering across 6 `TrustLevel` variants**
//!      — Blocked < Anonymous < Untrusted < Paired < Admin < Owner.
//!   2. **`cmp` truth table per pair** (15 ordered pairs +
//!      6 reflexive Equal cases).
//!   3. **`partial_cmp` returns `Some(_)` for every pair** (total
//!      ordering, no None).
//!   4. **`max` / `min` / `sort`** behave consistently with `<`.
//!   5. **Order properties** — reflexivity, antisymmetry,
//!      transitivity.
//!   6. **Per-variant JSON tag** in lowercase (`rename_all =
//!      "lowercase"`).
//!   7. **JSON + CBOR round-trip** per variant.
//!   8. **`RiskLevel` documents the mismatch** — RiskLevel has
//!      Low/Medium/High/Critical variant names matching the bead's
//!      pattern but no Ord; the discriminant order via `as u8` is
//!      the only ordering surface available, and it follows
//!      declaration order.

use std::cmp::Ordering;

use fcp_core::{RiskLevel, TrustLevel};

const ASCENDING: [TrustLevel; 6] = [
    TrustLevel::Blocked,
    TrustLevel::Anonymous,
    TrustLevel::Untrusted,
    TrustLevel::Paired,
    TrustLevel::Admin,
    TrustLevel::Owner,
];

// ─────────────────────────────────────────────────────────────────────────────
// 1. Strict total ordering across all 6 TrustLevel variants
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn trust_level_strict_ordering_chain() {
    // Document chain: Blocked < Anonymous < Untrusted < Paired < Admin < Owner
    assert!(TrustLevel::Blocked < TrustLevel::Anonymous);
    assert!(TrustLevel::Anonymous < TrustLevel::Untrusted);
    assert!(TrustLevel::Untrusted < TrustLevel::Paired);
    assert!(TrustLevel::Paired < TrustLevel::Admin);
    assert!(TrustLevel::Admin < TrustLevel::Owner);

    // Transitivity: lowest < highest.
    assert!(TrustLevel::Blocked < TrustLevel::Owner);
    assert!(TrustLevel::Anonymous < TrustLevel::Admin);

    // Reverse direction never holds.
    assert!(!(TrustLevel::Owner < TrustLevel::Admin));
    assert!(!(TrustLevel::Anonymous < TrustLevel::Blocked));
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. cmp() truth table per pair
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn cmp_returns_documented_ordering_per_pair() {
    for (i, a) in ASCENDING.iter().enumerate() {
        for (j, b) in ASCENDING.iter().enumerate() {
            let expected = match i.cmp(&j) {
                Ordering::Less => Ordering::Less,
                Ordering::Equal => Ordering::Equal,
                Ordering::Greater => Ordering::Greater,
            };
            assert_eq!(
                a.cmp(b),
                expected,
                "cmp({a:?}, {b:?}) drift: expected {expected:?}"
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. partial_cmp returns Some(_) for every pair
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn partial_cmp_is_total_returns_some_for_every_pair() {
    // The bead asks specifically for partial_cmp coverage. TrustLevel
    // is fully Ord, so partial_cmp MUST return Some(_) for every
    // pair — total ordering, no None ever.
    for a in ASCENDING {
        for b in ASCENDING {
            let pc = a.partial_cmp(&b);
            assert!(
                pc.is_some(),
                "partial_cmp({a:?}, {b:?}) MUST return Some(_) — total ordering"
            );
            assert_eq!(pc.unwrap(), a.cmp(&b), "partial_cmp MUST agree with cmp");
        }
    }
}

#[test]
fn partial_cmp_specific_pairs_pinned() {
    let cases = [
        (TrustLevel::Blocked, TrustLevel::Owner, Ordering::Less),
        (TrustLevel::Owner, TrustLevel::Blocked, Ordering::Greater),
        (TrustLevel::Paired, TrustLevel::Paired, Ordering::Equal),
        (TrustLevel::Admin, TrustLevel::Owner, Ordering::Less),
        (TrustLevel::Anonymous, TrustLevel::Untrusted, Ordering::Less),
    ];
    for (a, b, expected) in cases {
        assert_eq!(a.partial_cmp(&b), Some(expected));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. max / min / sort behavior
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn max_returns_higher_variant() {
    assert_eq!(
        std::cmp::max(TrustLevel::Blocked, TrustLevel::Owner),
        TrustLevel::Owner
    );
    assert_eq!(
        std::cmp::max(TrustLevel::Paired, TrustLevel::Anonymous),
        TrustLevel::Paired
    );
}

#[test]
fn min_returns_lower_variant() {
    assert_eq!(
        std::cmp::min(TrustLevel::Blocked, TrustLevel::Owner),
        TrustLevel::Blocked
    );
    assert_eq!(
        std::cmp::min(TrustLevel::Admin, TrustLevel::Untrusted),
        TrustLevel::Untrusted
    );
}

#[test]
fn sort_orders_ascending() {
    let mut shuffled = [
        TrustLevel::Owner,
        TrustLevel::Blocked,
        TrustLevel::Admin,
        TrustLevel::Anonymous,
        TrustLevel::Paired,
        TrustLevel::Untrusted,
    ];
    shuffled.sort();
    assert_eq!(&shuffled[..], &ASCENDING);
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
            if a <= b && b <= a {
                assert_eq!(a, b, "antisymmetry violated for {a:?} and {b:?}");
            }
        }
    }
}

#[test]
fn ordering_is_transitive_across_full_chain() {
    // Across the 6-element chain, transitivity is exhausted by:
    //   Blocked <= Anonymous <= ... <= Owner
    //   ⇒ Blocked <= Owner.
    let chain = ASCENDING;
    for window in chain.windows(2) {
        assert!(window[0] <= window[1]);
    }
    assert!(chain[0] <= chain[chain.len() - 1]);
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Per-variant JSON tag in lowercase
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn trust_level_json_tag_pinned_per_variant_lowercase() {
    let cases = [
        (TrustLevel::Blocked, "blocked"),
        (TrustLevel::Anonymous, "anonymous"),
        (TrustLevel::Untrusted, "untrusted"),
        (TrustLevel::Paired, "paired"),
        (TrustLevel::Admin, "admin"),
        (TrustLevel::Owner, "owner"),
    ];
    for (variant, expected) in cases {
        let json = serde_json::to_string(&variant).expect("serialize");
        assert_eq!(
            json,
            format!("\"{expected}\""),
            "TrustLevel JSON tag drift on {variant:?} — \
             rename_all=lowercase MUST emit lowercase variant name"
        );
    }
}

#[test]
fn trust_level_rejects_pascal_case_and_unknown() {
    for bad in [
        r#""Blocked""#,
        r#""Owner""#,
        r#""ROOT""#,
        r#""guest""#,
        r#""""#,
    ] {
        let parsed = serde_json::from_str::<TrustLevel>(bad);
        assert!(parsed.is_err(), "{bad} MUST be rejected");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. JSON + CBOR round-trip per variant
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn trust_level_json_roundtrip_per_variant() {
    for variant in ASCENDING {
        let json = serde_json::to_string(&variant).expect("serialize");
        let back: TrustLevel = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(variant, back);
    }
}

#[test]
fn trust_level_cbor_roundtrip_per_variant() {
    for variant in ASCENDING {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&variant, &mut buf).expect("encode");
        let back: TrustLevel = ciborium::de::from_reader(buf.as_slice()).expect("decode");
        assert_eq!(variant, back);
    }
}

#[test]
fn trust_level_cbor_roundtrip_preserves_relative_ordering() {
    // Encode all variants, decode each, verify chain ordering survives.
    let mut decoded: Vec<TrustLevel> = Vec::new();
    for v in ASCENDING {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&v, &mut buf).expect("encode");
        decoded.push(ciborium::de::from_reader(buf.as_slice()).expect("decode"));
    }
    for window in decoded.windows(2) {
        assert!(window[0] < window[1], "CBOR round-trip lost ordering");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. RiskLevel mismatch — Low/Medium/High/Critical without Ord
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn risk_level_does_not_derive_ord_so_only_discriminant_ordering_is_observable() {
    // RiskLevel has the EXACT variant names the bead asks about
    // (Low/Medium/High/Critical) but does NOT derive PartialOrd or
    // Ord — so direct `<` comparison is unavailable. The discriminant
    // order via `as u8` is the only observable substitute, and it
    // follows source declaration order.
    //
    // (If a future commit adds Ord derive on RiskLevel, this test
    // still passes — but the mismatch documentation in the docstring
    // is a sentinel for review.)
    let levels = [
        RiskLevel::Low,
        RiskLevel::Medium,
        RiskLevel::High,
        RiskLevel::Critical,
    ];
    let discriminants: Vec<u8> = levels.iter().map(|r| *r as u8).collect();
    assert_eq!(
        discriminants,
        vec![0, 1, 2, 3],
        "RiskLevel discriminants MUST follow source declaration order \
         (Low=0, Medium=1, High=2, Critical=3) — drift surfaces here \
         even without an Ord derive"
    );
}

#[test]
fn risk_level_serde_tags_pinned_in_documented_priority_order() {
    // Pin the serialized form per variant in declaration order so
    // any future reordering (e.g., putting Critical first) is
    // immediately observable in this test even though the type
    // can't compare via `<`.
    let cases = [
        (RiskLevel::Low, "low"),
        (RiskLevel::Medium, "medium"),
        (RiskLevel::High, "high"),
        (RiskLevel::Critical, "critical"),
    ];
    for (variant, expected) in cases {
        let json = serde_json::to_string(&variant).unwrap();
        assert_eq!(json, format!("\"{expected}\""));
    }
}

#[test]
fn trust_level_count_matches_documented_six() {
    assert_eq!(ASCENDING.len(), 6);
}
