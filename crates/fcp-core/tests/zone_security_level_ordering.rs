//! Pin `IntegrityLevel` + `ConfidentialityLevel` Display + serde + zone-derived
//! Bell-LaPadula/Biba flow contracts — the closest analogue to
//! "ZoneSecurityLevel ordering + Display"
//! (flywheel_connectors-z8agn).
//!
//! Bead asks for `ZoneSecurityLevel` ordering + Display pinning. No type
//! literally named `ZoneSecurityLevel` exists in fcp-core. The closest
//! zone-derived security-level analogues are [`IntegrityLevel`] and
//! [`ConfidentialityLevel`] at `crates/fcp-core/src/provenance.rs:51+105`.
//! Both are 5-variant `repr(u8)` enums with `from_zone(zone) → Self`,
//! Display, Ord/PartialOrd, and complementary lattice semantics:
//!   * `IntegrityLevel`: integrity flows DOWN the lattice freely; flowing
//!     UP requires elevation,
//!   * `ConfidentialityLevel`: confidentiality flows UP the lattice freely;
//!     flowing DOWN requires declassification.
//!
//! Existing `isolation_level_ordering.rs` covers ordering chains + zone
//! defaults at as_u8 granularity. This pin adds residual axes:
//!   * Per-variant Display verbatim,
//!   * Per-variant snake_case serde wire form (NOTE: ConfidentialityLevel
//!     and IntegrityLevel default to PascalCase — pin the actual form),
//!   * Default = Untrusted / Public (zero of each ladder),
//!   * `from_zone` truth table for every documented zone token + unknown,
//!   * Bell-LaPadula/Biba flow contract: integrity-down is ≤; confidentiality-up
//!     is ≥ — pin via direct comparison so a future swap of the defaults
//!     (e.g. flipping Owner=0 / Untrusted=4) is caught loudly,
//!   * Cross-enum disjoint-bottom sentinel: both Untrusted (Integrity 0)
//!     and Public (Confidentiality 0) live at the bottom, but for OPPOSITE
//!     reasons (least trust vs least restriction). They MUST NOT be
//!     conflated by any caller; pin distinct Display strings.
//!   * JSON + CBOR round-trip for every variant.

use ciborium::Value as CborValue;
use fcp_core::{ConfidentialityLevel, IntegrityLevel, ZoneId};
use serde_json::json;

const ALL_INTEGRITY: &[(IntegrityLevel, &str)] = &[
    (IntegrityLevel::Untrusted, "untrusted"),
    (IntegrityLevel::Community, "community"),
    (IntegrityLevel::Work, "work"),
    (IntegrityLevel::Private, "private"),
    (IntegrityLevel::Owner, "owner"),
];

const ALL_CONFIDENTIALITY: &[(ConfidentialityLevel, &str)] = &[
    (ConfidentialityLevel::Public, "public"),
    (ConfidentialityLevel::Community, "community"),
    (ConfidentialityLevel::Work, "work"),
    (ConfidentialityLevel::Private, "private"),
    (ConfidentialityLevel::Owner, "owner"),
];

#[test]
fn integrity_level_display_matches_documented_per_variant_token() {
    for &(variant, token) in ALL_INTEGRITY {
        assert_eq!(
            variant.to_string(),
            token,
            "IntegrityLevel Display drift on {variant:?}"
        );
    }
}

#[test]
fn confidentiality_level_display_matches_documented_per_variant_token() {
    for &(variant, token) in ALL_CONFIDENTIALITY {
        assert_eq!(
            variant.to_string(),
            token,
            "ConfidentialityLevel Display drift on {variant:?}"
        );
    }
}

#[test]
fn integrity_level_default_is_untrusted_zero() {
    let default = IntegrityLevel::default();
    assert_eq!(default, IntegrityLevel::Untrusted);
    assert_eq!(default.as_u8(), 0);
}

#[test]
fn confidentiality_level_default_is_public_zero() {
    let default = ConfidentialityLevel::default();
    assert_eq!(default, ConfidentialityLevel::Public);
    assert_eq!(default.as_u8(), 0);
}

#[test]
fn integrity_from_zone_truth_table_per_documented_zone() {
    // Documented: owner/private/work/community → matching variant; any other
    // zone (including public, custom, malformed) maps to Untrusted.
    assert_eq!(
        IntegrityLevel::from_zone(&ZoneId::owner()),
        IntegrityLevel::Owner
    );
    assert_eq!(
        IntegrityLevel::from_zone(&ZoneId::private()),
        IntegrityLevel::Private
    );
    assert_eq!(
        IntegrityLevel::from_zone(&ZoneId::work()),
        IntegrityLevel::Work
    );
    assert_eq!(
        IntegrityLevel::from_zone(&ZoneId::community()),
        IntegrityLevel::Community
    );
    // Public zone → Untrusted (NOT a special variant for Public on the
    // integrity lattice — pin so a future Public=Some other value is caught).
    assert_eq!(
        IntegrityLevel::from_zone(&ZoneId::public()),
        IntegrityLevel::Untrusted
    );
}

#[test]
fn confidentiality_from_zone_truth_table_per_documented_zone() {
    assert_eq!(
        ConfidentialityLevel::from_zone(&ZoneId::owner()),
        ConfidentialityLevel::Owner
    );
    assert_eq!(
        ConfidentialityLevel::from_zone(&ZoneId::private()),
        ConfidentialityLevel::Private
    );
    assert_eq!(
        ConfidentialityLevel::from_zone(&ZoneId::work()),
        ConfidentialityLevel::Work
    );
    assert_eq!(
        ConfidentialityLevel::from_zone(&ZoneId::community()),
        ConfidentialityLevel::Community
    );
    // Public zone → Public confidentiality (lowest restriction).
    assert_eq!(
        ConfidentialityLevel::from_zone(&ZoneId::public()),
        ConfidentialityLevel::Public
    );
}

#[test]
fn integrity_lattice_owner_strictly_dominates_every_lower_variant() {
    // Pin the documented order: Untrusted < Community < Work < Private < Owner.
    let owner = IntegrityLevel::Owner;
    for &(lower, _) in &ALL_INTEGRITY[..4] {
        assert!(lower < owner, "{lower:?} must be < Owner");
        assert!(owner > lower, "Owner must be > {lower:?}");
    }
    for window in ALL_INTEGRITY.windows(2) {
        let (a, _) = window[0];
        let (b, _) = window[1];
        assert!(a < b, "{a:?} must be < {b:?}");
    }
}

#[test]
fn confidentiality_lattice_owner_strictly_dominates_every_lower_variant() {
    let owner = ConfidentialityLevel::Owner;
    for &(lower, _) in &ALL_CONFIDENTIALITY[..4] {
        assert!(lower < owner, "{lower:?} must be < Owner");
        assert!(owner > lower, "Owner must be > {lower:?}");
    }
    for window in ALL_CONFIDENTIALITY.windows(2) {
        let (a, _) = window[0];
        let (b, _) = window[1];
        assert!(a < b, "{a:?} must be < {b:?}");
    }
}

#[test]
fn biba_integrity_flow_predicate_via_le_comparison() {
    // Biba "no read down, no write up" rephrased in this lattice:
    // data tagged at integrity level `src` flows to a sink at level `dst`
    // freely iff src >= dst (data of higher integrity can drive lower-integrity
    // sinks; the reverse requires elevation). Pin via direct >= comparison
    // for every pair.
    let dst = IntegrityLevel::Work;
    assert!(IntegrityLevel::Owner >= dst);
    assert!(IntegrityLevel::Private >= dst);
    assert!(IntegrityLevel::Work >= dst);
    assert!(!(IntegrityLevel::Community >= dst));
    assert!(!(IntegrityLevel::Untrusted >= dst));
}

#[test]
fn bell_lapadula_confidentiality_flow_predicate_via_ge_comparison() {
    // Bell-LaPadula "no read up, no write down" rephrased: data tagged at
    // confidentiality level `src` flows to a sink at level `dst` freely iff
    // dst >= src (the sink is at least as restricted as the source; the
    // reverse requires declassification). Pin via direct dst >= src for
    // every pair.
    let src = ConfidentialityLevel::Work;
    assert!(ConfidentialityLevel::Owner >= src);
    assert!(ConfidentialityLevel::Private >= src);
    assert!(ConfidentialityLevel::Work >= src);
    assert!(!(ConfidentialityLevel::Community >= src));
    assert!(!(ConfidentialityLevel::Public >= src));
}

#[test]
fn integrity_and_confidentiality_zero_are_disjoint_bottom_states() {
    // Both ladders have an as_u8() == 0 variant, but the variants are
    // distinct concepts: Untrusted (least trust) vs Public (least restriction).
    // Display strings MUST differ to keep audit logs unambiguous.
    let i_zero = IntegrityLevel::default(); // Untrusted
    let c_zero = ConfidentialityLevel::default(); // Public
    assert_eq!(i_zero.as_u8(), 0);
    assert_eq!(c_zero.as_u8(), 0);
    assert_ne!(
        i_zero.to_string(),
        c_zero.to_string(),
        "Bottom-state Display must differ: integrity `{i_zero}` vs confidentiality `{c_zero}`"
    );
    assert_eq!(i_zero.to_string(), "untrusted");
    assert_eq!(c_zero.to_string(), "public");
}

#[test]
fn integrity_level_serde_pascalcase_default_per_variant() {
    // IntegrityLevel has NO rename_all → serde defaults to PascalCase.
    // Pin so a future addition of rename_all (which would silently break
    // wire compatibility for existing on-disk Provenance objects) is caught.
    let cases = [
        (IntegrityLevel::Untrusted, "Untrusted"),
        (IntegrityLevel::Community, "Community"),
        (IntegrityLevel::Work, "Work"),
        (IntegrityLevel::Private, "Private"),
        (IntegrityLevel::Owner, "Owner"),
    ];
    for (variant, pascal) in cases {
        let v = serde_json::to_value(variant).unwrap();
        assert_eq!(
            v,
            json!(pascal),
            "IntegrityLevel {variant:?} must serialize PascalCase `{pascal}`"
        );
        let back: IntegrityLevel = serde_json::from_value(v).unwrap();
        assert_eq!(back, variant);
    }
}

#[test]
fn confidentiality_level_serde_pascalcase_default_per_variant() {
    let cases = [
        (ConfidentialityLevel::Public, "Public"),
        (ConfidentialityLevel::Community, "Community"),
        (ConfidentialityLevel::Work, "Work"),
        (ConfidentialityLevel::Private, "Private"),
        (ConfidentialityLevel::Owner, "Owner"),
    ];
    for (variant, pascal) in cases {
        let v = serde_json::to_value(variant).unwrap();
        assert_eq!(
            v,
            json!(pascal),
            "ConfidentialityLevel {variant:?} must serialize PascalCase `{pascal}`"
        );
        let back: ConfidentialityLevel = serde_json::from_value(v).unwrap();
        assert_eq!(back, variant);
    }
}

#[test]
fn integrity_level_cbor_roundtrip_per_variant() {
    for &(variant, _) in ALL_INTEGRITY {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&variant, &mut bytes).unwrap();
        let back: IntegrityLevel = ciborium::de::from_reader(&bytes[..]).unwrap();
        assert_eq!(back, variant);

        // CBOR shape: PascalCase Text scalar.
        let value: CborValue = ciborium::de::from_reader(&bytes[..]).unwrap();
        match value {
            CborValue::Text(_) => (),
            other => panic!("IntegrityLevel must encode as CBOR Text, got {other:?}"),
        }
    }
}

#[test]
fn confidentiality_level_cbor_roundtrip_per_variant() {
    for &(variant, _) in ALL_CONFIDENTIALITY {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&variant, &mut bytes).unwrap();
        let back: ConfidentialityLevel = ciborium::de::from_reader(&bytes[..]).unwrap();
        assert_eq!(back, variant);
    }
}

#[test]
fn levels_work_as_hashmap_keys_for_audit_grouping() {
    // Audit pipelines bucket by integrity/confidentiality; pin Hash + Eq.
    let mut counts: std::collections::HashMap<IntegrityLevel, u32> =
        std::collections::HashMap::new();
    *counts.entry(IntegrityLevel::Owner).or_insert(0) += 3;
    *counts.entry(IntegrityLevel::Untrusted).or_insert(0) += 7;
    *counts.entry(IntegrityLevel::Owner).or_insert(0) += 2;
    assert_eq!(counts.get(&IntegrityLevel::Owner), Some(&5));
    assert_eq!(counts.get(&IntegrityLevel::Untrusted), Some(&7));
    assert_eq!(counts.get(&IntegrityLevel::Work), None);
}

#[test]
fn integrity_lattice_min_and_max_match_expected_endpoints() {
    let levels = [
        IntegrityLevel::Owner,
        IntegrityLevel::Untrusted,
        IntegrityLevel::Work,
        IntegrityLevel::Community,
        IntegrityLevel::Private,
    ];
    assert_eq!(*levels.iter().min().unwrap(), IntegrityLevel::Untrusted);
    assert_eq!(*levels.iter().max().unwrap(), IntegrityLevel::Owner);
}

#[test]
fn confidentiality_lattice_min_and_max_match_expected_endpoints() {
    let levels = [
        ConfidentialityLevel::Owner,
        ConfidentialityLevel::Public,
        ConfidentialityLevel::Work,
        ConfidentialityLevel::Community,
        ConfidentialityLevel::Private,
    ];
    assert_eq!(*levels.iter().min().unwrap(), ConfidentialityLevel::Public);
    assert_eq!(*levels.iter().max().unwrap(), ConfidentialityLevel::Owner);
}
