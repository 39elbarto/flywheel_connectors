//! Pin `EnforcementCheckId` Display label stability + serde round-trip
//! (flywheel_connectors-tt7js).
//!
//! `EnforcementCheckId` (enforcement.rs:34) is the canonical
//! identifier for each step of the NORMATIVE enforcement pipeline.
//! Its `as_str()` label is the stable token used in:
//!
//! - Audit-log entries (every `CheckRecord` carries the check id).
//! - Operator dashboards and API responses.
//! - Cross-implementation conformance reports.
//!
//! Drift in any label fragments audit-log compatibility and breaks
//! operator tooling that filters on those tokens.
//!
//! Bead asks for "Display+FromStr roundtrip"; the type does NOT
//! implement `FromStr` (only Display via `as_str()`). The test
//! covers what exists:
//!
//!   1. **Per-variant label pinning** — the exact `as_str()` /
//!      `Display` form for every one of the 12 variants.
//!   2. **Display agrees with `as_str()`** — both implementations
//!      MUST emit the same bytes.
//!   3. **All 12 labels pairwise distinct** — required so audit
//!      logs can unambiguously discriminate checks.
//!   4. **Equality + Hash via the derive** — Copy + Eq + Hash on
//!      every variant; clones and copies hash identically.
//!   5. **Serde JSON round-trip** — `#[serde(rename_all =
//!      "snake_case")]` MUST emit the same labels as `as_str()`,
//!      and JSON deserialize MUST round-trip.
//!   6. **Cross-pair distinctness** — every distinct pair has
//!      distinct hashes (sanity check on the hasher).
//!   7. **Label format constraint** — every label is non-empty,
//!      ASCII, lowercase, and uses only `[a-z_]` (no digits or
//!      separators outside `_`).

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use fcp_core::EnforcementCheckId;

fn hash_of<T: Hash + ?Sized>(v: &T) -> u64 {
    let mut h = DefaultHasher::new();
    v.hash(&mut h);
    h.finish()
}

/// All 12 variants paired with their NORMATIVE label.
const VARIANTS: &[(EnforcementCheckId, &str)] = &[
    (EnforcementCheckId::CanonicalDecode, "canonical_decode"),
    (EnforcementCheckId::ZoneMembership, "zone_membership"),
    (EnforcementCheckId::CapabilityVerify, "capability_verify"),
    (EnforcementCheckId::HolderProof, "holder_proof"),
    (
        EnforcementCheckId::CheckpointFreshness,
        "checkpoint_freshness",
    ),
    (
        EnforcementCheckId::RevocationFreshness,
        "revocation_freshness",
    ),
    (EnforcementCheckId::TaintApproval, "taint_approval"),
    (EnforcementCheckId::PolicyCeiling, "policy_ceiling"),
    (
        EnforcementCheckId::CapabilityConstraints,
        "capability_constraints",
    ),
    (EnforcementCheckId::ConnectorManifest, "connector_manifest"),
    (EnforcementCheckId::Budget, "budget"),
    (EnforcementCheckId::RateLimit, "rate_limit"),
];

// ─────────────────────────────────────────────────────────────────────────────
// 1. Per-variant label pinning
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn as_str_label_pinned_for_every_variant() {
    for (variant, expected) in VARIANTS {
        assert_eq!(
            variant.as_str(),
            *expected,
            "AUDIT REGRESSION: label drift on {variant:?} — old logs and dashboards \
             will stop matching"
        );
    }
}

#[test]
fn display_emits_as_str_label_for_every_variant() {
    for (variant, expected) in VARIANTS {
        assert_eq!(
            variant.to_string(),
            *expected,
            "Display MUST emit the as_str label verbatim for {variant:?}"
        );
        assert_eq!(format!("{variant}"), *expected, "format!() agrees");
    }
}

#[test]
fn display_agrees_with_as_str_byte_for_byte() {
    // Two distinct implementations of "render to string" — Display
    // and as_str — MUST agree byte-for-byte.
    for (variant, _) in VARIANTS {
        assert_eq!(
            variant.to_string(),
            variant.as_str(),
            "Display vs as_str MUST agree for {variant:?}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Pairwise distinct labels
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn all_twelve_labels_pairwise_distinct() {
    use std::collections::HashSet;
    let labels: HashSet<&'static str> = VARIANTS.iter().map(|(_, s)| *s).collect();
    assert_eq!(
        labels.len(),
        VARIANTS.len(),
        "every EnforcementCheckId label MUST be distinct so audit logs can \
         unambiguously discriminate checks; got duplicates: {labels:?}"
    );
}

#[test]
fn label_count_matches_documented_twelve() {
    assert_eq!(
        VARIANTS.len(),
        12,
        "EnforcementCheckId variant count drifted from documented 12"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Equality + Hash + Copy via derive
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn equality_reflexive_and_hash_deterministic() {
    for (variant, _) in VARIANTS {
        assert_eq!(*variant, *variant, "reflexive equality");
        let h1 = hash_of(variant);
        let h2 = hash_of(variant);
        assert_eq!(h1, h2, "Hash is deterministic for {variant:?}");
    }
}

#[test]
fn copy_and_clone_preserve_equality_and_hash() {
    for (variant, _) in VARIANTS {
        let copied: EnforcementCheckId = *variant; // Copy
        let cloned: EnforcementCheckId = copied; // Copy via assignment
        let cloned_explicit = (*variant).clone();
        assert_eq!(*variant, copied);
        assert_eq!(*variant, cloned);
        assert_eq!(*variant, cloned_explicit);
        let h = hash_of(variant);
        assert_eq!(h, hash_of(&copied));
        assert_eq!(h, hash_of(&cloned));
        assert_eq!(h, hash_of(&cloned_explicit));
    }
}

#[test]
fn distinct_variants_pairwise_unequal() {
    for i in 0..VARIANTS.len() {
        for j in (i + 1)..VARIANTS.len() {
            assert_ne!(
                VARIANTS[i].0, VARIANTS[j].0,
                "{:?} and {:?} MUST be distinct variants",
                VARIANTS[i].0, VARIANTS[j].0
            );
        }
    }
}

#[test]
fn distinct_variants_hash_distinctly_in_practice() {
    // Sanity check on the derived Hash producing useful output.
    let hashes: Vec<u64> = VARIANTS.iter().map(|(v, _)| hash_of(v)).collect();
    let unique: std::collections::HashSet<u64> = hashes.iter().copied().collect();
    assert_eq!(
        unique.len(),
        hashes.len(),
        "12 variants MUST hash to distinct u64s: {hashes:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Serde JSON round-trip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn serde_json_form_pinned_for_every_variant() {
    // `#[serde(rename_all = "snake_case")]` MUST produce the same
    // labels as as_str(). JSON form is the quoted snake_case label.
    for (variant, expected) in VARIANTS {
        let json = serde_json::to_string(variant).expect("serialize");
        assert_eq!(
            json,
            format!("\"{expected}\""),
            "JSON form MUST be quoted {expected:?} for {variant:?}"
        );
    }
}

#[test]
fn serde_json_roundtrip_preserves_variant() {
    for (variant, _) in VARIANTS {
        let json = serde_json::to_string(variant).expect("serialize");
        let back: EnforcementCheckId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(
            *variant, back,
            "JSON round-trip lost variant for {variant:?}"
        );
        assert_eq!(hash_of(variant), hash_of(&back));
    }
}

#[test]
fn serde_json_deserialize_accepts_documented_label() {
    // Pin that the JSON deserialization accepts the exact as_str()
    // label as input — i.e., the JSON form is the canonical input
    // for downstream tooling.
    for (variant, expected) in VARIANTS {
        let input = format!("\"{expected}\"");
        let parsed: EnforcementCheckId =
            serde_json::from_str(&input).unwrap_or_else(|err| panic!("deserialize {input}: {err}"));
        assert_eq!(parsed, *variant);
    }
}

#[test]
fn serde_json_rejects_unknown_label() {
    let bad = serde_json::from_str::<EnforcementCheckId>("\"unknown_check\"");
    assert!(bad.is_err(), "unknown label MUST be rejected");

    // Wrong case (PascalCase original variant name) — rejected.
    let bad_case = serde_json::from_str::<EnforcementCheckId>("\"CanonicalDecode\"");
    assert!(
        bad_case.is_err(),
        "PascalCase variant name MUST be rejected; only snake_case is canonical"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Label format invariants
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn every_label_is_non_empty_ascii_lowercase_snake_case() {
    for (variant, label) in VARIANTS {
        assert!(!label.is_empty(), "{variant:?}: empty label");
        assert!(label.is_ascii(), "{variant:?}: non-ASCII label {label:?}");
        assert!(
            label.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
            "{variant:?}: label MUST be lowercase a-z plus `_`, got {label:?}"
        );
        // No leading or trailing underscore.
        assert!(
            !label.starts_with('_'),
            "{variant:?}: label MUST NOT start with `_` ({label:?})"
        );
        assert!(
            !label.ends_with('_'),
            "{variant:?}: label MUST NOT end with `_` ({label:?})"
        );
        // No double underscore.
        assert!(
            !label.contains("__"),
            "{variant:?}: label MUST NOT contain `__` ({label:?})"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. HashMap-key correctness
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn enforcement_check_id_serves_as_hashmap_key() {
    use std::collections::HashMap;
    let mut map: HashMap<EnforcementCheckId, &'static str> = HashMap::new();
    for (variant, label) in VARIANTS {
        map.insert(*variant, *label);
    }
    assert_eq!(
        map.len(),
        VARIANTS.len(),
        "every variant MUST be a distinct key"
    );

    // Look up via copies (Copy trait) and via JSON-roundtripped values.
    for (variant, label) in VARIANTS {
        assert_eq!(map.get(variant), Some(label));
        let copied: EnforcementCheckId = *variant;
        assert_eq!(map.get(&copied), Some(label));
        let json = serde_json::to_string(variant).unwrap();
        let rt: EnforcementCheckId = serde_json::from_str(&json).unwrap();
        assert_eq!(map.get(&rt), Some(label));
    }
}
