//! Pin `RevocationDecision` + `RevocationFreshnessClass` serde tag
//! matrix — the closest analogues to "CapabilityRevocation Display"
//! (flywheel_connectors-ym328).
//!
//! Bead asks for `CapabilityRevocation Display + serde tag`. No type
//! literally named `CapabilityRevocation` exists in fcp-core. The
//! revocation surface that decides whether a capability is revoked
//! covers many enums most of which are already pinned (RevocationScope
//! by 8gfcv, SealValidation by registry_consistency_variant_matrix.rs,
//! RevocationSlaStatus indirectly via revocation tests). Two unpinned
//! revocation classifiers in this surface:
//!
//!  - `RevocationDecision` (revocation.rs:714) — 2-variant decision
//!    (`NotRevoked` / `Revoked`) with NO `rename_all`, so the wire
//!    form is the PascalCase variant name verbatim.
//!  - `RevocationFreshnessClass` (revocation.rs:349) — 3-variant
//!    operation classifier (`Critical` / `Risky` / `Safe`) with
//!    `#[serde(rename_all = "snake_case")]` plus a hand-written
//!    `as_str()` returning the same snake_case tokens.
//!
//! `RevocationFreshnessClass` also has documented `.minimum_policy()`
//! and `.allows_policy()` truth tables — pinning these protects the
//! "host MUST NOT downgrade Critical to BestEffort" invariant.
//!
//! Targets:
//!
//!   1. **`RevocationDecision` per-variant JSON form** (PascalCase).
//!   2. **`RevocationDecision` JSON + CBOR round-trip**.
//!   3. **`RevocationFreshnessClass` per-variant JSON tag** (snake_case).
//!   4. **`RevocationFreshnessClass::as_str` agrees with serde tag**.
//!   5. **`RevocationFreshnessClass` JSON + CBOR round-trip**.
//!   6. **`RevocationFreshnessClass::minimum_policy` truth table** —
//!      Critical→Strict / Risky→Warn / Safe→BestEffort.
//!   7. **`RevocationFreshnessClass::allows_policy` truth table** —
//!      operator MUST NOT downgrade Critical to BestEffort/Warn.
//!   8. **PascalCase rejected for snake_case enum, snake_case
//!      rejected for PascalCase enum** — drift sentinel.
//!   9. **Pairwise distinctness within each enum**.
//!  10. **Cross-enum: RevocationDecision and RevocationFreshnessClass
//!      use disjoint token spaces**.

use ciborium::value::Value as CborValue;
use fcp_core::{FreshnessPolicy, RevocationDecision, RevocationFreshnessClass};

const REVOCATION_DECISION_CASES: &[(RevocationDecision, &str)] = &[
    (RevocationDecision::NotRevoked, "NotRevoked"),
    (RevocationDecision::Revoked, "Revoked"),
];

const REVOCATION_FRESHNESS_CLASS_CASES: &[(RevocationFreshnessClass, &str)] = &[
    (RevocationFreshnessClass::Critical, "critical"),
    (RevocationFreshnessClass::Risky, "risky"),
    (RevocationFreshnessClass::Safe, "safe"),
];

// ─────────────────────────────────────────────────────────────────────────────
// 1. RevocationDecision per-variant JSON form (PascalCase verbatim)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn revocation_decision_json_form_pinned_per_variant() {
    // RevocationDecision has NO #[serde(rename_all = ...)] — the
    // wire form is the PascalCase variant name verbatim. Pin
    // explicitly so any future rename_all swap is visible.
    for (variant, expected) in REVOCATION_DECISION_CASES {
        let json = serde_json::to_string(variant).expect("serialize");
        assert_eq!(
            json,
            format!("\"{expected}\""),
            "REVOCATION REGRESSION: RevocationDecision wire form drift on {variant:?} — \
             current contract is PascalCase verbatim"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. RevocationDecision JSON + CBOR round-trip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn revocation_decision_json_roundtrip_per_variant() {
    for (variant, _) in REVOCATION_DECISION_CASES {
        let json = serde_json::to_string(variant).expect("serialize");
        let back: RevocationDecision = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*variant, back);
    }
}

#[test]
fn revocation_decision_cbor_roundtrip_per_variant() {
    for (variant, _) in REVOCATION_DECISION_CASES {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(variant, &mut buf).expect("encode");
        let back: RevocationDecision = ciborium::de::from_reader(buf.as_slice()).expect("decode");
        assert_eq!(*variant, back);
    }
}

#[test]
fn revocation_decision_cbor_encodes_as_text_pascal_case() {
    for (variant, expected) in REVOCATION_DECISION_CASES {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(variant, &mut buf).expect("encode");
        let value: CborValue = ciborium::de::from_reader(buf.as_slice()).expect("decode as Value");
        match value {
            CborValue::Text(s) => assert_eq!(s, *expected),
            other => panic!("RevocationDecision MUST encode as Text({expected:?}); got {other:?}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. RevocationFreshnessClass per-variant JSON tag
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn revocation_freshness_class_json_tag_pinned_per_variant() {
    for (variant, expected) in REVOCATION_FRESHNESS_CLASS_CASES {
        let json = serde_json::to_string(variant).expect("serialize");
        assert_eq!(
            json,
            format!("\"{expected}\""),
            "RevocationFreshnessClass tag drift on {variant:?}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. RevocationFreshnessClass::as_str agrees with serde tag
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn revocation_freshness_class_as_str_agrees_with_serde_tag_byte_for_byte() {
    // The hand-written as_str() at revocation.rs:392 MUST match
    // the rename_all snake_case serde output byte-for-byte.
    for (variant, expected) in REVOCATION_FRESHNESS_CLASS_CASES {
        let stringy = variant.as_str();
        let json = serde_json::to_string(variant).expect("serialize");
        assert_eq!(stringy, *expected);
        assert_eq!(
            json.trim_matches('"'),
            stringy,
            "as_str vs serde tag drift on {variant:?}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. RevocationFreshnessClass JSON + CBOR round-trip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn revocation_freshness_class_json_roundtrip_per_variant() {
    for (variant, _) in REVOCATION_FRESHNESS_CLASS_CASES {
        let json = serde_json::to_string(variant).expect("serialize");
        let back: RevocationFreshnessClass = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*variant, back);
    }
}

#[test]
fn revocation_freshness_class_cbor_roundtrip_per_variant() {
    for (variant, _) in REVOCATION_FRESHNESS_CLASS_CASES {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(variant, &mut buf).expect("encode");
        let back: RevocationFreshnessClass =
            ciborium::de::from_reader(buf.as_slice()).expect("decode");
        assert_eq!(*variant, back);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. RevocationFreshnessClass::minimum_policy truth table
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn freshness_class_minimum_policy_truth_table() {
    // Mapping pinned by revocation.rs:366:
    //   Critical → Strict
    //   Risky    → Warn
    //   Safe     → BestEffort
    assert_eq!(
        RevocationFreshnessClass::Critical.minimum_policy(),
        FreshnessPolicy::Strict
    );
    assert_eq!(
        RevocationFreshnessClass::Risky.minimum_policy(),
        FreshnessPolicy::Warn
    );
    assert_eq!(
        RevocationFreshnessClass::Safe.minimum_policy(),
        FreshnessPolicy::BestEffort
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. RevocationFreshnessClass::allows_policy truth table
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn critical_class_only_satisfied_by_strict_policy() {
    let class = RevocationFreshnessClass::Critical;
    assert!(class.allows_policy(FreshnessPolicy::Strict));
    assert!(!class.allows_policy(FreshnessPolicy::Warn));
    assert!(!class.allows_policy(FreshnessPolicy::BestEffort));
}

#[test]
fn risky_class_satisfied_by_strict_or_warn() {
    let class = RevocationFreshnessClass::Risky;
    assert!(class.allows_policy(FreshnessPolicy::Strict));
    assert!(class.allows_policy(FreshnessPolicy::Warn));
    assert!(!class.allows_policy(FreshnessPolicy::BestEffort));
}

#[test]
fn safe_class_satisfied_by_any_policy() {
    let class = RevocationFreshnessClass::Safe;
    assert!(class.allows_policy(FreshnessPolicy::Strict));
    assert!(class.allows_policy(FreshnessPolicy::Warn));
    assert!(class.allows_policy(FreshnessPolicy::BestEffort));
}

#[test]
fn host_must_not_downgrade_critical_to_best_effort() {
    // The documented invariant at revocation.rs:341: "The host
    // MUST NOT allow an operator to downgrade a Critical operation
    // to BestEffort." Pin the truth-table entry that enforces this.
    let critical = RevocationFreshnessClass::Critical;
    assert!(
        !critical.allows_policy(FreshnessPolicy::BestEffort),
        "DOWNGRADE REGRESSION: Critical class MUST NOT accept BestEffort \
         freshness policy — operator downgrade attempt would silently bypass \
         security check"
    );
    assert!(
        !critical.allows_policy(FreshnessPolicy::Warn),
        "Critical class MUST NOT accept Warn either — only Strict satisfies"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. PascalCase / snake_case rejection per enum
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn revocation_decision_rejects_lower_snake_case() {
    // Wire form is PascalCase; lower snake_case MUST be rejected.
    for bad in [r#""not_revoked""#, r#""revoked""#, r#""""#] {
        let parsed = serde_json::from_str::<RevocationDecision>(bad);
        assert!(
            parsed.is_err(),
            "{bad} MUST be rejected — wire form is PascalCase"
        );
    }
}

#[test]
fn revocation_freshness_class_rejects_pascal_case() {
    // Wire form is snake_case; PascalCase MUST be rejected.
    for bad in [
        r#""Critical""#,
        r#""Risky""#,
        r#""Safe""#,
        r#""low""#,
        r#""""#,
    ] {
        let parsed = serde_json::from_str::<RevocationFreshnessClass>(bad);
        assert!(parsed.is_err(), "{bad} MUST be rejected");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. Pairwise distinctness within each enum
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn revocation_decision_pairwise_distinct() {
    assert_ne!(RevocationDecision::NotRevoked, RevocationDecision::Revoked);
    assert_ne!(
        serde_json::to_string(&RevocationDecision::NotRevoked).unwrap(),
        serde_json::to_string(&RevocationDecision::Revoked).unwrap()
    );
}

#[test]
fn revocation_freshness_class_pairwise_distinct() {
    let cases = [
        RevocationFreshnessClass::Critical,
        RevocationFreshnessClass::Risky,
        RevocationFreshnessClass::Safe,
    ];
    for i in 0..cases.len() {
        for j in (i + 1)..cases.len() {
            assert_ne!(cases[i], cases[j]);
        }
    }
}

#[test]
fn revocation_freshness_class_count_is_three() {
    assert_eq!(REVOCATION_FRESHNESS_CLASS_CASES.len(), 3);
}

#[test]
fn revocation_decision_count_is_two() {
    assert_eq!(REVOCATION_DECISION_CASES.len(), 2);
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. Cross-enum disjoint token spaces
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn revocation_decision_and_freshness_class_use_disjoint_token_spaces() {
    let decision_tokens: std::collections::HashSet<&str> =
        REVOCATION_DECISION_CASES.iter().map(|(_, s)| *s).collect();
    let class_tokens: std::collections::HashSet<&str> = REVOCATION_FRESHNESS_CLASS_CASES
        .iter()
        .map(|(_, s)| *s)
        .collect();
    let intersection: Vec<&&str> = decision_tokens.intersection(&class_tokens).collect();
    assert!(
        intersection.is_empty(),
        "RevocationDecision and RevocationFreshnessClass tokens MUST be disjoint; \
         got collisions: {intersection:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 11. Hash + Eq + Copy correctness
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn revocation_decision_serves_as_hashmap_key() {
    use std::collections::HashMap;
    let mut map: HashMap<RevocationDecision, &'static str> = HashMap::new();
    map.insert(RevocationDecision::NotRevoked, "not_revoked");
    map.insert(RevocationDecision::Revoked, "revoked");
    assert_eq!(map.len(), 2);
    assert_eq!(
        map.get(&RevocationDecision::NotRevoked),
        Some(&"not_revoked")
    );
}

#[test]
fn revocation_freshness_class_serves_as_hashmap_key() {
    use std::collections::HashMap;
    let mut map: HashMap<RevocationFreshnessClass, &'static str> = HashMap::new();
    for (variant, label) in REVOCATION_FRESHNESS_CLASS_CASES {
        map.insert(*variant, label);
    }
    assert_eq!(map.len(), 3);
    for (variant, label) in REVOCATION_FRESHNESS_CLASS_CASES {
        assert_eq!(map.get(variant), Some(label));
    }
}
