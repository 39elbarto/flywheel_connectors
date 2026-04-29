//! Pin the closest analogue to a "CapabilityType" serde tag matrix
//! (flywheel_connectors-282xa).
//!
//! Bead asks for "CapabilityType serde tag JSON+CBOR roundtrip per
//! documented contract". No type literally named `CapabilityType`
//! exists in fcp-core. The capability surface in fcp-core has
//! several classifier enums, each with `#[serde(rename_all =
//! "snake_case")]`:
//!
//!  - `SafetyTier` (capability.rs:2240) — 5 variants
//!    (Safe/Risky/Dangerous/Critical/Forbidden). Classifies
//!    "can this agent do this?" — the closest "CapabilityType"
//!    analogue and the one wired into `OperationMeta.safety_tier`,
//!    `ToolDescriptor.safety_tier`, and CLI filters.
//!  - `RiskLevel` (capability.rs:2217) — 4 variants
//!    (Low/Medium/High/Critical).
//!  - `IdempotencyClass` (capability.rs:2256) — 3 variants
//!    (None/BestEffort/Strict).
//!
//! This test pins the JSON+CBOR tag matrix for ALL THREE classifier
//! enums (SafetyTier as the primary, RiskLevel + IdempotencyClass as
//! the rest of the capability-typing surface), since drift in any of
//! them silently breaks operator dashboards and audit-log filtering.
//!
//! Targets per enum:
//!
//!   1. **Per-variant JSON tag form** in snake_case.
//!   2. **JSON round-trip** preserves variant identity.
//!   3. **CBOR round-trip** preserves variant identity.
//!   4. **CBOR encodes as Text(snake_case)**, not as integer/array.
//!   5. **PascalCase + unknown rejected** — only documented snake_case
//!      tokens are canonical wire input.
//!   6. **All variants pairwise distinct** (Eq + serialized form).

use ciborium::value::Value as CborValue;
use fcp_core::{IdempotencyClass, RiskLevel, SafetyTier};

// ─────────────────────────────────────────────────────────────────────────────
// SafetyTier — primary CapabilityType analogue
// ─────────────────────────────────────────────────────────────────────────────

const SAFETY_TIER_CASES: &[(SafetyTier, &str)] = &[
    (SafetyTier::Safe, "safe"),
    (SafetyTier::Risky, "risky"),
    (SafetyTier::Dangerous, "dangerous"),
    (SafetyTier::Critical, "critical"),
    (SafetyTier::Forbidden, "forbidden"),
];

#[test]
fn safety_tier_json_form_pinned_per_variant() {
    for (variant, expected) in SAFETY_TIER_CASES {
        let json = serde_json::to_string(variant).expect("serialize");
        assert_eq!(
            json,
            format!("\"{expected}\""),
            "SafetyTier JSON tag drift on {variant:?} — operator \
             dashboards / CLI filters consume this exact token"
        );
    }
}

#[test]
fn safety_tier_json_roundtrip_preserves_variant() {
    for (variant, _) in SAFETY_TIER_CASES {
        let json = serde_json::to_string(variant).expect("serialize");
        let back: SafetyTier = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*variant, back, "JSON round-trip lost {variant:?}");
    }
}

#[test]
fn safety_tier_cbor_roundtrip_preserves_variant() {
    for (variant, _) in SAFETY_TIER_CASES {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(variant, &mut buf).expect("encode");
        let back: SafetyTier = ciborium::de::from_reader(buf.as_slice()).expect("decode");
        assert_eq!(*variant, back, "CBOR round-trip lost {variant:?}");
    }
}

#[test]
fn safety_tier_cbor_encodes_as_text_not_integer() {
    // The serde rename_all means the on-wire CBOR form is the
    // snake_case Text — not a numeric discriminant. Pin that
    // because cross-language consumers (Python, TypeScript)
    // dispatch on the string form.
    for (variant, expected) in SAFETY_TIER_CASES {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(variant, &mut buf).expect("encode");
        let value: CborValue = ciborium::de::from_reader(buf.as_slice()).expect("decode as Value");
        match value {
            CborValue::Text(s) => {
                assert_eq!(s, *expected, "SafetyTier CBOR Text drift on {variant:?}")
            }
            other => panic!("SafetyTier CBOR MUST encode as Text({expected:?}); got {other:?}"),
        }
    }
}

#[test]
fn safety_tier_rejects_pascal_case_and_unknown() {
    for bad in [
        r#""Safe""#,
        r#""Risky""#,
        r#""DANGEROUS""#,
        r#""banned""#,
        r#""""#,
    ] {
        let parsed = serde_json::from_str::<SafetyTier>(bad);
        assert!(
            parsed.is_err(),
            "{bad} MUST be rejected — only documented snake_case is canonical"
        );
    }
}

#[test]
fn safety_tier_variants_pairwise_distinct() {
    let mut seen_jsons = std::collections::HashSet::new();
    for (variant, _) in SAFETY_TIER_CASES {
        let json = serde_json::to_string(variant).expect("serialize");
        assert!(
            seen_jsons.insert(json.clone()),
            "duplicate JSON form {json}"
        );
    }
    assert_eq!(seen_jsons.len(), SAFETY_TIER_CASES.len());

    for i in 0..SAFETY_TIER_CASES.len() {
        for j in (i + 1)..SAFETY_TIER_CASES.len() {
            assert_ne!(
                SAFETY_TIER_CASES[i].0, SAFETY_TIER_CASES[j].0,
                "{:?} and {:?} MUST be distinct",
                SAFETY_TIER_CASES[i].0, SAFETY_TIER_CASES[j].0
            );
        }
    }
}

#[test]
fn safety_tier_documented_count_is_five() {
    assert_eq!(
        SAFETY_TIER_CASES.len(),
        5,
        "SafetyTier has 5 documented variants — count drifted"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// RiskLevel — secondary classifier on capabilities
// ─────────────────────────────────────────────────────────────────────────────

const RISK_LEVEL_CASES: &[(RiskLevel, &str)] = &[
    (RiskLevel::Low, "low"),
    (RiskLevel::Medium, "medium"),
    (RiskLevel::High, "high"),
    (RiskLevel::Critical, "critical"),
];

#[test]
fn risk_level_json_form_pinned_per_variant() {
    for (variant, expected) in RISK_LEVEL_CASES {
        let json = serde_json::to_string(variant).expect("serialize");
        assert_eq!(
            json,
            format!("\"{expected}\""),
            "RiskLevel JSON tag drift on {variant:?}"
        );
    }
}

#[test]
fn risk_level_json_and_cbor_roundtrip() {
    for (variant, _) in RISK_LEVEL_CASES {
        // JSON
        let json = serde_json::to_string(variant).expect("JSON serialize");
        let from_json: RiskLevel = serde_json::from_str(&json).expect("JSON deserialize");
        assert_eq!(*variant, from_json);

        // CBOR
        let mut buf = Vec::new();
        ciborium::ser::into_writer(variant, &mut buf).expect("CBOR encode");
        let from_cbor: RiskLevel = ciborium::de::from_reader(buf.as_slice()).expect("CBOR decode");
        assert_eq!(*variant, from_cbor);
    }
}

#[test]
fn risk_level_rejects_pascal_case() {
    for bad in [r#""Low""#, r#""High""#, r#""LOW""#, r#""extreme""#] {
        let parsed = serde_json::from_str::<RiskLevel>(bad);
        assert!(parsed.is_err(), "{bad} MUST be rejected");
    }
}

#[test]
fn risk_level_critical_collides_with_safety_tier_critical_token() {
    // Both `RiskLevel::Critical` and `SafetyTier::Critical` serialize
    // to the same `"critical"` token. Pin that — the collision is
    // intentional (each enum lives in its own field), but if downstream
    // tooling ever conflates the two by token alone, this test
    // surfaces the structural overlap.
    let r = serde_json::to_string(&RiskLevel::Critical).unwrap();
    let s = serde_json::to_string(&SafetyTier::Critical).unwrap();
    assert_eq!(r, s);
    assert_eq!(r, r#""critical""#);
}

// ─────────────────────────────────────────────────────────────────────────────
// IdempotencyClass — third classifier on capabilities
// ─────────────────────────────────────────────────────────────────────────────

const IDEMPOTENCY_CASES: &[(IdempotencyClass, &str)] = &[
    (IdempotencyClass::None, "none"),
    (IdempotencyClass::BestEffort, "best_effort"),
    (IdempotencyClass::Strict, "strict"),
];

#[test]
fn idempotency_class_json_form_pinned_per_variant() {
    for (variant, expected) in IDEMPOTENCY_CASES {
        let json = serde_json::to_string(variant).expect("serialize");
        assert_eq!(
            json,
            format!("\"{expected}\""),
            "IdempotencyClass tag drift on {variant:?}"
        );
    }
}

#[test]
fn idempotency_class_best_effort_uses_underscore_not_hyphen() {
    // snake_case rename — multi-word variants use `_`, not `-`.
    let json = serde_json::to_string(&IdempotencyClass::BestEffort).unwrap();
    assert_eq!(json, r#""best_effort""#);
    assert!(!json.contains('-'), "snake_case MUST NOT contain hyphens");
}

#[test]
fn idempotency_class_json_and_cbor_roundtrip() {
    for (variant, _) in IDEMPOTENCY_CASES {
        let json = serde_json::to_string(variant).expect("JSON serialize");
        let from_json: IdempotencyClass = serde_json::from_str(&json).expect("JSON deserialize");
        assert_eq!(*variant, from_json);

        let mut buf = Vec::new();
        ciborium::ser::into_writer(variant, &mut buf).expect("CBOR encode");
        let from_cbor: IdempotencyClass =
            ciborium::de::from_reader(buf.as_slice()).expect("CBOR decode");
        assert_eq!(*variant, from_cbor);
    }
}

#[test]
fn idempotency_class_rejects_pascal_case_and_kebab_case() {
    for bad in [
        r#""None""#,
        r#""BestEffort""#,
        r#""best-effort""#,
        r#""Strict""#,
    ] {
        let parsed = serde_json::from_str::<IdempotencyClass>(bad);
        assert!(
            parsed.is_err(),
            "{bad} MUST be rejected — neither PascalCase nor kebab-case is canonical"
        );
    }
}

#[test]
fn idempotency_class_none_token_does_not_alias_serde_unit() {
    // The literal `"none"` token is the IdempotencyClass::None
    // variant — NOT a serde `null`. Pin that mistake (decoding
    // null → IdempotencyClass MUST fail).
    let bad_null = serde_json::from_str::<IdempotencyClass>("null");
    assert!(
        bad_null.is_err(),
        "JSON null MUST NOT alias to IdempotencyClass::None — \
         only the explicit \"none\" string maps to that variant"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Cross-enum: snake_case format invariants are uniform
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn every_capability_classifier_token_is_snake_case_lowercase_ascii() {
    // Walk every variant of every classifier — pin that none of
    // them ever contained accidental uppercase, hyphens, or non-ASCII.
    fn check(label: &str) {
        assert!(
            label.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
            "token {label:?} contains non-snake_case characters"
        );
        assert!(!label.is_empty(), "token MUST be non-empty");
        assert!(
            !label.starts_with('_') && !label.ends_with('_'),
            "token {label:?} MUST NOT start/end with `_`"
        );
        assert!(
            !label.contains("__"),
            "token {label:?} MUST NOT contain `__`"
        );
    }
    for (_, label) in SAFETY_TIER_CASES {
        check(label);
    }
    for (_, label) in RISK_LEVEL_CASES {
        check(label);
    }
    for (_, label) in IDEMPOTENCY_CASES {
        check(label);
    }
}
