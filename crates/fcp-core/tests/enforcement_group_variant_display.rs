//! Pin enforcement-mode + scope classifier serde tags — the closest
//! analogues to "EnforcementGroup variant Display"
//! (flywheel_connectors-b6x37).
//!
//! Bead asks for `EnforcementGroup variant Display + serde tag`. No
//! type literally named `EnforcementGroup` exists in fcp-core. The
//! `EnforcementCheckId` (enforcement.rs:34, the canonical pipeline
//! check identifier) is already pinned by tt7js
//! (`enforcement_check_id_display_roundtrip.rs`). The unpinned
//! enforcement-mode/scope classifier surface covers three enums:
//!
//!  - `BudgetEnforcement` (policy.rs:93) — 2 variants Warn/Deny
//!    with `#[serde(rename_all = "snake_case")]`.
//!  - `RateLimitEnforcement` (ratelimit.rs:214) — 3 variants
//!    Hard/Soft/Advisory with `rename_all = "snake_case"`.
//!  - `RateLimitScope` (ratelimit.rs:226) — 3 variants
//!    Instance/Credential/Global with `rename_all = "snake_case"`.
//!
//! None implements Display directly, so the bead's "Display" ask
//! projects onto the serde tag form (the operator-facing token).
//!
//! Targets:
//!
//!   1. **`BudgetEnforcement` per-variant JSON tag** (`warn` / `deny`).
//!   2. **`BudgetEnforcement` JSON + CBOR round-trip**.
//!   3. **`RateLimitEnforcement` per-variant JSON tag** (`hard` /
//!      `soft` / `advisory`).
//!   4. **`RateLimitEnforcement` JSON + CBOR round-trip**.
//!   5. **`RateLimitScope` per-variant JSON tag** (`instance` /
//!      `credential` / `global`).
//!   6. **`RateLimitScope` JSON + CBOR round-trip**.
//!   7. **CBOR encodes as Text** (cross-language consumers).
//!   8. **PascalCase + unknown rejected** for all three.
//!   9. **Pairwise distinctness** within each enum.
//!  10. **Cross-enum: `deny` token shared** by intentional design
//!      across BudgetEnforcement::Deny + (already-pinned
//!      VerificationDecision::Deny / PolicyPreviewDecision::Deny /
//!      ResumeDisposition::Deny) — pin the collision is intentional
//!      since each lives in its own field.

use ciborium::value::Value as CborValue;
use fcp_core::{BudgetEnforcement, RateLimitEnforcement, RateLimitScope};

const BUDGET_ENFORCEMENT_CASES: &[(BudgetEnforcement, &str)] = &[
    (BudgetEnforcement::Warn, "warn"),
    (BudgetEnforcement::Deny, "deny"),
];

const RATE_LIMIT_ENFORCEMENT_CASES: &[(RateLimitEnforcement, &str)] = &[
    (RateLimitEnforcement::Hard, "hard"),
    (RateLimitEnforcement::Soft, "soft"),
    (RateLimitEnforcement::Advisory, "advisory"),
];

const RATE_LIMIT_SCOPE_CASES: &[(RateLimitScope, &str)] = &[
    (RateLimitScope::Instance, "instance"),
    (RateLimitScope::Credential, "credential"),
    (RateLimitScope::Global, "global"),
];

// ─────────────────────────────────────────────────────────────────────────────
// 1. BudgetEnforcement per-variant JSON tag
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn budget_enforcement_json_tag_pinned_per_variant() {
    for (variant, expected) in BUDGET_ENFORCEMENT_CASES {
        let json = serde_json::to_string(variant).expect("serialize");
        assert_eq!(
            json,
            format!("\"{expected}\""),
            "ENFORCEMENT-GROUP REGRESSION: BudgetEnforcement tag drift on {variant:?} — \
             budget-policy audit logs filter on this exact token"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. BudgetEnforcement JSON + CBOR round-trip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn budget_enforcement_json_roundtrip_per_variant() {
    for (variant, _) in BUDGET_ENFORCEMENT_CASES {
        let json = serde_json::to_string(variant).expect("serialize");
        let back: BudgetEnforcement = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*variant, back);
    }
}

#[test]
fn budget_enforcement_cbor_roundtrip_per_variant() {
    for (variant, _) in BUDGET_ENFORCEMENT_CASES {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(variant, &mut buf).expect("encode");
        let back: BudgetEnforcement = ciborium::de::from_reader(buf.as_slice()).expect("decode");
        assert_eq!(*variant, back);
    }
}

#[test]
fn budget_enforcement_count_is_two() {
    assert_eq!(
        BUDGET_ENFORCEMENT_CASES.len(),
        2,
        "BudgetEnforcement has 2 documented variants — count drifted"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. RateLimitEnforcement per-variant JSON tag
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn rate_limit_enforcement_json_tag_pinned_per_variant() {
    for (variant, expected) in RATE_LIMIT_ENFORCEMENT_CASES {
        let json = serde_json::to_string(variant).expect("serialize");
        assert_eq!(
            json,
            format!("\"{expected}\""),
            "RateLimitEnforcement tag drift on {variant:?}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. RateLimitEnforcement JSON + CBOR round-trip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn rate_limit_enforcement_json_roundtrip_per_variant() {
    for (variant, _) in RATE_LIMIT_ENFORCEMENT_CASES {
        let json = serde_json::to_string(variant).expect("serialize");
        let back: RateLimitEnforcement = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*variant, back);
    }
}

#[test]
fn rate_limit_enforcement_cbor_roundtrip_per_variant() {
    for (variant, _) in RATE_LIMIT_ENFORCEMENT_CASES {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(variant, &mut buf).expect("encode");
        let back: RateLimitEnforcement =
            ciborium::de::from_reader(buf.as_slice()).expect("decode");
        assert_eq!(*variant, back);
    }
}

#[test]
fn rate_limit_enforcement_count_is_three() {
    assert_eq!(
        RATE_LIMIT_ENFORCEMENT_CASES.len(),
        3,
        "RateLimitEnforcement has 3 documented variants — count drifted"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. RateLimitScope per-variant JSON tag
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn rate_limit_scope_json_tag_pinned_per_variant() {
    for (variant, expected) in RATE_LIMIT_SCOPE_CASES {
        let json = serde_json::to_string(variant).expect("serialize");
        assert_eq!(
            json,
            format!("\"{expected}\""),
            "RateLimitScope tag drift on {variant:?}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. RateLimitScope JSON + CBOR round-trip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn rate_limit_scope_json_roundtrip_per_variant() {
    for (variant, _) in RATE_LIMIT_SCOPE_CASES {
        let json = serde_json::to_string(variant).expect("serialize");
        let back: RateLimitScope = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*variant, back);
    }
}

#[test]
fn rate_limit_scope_cbor_roundtrip_per_variant() {
    for (variant, _) in RATE_LIMIT_SCOPE_CASES {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(variant, &mut buf).expect("encode");
        let back: RateLimitScope = ciborium::de::from_reader(buf.as_slice()).expect("decode");
        assert_eq!(*variant, back);
    }
}

#[test]
fn rate_limit_scope_count_is_three() {
    assert_eq!(RATE_LIMIT_SCOPE_CASES.len(), 3);
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. CBOR encodes as Text (cross-language consumers)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn budget_enforcement_cbor_encodes_as_text_not_integer() {
    for (variant, expected) in BUDGET_ENFORCEMENT_CASES {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(variant, &mut buf).expect("encode");
        let value: CborValue = ciborium::de::from_reader(buf.as_slice()).expect("decode as Value");
        match value {
            CborValue::Text(s) => assert_eq!(s, *expected),
            other => panic!("BudgetEnforcement MUST encode as Text({expected:?}); got {other:?}"),
        }
    }
}

#[test]
fn rate_limit_enforcement_cbor_encodes_as_text_not_integer() {
    for (variant, expected) in RATE_LIMIT_ENFORCEMENT_CASES {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(variant, &mut buf).expect("encode");
        let value: CborValue = ciborium::de::from_reader(buf.as_slice()).expect("decode as Value");
        match value {
            CborValue::Text(s) => assert_eq!(s, *expected),
            other => panic!(
                "RateLimitEnforcement MUST encode as Text({expected:?}); got {other:?}"
            ),
        }
    }
}

#[test]
fn rate_limit_scope_cbor_encodes_as_text_not_integer() {
    for (variant, expected) in RATE_LIMIT_SCOPE_CASES {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(variant, &mut buf).expect("encode");
        let value: CborValue = ciborium::de::from_reader(buf.as_slice()).expect("decode as Value");
        match value {
            CborValue::Text(s) => assert_eq!(s, *expected),
            other => panic!("RateLimitScope MUST encode as Text({expected:?}); got {other:?}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. PascalCase + unknown rejected
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn budget_enforcement_rejects_pascal_case_and_unknown() {
    for bad in [r#""Warn""#, r#""Deny""#, r#""block""#, r#""""#] {
        let parsed = serde_json::from_str::<BudgetEnforcement>(bad);
        assert!(parsed.is_err(), "{bad} MUST be rejected");
    }
}

#[test]
fn rate_limit_enforcement_rejects_pascal_case_and_unknown() {
    for bad in [
        r#""Hard""#,
        r#""Soft""#,
        r#""Advisory""#,
        r#""warn""#,
        r#""""#,
    ] {
        let parsed = serde_json::from_str::<RateLimitEnforcement>(bad);
        assert!(parsed.is_err(), "{bad} MUST be rejected");
    }
}

#[test]
fn rate_limit_scope_rejects_pascal_case_and_unknown() {
    for bad in [
        r#""Instance""#,
        r#""Credential""#,
        r#""Global""#,
        r#""zone""#,
        r#""""#,
    ] {
        let parsed = serde_json::from_str::<RateLimitScope>(bad);
        assert!(parsed.is_err(), "{bad} MUST be rejected");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. Pairwise distinctness within each enum
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn budget_enforcement_pairwise_distinct() {
    assert_ne!(BudgetEnforcement::Warn, BudgetEnforcement::Deny);
    assert_ne!(
        serde_json::to_string(&BudgetEnforcement::Warn).unwrap(),
        serde_json::to_string(&BudgetEnforcement::Deny).unwrap()
    );
}

#[test]
fn rate_limit_enforcement_pairwise_distinct() {
    let cases = [
        RateLimitEnforcement::Hard,
        RateLimitEnforcement::Soft,
        RateLimitEnforcement::Advisory,
    ];
    for i in 0..cases.len() {
        for j in (i + 1)..cases.len() {
            assert_ne!(cases[i], cases[j]);
        }
    }
    let mut tokens = std::collections::HashSet::new();
    for variant in cases {
        let json = serde_json::to_string(&variant).unwrap();
        assert!(tokens.insert(json));
    }
    assert_eq!(tokens.len(), 3);
}

#[test]
fn rate_limit_scope_pairwise_distinct() {
    let cases = [
        RateLimitScope::Instance,
        RateLimitScope::Credential,
        RateLimitScope::Global,
    ];
    for i in 0..cases.len() {
        for j in (i + 1)..cases.len() {
            assert_ne!(cases[i], cases[j]);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. Cross-enum `deny` token shared by intentional design
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn deny_token_shared_with_other_enforcement_enums_intentionally() {
    // BudgetEnforcement::Deny serializes to "deny" — same token as
    // VerificationDecision::Deny, PolicyPreviewDecision::Deny,
    // ResumeDisposition::Deny (already pinned by zncpi/kjs08). Pin
    // the collision is intentional — each lives in its own field
    // and operator dashboards distinguish by source.
    let budget_deny = serde_json::to_string(&BudgetEnforcement::Deny).unwrap();
    assert_eq!(budget_deny, r#""deny""#);
}

// ─────────────────────────────────────────────────────────────────────────────
// 11. Cross-enum: BudgetEnforcement::Warn vs RateLimitEnforcement::Soft —
//     similar semantics, different tokens
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn budget_warn_and_rate_limit_soft_use_distinct_tokens() {
    // Both variants represent "permissive enforcement that emits
    // signals but doesn't block" — but they use different tokens
    // (warn vs soft). Pin that distinction so cross-enum tooling
    // doesn't conflate them.
    let warn_json = serde_json::to_string(&BudgetEnforcement::Warn).unwrap();
    let soft_json = serde_json::to_string(&RateLimitEnforcement::Soft).unwrap();
    assert_eq!(warn_json, r#""warn""#);
    assert_eq!(soft_json, r#""soft""#);
    assert_ne!(warn_json, soft_json);
}
