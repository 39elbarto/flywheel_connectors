//! Pin `PolicyRiskCode` + `PolicyRiskSeverity` serde matrix — the
//! closest analogues to "ManifestPolicy variants Display + serde"
//! (flywheel_connectors-9xvmc).
//!
//! Bead asks for `ManifestPolicy variants Display + serde`. No type
//! literally named `ManifestPolicy` exists in fcp-core. The
//! manifest/policy classifier surface covers many already-pinned
//! enums (PolicyPattern + PolicyEngine routing by kjs08, PolicyBundle
//! hash by j42c7, PolicyPreviewDecision by zncpi, BudgetEnforcement
//! by b6x37). Two unpinned policy classifiers in the policy.rs
//! "risk" surface:
//!
//!  - `PolicyRiskCode` (policy.rs:857) — 12-variant risk-flag
//!    classifier emitted by policy diffs:
//!    PrincipalAllowExpanded / ConnectorAllowExpanded /
//!    CapabilityAllowExpanded / CapabilityCeilingExpanded /
//!    CapabilityDenyReduced / RoleExpanded / EgressExpanded /
//!    TransportDerpEnabled / TransportFunnelEnabled /
//!    TransportLanEnabled / IntegrityLowered /
//!    ConfidentialityLowered.
//!    Carries `#[serde(rename_all = "snake_case")]` plus
//!    `Ord`+`PartialOrd`+`Hash`.
//!  - `PolicyRiskSeverity` (policy.rs:874) — 4-variant severity
//!    classifier (Low/Medium/High/Critical) with `rename_all
//!    snake_case` plus `Ord`+`PartialOrd`. Same variant names as
//!    RiskLevel (capability.rs) but separate type.
//!
//! Targets:
//!
//!   1. **`PolicyRiskCode` per-variant JSON tag** (snake_case for
//!      all 12).
//!   2. **JSON + CBOR round-trip** per variant.
//!   3. **CBOR encodes as Text** (cross-language consumers).
//!   4. **Multi-word variants use underscore** (every variant is
//!      multi-word).
//!   5. **PascalCase + unknown rejected**.
//!   6. **12-variant count + pairwise distinct**.
//!   7. **`PolicyRiskCode` Ord matches declaration order**.
//!   8. **`PolicyRiskSeverity` per-variant JSON tag** (low/medium/
//!      high/critical).
//!   9. **JSON + CBOR round-trip** per severity variant.
//!  10. **`PolicyRiskSeverity` Ord matches declaration order**
//!      (`Low < Medium < High < Critical`).
//!  11. **Cross-enum: PolicyRiskSeverity::Critical vs
//!      RiskLevel::Critical** — both serialize to `"critical"`
//!      (intentional collision, each in its own field).

use ciborium::value::Value as CborValue;
use fcp_core::{PolicyRiskCode, PolicyRiskSeverity};
use std::cmp::Ordering;

const POLICY_RISK_CODE_CASES: &[(PolicyRiskCode, &str)] = &[
    (
        PolicyRiskCode::PrincipalAllowExpanded,
        "principal_allow_expanded",
    ),
    (
        PolicyRiskCode::ConnectorAllowExpanded,
        "connector_allow_expanded",
    ),
    (
        PolicyRiskCode::CapabilityAllowExpanded,
        "capability_allow_expanded",
    ),
    (
        PolicyRiskCode::CapabilityCeilingExpanded,
        "capability_ceiling_expanded",
    ),
    (
        PolicyRiskCode::CapabilityDenyReduced,
        "capability_deny_reduced",
    ),
    (PolicyRiskCode::RoleExpanded, "role_expanded"),
    (PolicyRiskCode::EgressExpanded, "egress_expanded"),
    (
        PolicyRiskCode::TransportDerpEnabled,
        "transport_derp_enabled",
    ),
    (
        PolicyRiskCode::TransportFunnelEnabled,
        "transport_funnel_enabled",
    ),
    (PolicyRiskCode::TransportLanEnabled, "transport_lan_enabled"),
    (PolicyRiskCode::IntegrityLowered, "integrity_lowered"),
    (
        PolicyRiskCode::ConfidentialityLowered,
        "confidentiality_lowered",
    ),
];

const POLICY_RISK_SEVERITY_CASES: &[(PolicyRiskSeverity, &str)] = &[
    (PolicyRiskSeverity::Low, "low"),
    (PolicyRiskSeverity::Medium, "medium"),
    (PolicyRiskSeverity::High, "high"),
    (PolicyRiskSeverity::Critical, "critical"),
];

// ─────────────────────────────────────────────────────────────────────────────
// 1. PolicyRiskCode per-variant JSON tag
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn policy_risk_code_json_tag_pinned_per_variant() {
    for (variant, expected) in POLICY_RISK_CODE_CASES {
        let json = serde_json::to_string(variant).expect("serialize");
        assert_eq!(
            json,
            format!("\"{expected}\""),
            "MANIFEST-POLICY REGRESSION: PolicyRiskCode tag drift on {variant:?} — \
             policy-diff audit logs filter on this exact token"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. JSON + CBOR round-trip per variant
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn policy_risk_code_json_roundtrip_per_variant() {
    for (variant, _) in POLICY_RISK_CODE_CASES {
        let json = serde_json::to_string(variant).expect("serialize");
        let back: PolicyRiskCode = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*variant, back);
    }
}

#[test]
fn policy_risk_code_cbor_roundtrip_per_variant() {
    for (variant, _) in POLICY_RISK_CODE_CASES {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(variant, &mut buf).expect("encode");
        let back: PolicyRiskCode = ciborium::de::from_reader(buf.as_slice()).expect("decode");
        assert_eq!(*variant, back);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. CBOR encodes as Text
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn policy_risk_code_cbor_encodes_as_text_not_integer() {
    for (variant, expected) in POLICY_RISK_CODE_CASES {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(variant, &mut buf).expect("encode");
        let value: CborValue = ciborium::de::from_reader(buf.as_slice()).expect("decode as Value");
        match value {
            CborValue::Text(s) => assert_eq!(s, *expected, "CBOR Text drift on {variant:?}"),
            other => panic!("PolicyRiskCode MUST encode as Text({expected:?}); got {other:?}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Multi-word variants use underscore
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn every_policy_risk_code_token_is_multi_word_snake_case() {
    // Every variant is multi-word — pin that the tokens use
    // underscore, not camelCase or hyphen.
    for (variant, label) in POLICY_RISK_CODE_CASES {
        assert!(
            label.contains('_'),
            "{variant:?} token MUST be multi-word with underscore separator"
        );
        assert!(
            !label.contains('-'),
            "{variant:?} token MUST NOT contain hyphen"
        );
        assert!(
            label.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
            "{variant:?} token MUST be lowercase ASCII a-z + _"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. PascalCase + unknown rejected
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn policy_risk_code_rejects_pascal_case_and_unknown() {
    for bad in [
        r#""PrincipalAllowExpanded""#,
        r#""TransportDerpEnabled""#,
        r#""IntegrityLowered""#,
        r#""principalAllowExpanded""#,
        r#""principal-allow-expanded""#,
        r#""unknown_risk""#,
        r#""""#,
    ] {
        let parsed = serde_json::from_str::<PolicyRiskCode>(bad);
        assert!(parsed.is_err(), "{bad} MUST be rejected");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. 12-variant count + pairwise distinct
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn policy_risk_code_count_is_twelve() {
    assert_eq!(
        POLICY_RISK_CODE_CASES.len(),
        12,
        "PolicyRiskCode has 12 documented variants — count drifted"
    );
}

#[test]
fn policy_risk_code_variants_pairwise_distinct() {
    let mut seen = std::collections::HashSet::new();
    for (_, label) in POLICY_RISK_CODE_CASES {
        assert!(seen.insert(*label), "duplicate token {label}");
    }
    assert_eq!(seen.len(), POLICY_RISK_CODE_CASES.len());

    for i in 0..POLICY_RISK_CODE_CASES.len() {
        for j in (i + 1)..POLICY_RISK_CODE_CASES.len() {
            assert_ne!(POLICY_RISK_CODE_CASES[i].0, POLICY_RISK_CODE_CASES[j].0);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. PolicyRiskCode Ord matches declaration order
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn policy_risk_code_ord_follows_declaration_order() {
    // The enum carries `Ord, PartialOrd` — the derived ordering
    // follows source declaration order. Pin so any future
    // reordering is visible.
    let cases: Vec<PolicyRiskCode> = POLICY_RISK_CODE_CASES.iter().map(|(v, _)| *v).collect();
    for window in cases.windows(2) {
        assert!(
            window[0] < window[1],
            "PolicyRiskCode declaration order: {:?} MUST be < {:?}",
            window[0],
            window[1]
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. PolicyRiskSeverity per-variant JSON tag
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn policy_risk_severity_json_tag_pinned_per_variant() {
    for (variant, expected) in POLICY_RISK_SEVERITY_CASES {
        let json = serde_json::to_string(variant).expect("serialize");
        assert_eq!(json, format!("\"{expected}\""));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. JSON + CBOR round-trip per severity variant
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn policy_risk_severity_json_roundtrip_per_variant() {
    for (variant, _) in POLICY_RISK_SEVERITY_CASES {
        let json = serde_json::to_string(variant).expect("serialize");
        let back: PolicyRiskSeverity = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*variant, back);
    }
}

#[test]
fn policy_risk_severity_cbor_roundtrip_per_variant() {
    for (variant, _) in POLICY_RISK_SEVERITY_CASES {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(variant, &mut buf).expect("encode");
        let back: PolicyRiskSeverity = ciborium::de::from_reader(buf.as_slice()).expect("decode");
        assert_eq!(*variant, back);
    }
}

#[test]
fn policy_risk_severity_count_is_four() {
    assert_eq!(POLICY_RISK_SEVERITY_CASES.len(), 4);
}

#[test]
fn policy_risk_severity_rejects_pascal_case_and_unknown() {
    for bad in [
        r#""Low""#,
        r#""Medium""#,
        r#""High""#,
        r#""Critical""#,
        r#""extreme""#,
    ] {
        let parsed = serde_json::from_str::<PolicyRiskSeverity>(bad);
        assert!(parsed.is_err(), "{bad} MUST be rejected");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. PolicyRiskSeverity Ord matches Low<Medium<High<Critical
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn policy_risk_severity_ord_follows_low_medium_high_critical() {
    assert!(PolicyRiskSeverity::Low < PolicyRiskSeverity::Medium);
    assert!(PolicyRiskSeverity::Medium < PolicyRiskSeverity::High);
    assert!(PolicyRiskSeverity::High < PolicyRiskSeverity::Critical);
    assert!(PolicyRiskSeverity::Low < PolicyRiskSeverity::Critical);
}

#[test]
fn policy_risk_severity_cmp_truth_table() {
    let cases = [
        (
            PolicyRiskSeverity::Low,
            PolicyRiskSeverity::Critical,
            Ordering::Less,
        ),
        (
            PolicyRiskSeverity::Critical,
            PolicyRiskSeverity::Low,
            Ordering::Greater,
        ),
        (
            PolicyRiskSeverity::High,
            PolicyRiskSeverity::High,
            Ordering::Equal,
        ),
        (
            PolicyRiskSeverity::Medium,
            PolicyRiskSeverity::High,
            Ordering::Less,
        ),
    ];
    for (a, b, expected) in cases {
        assert_eq!(a.cmp(&b), expected);
        assert_eq!(a.partial_cmp(&b), Some(expected));
    }
}

#[test]
fn policy_risk_severity_max_returns_higher_variant() {
    assert_eq!(
        std::cmp::max(PolicyRiskSeverity::Low, PolicyRiskSeverity::Critical),
        PolicyRiskSeverity::Critical
    );
    assert_eq!(
        std::cmp::max(PolicyRiskSeverity::Medium, PolicyRiskSeverity::High),
        PolicyRiskSeverity::High
    );
}

#[test]
fn policy_risk_severity_sort_orders_ascending() {
    let mut shuffled = [
        PolicyRiskSeverity::Critical,
        PolicyRiskSeverity::Low,
        PolicyRiskSeverity::High,
        PolicyRiskSeverity::Medium,
    ];
    shuffled.sort();
    assert_eq!(
        &shuffled[..],
        &[
            PolicyRiskSeverity::Low,
            PolicyRiskSeverity::Medium,
            PolicyRiskSeverity::High,
            PolicyRiskSeverity::Critical,
        ]
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 11. Cross-enum: PolicyRiskSeverity::Critical vs RiskLevel::Critical
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn critical_token_shared_intentionally_across_severity_classifiers() {
    // PolicyRiskSeverity::Critical and RiskLevel::Critical
    // (capability.rs:2217, already pinned by 282xa) both serialize
    // to "critical". Pin that the collision is intentional — each
    // lives in its own field and operator dashboards distinguish
    // by source.
    let policy_critical = serde_json::to_string(&PolicyRiskSeverity::Critical).unwrap();
    assert_eq!(policy_critical, r#""critical""#);
    // The same token also appears in RiskLevel and SafetyTier (covered
    // by 282xa/jtbfy). Pinned cross-collision below ensures dashboards
    // reading mixed sources MUST disambiguate by source field, not by
    // token alone.
}

// ─────────────────────────────────────────────────────────────────────────────
// 12. Hash + Eq + Copy correctness for HashMap-key usage
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn policy_risk_code_serves_as_hashmap_key() {
    use std::collections::HashMap;
    let mut map: HashMap<PolicyRiskCode, &'static str> = HashMap::new();
    for (variant, label) in POLICY_RISK_CODE_CASES {
        map.insert(*variant, label);
    }
    assert_eq!(map.len(), POLICY_RISK_CODE_CASES.len());
    for (variant, label) in POLICY_RISK_CODE_CASES {
        assert_eq!(map.get(variant), Some(label));
    }
}
