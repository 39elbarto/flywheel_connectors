//! Pin `PrerequisiteStatus` serde tag + DescriptorStatus conversion
//! mapping — the closest analogues to "ConnectorActivationStage"
//! (flywheel_connectors-nhms0).
//!
//! Bead asks for `ConnectorActivationStage Display + serde tag`. No
//! type literally named `ConnectorActivationStage` exists in
//! fcp-core. The activation-stage-shaped surface in fcp-core covers:
//!
//!  - `ConnectorLifecycleState` (connector.rs:180) — 5 variants
//!    Loaded/Activated/Running/Suspended/Terminated. Already pinned
//!    by `connector_lifecycle_state_display.rs`.
//!  - `PrerequisiteStatus` (connector_descriptors.rs:355) — 7
//!    variants describing "what stage is the prerequisite at?":
//!    Satisfied / Missing / Drifted / Unverifiable / PolicyBlocked /
//!    NotYetMeasured / Unavailable. NOT yet pinned.
//!  - `DescriptorStatus` (connector_descriptors.rs:23) — 11-variant
//!    superset already pinned by `live_status_serde_tag_matrix.rs`.
//!  - `ProvisioningStatus` (provisioning.rs:489) — already pinned
//!    by `connector_plan_step_ordering.rs`.
//!
//! `PrerequisiteStatus` is the closest "activation stage" analogue
//! — it's the per-prerequisite stage during connector onboarding/
//! activation, with a documented `From<PrerequisiteStatus>` →
//! `DescriptorStatus` projection at connector_descriptors.rs:372.
//!
//! Targets:
//!
//!   1. **Per-variant JSON tag** in snake_case (`satisfied` /
//!      `missing` / `drifted` / `unverifiable` / `policy_blocked`
//!      / `not_yet_measured` / `unavailable`).
//!   2. **JSON + CBOR round-trip** per variant.
//!   3. **CBOR encodes as Text** (cross-language consumers).
//!   4. **Multi-word variant uses underscore** for `policy_blocked`
//!      and `not_yet_measured`.
//!   5. **PascalCase + unknown rejected** — drift sentinel.
//!   6. **7-variant count + pairwise distinct**.
//!   7. **`From<PrerequisiteStatus>` → `DescriptorStatus`** truth
//!      table — every PrerequisiteStatus variant projects to its
//!      documented DescriptorStatus counterpart (the lossy mapping
//!      that operator dashboards use to roll up prerequisite stages
//!      into descriptor-level health).
//!   8. **DescriptorStatus tokens for the projected variants match
//!      PrerequisiteStatus tokens** byte-for-byte where the
//!      mapping name matches (Missing / Drifted / Unverifiable /
//!      PolicyBlocked / NotYetMeasured / Unavailable).

use ciborium::value::Value as CborValue;
use fcp_core::{DescriptorStatus, PrerequisiteStatus};

const ALL_STATUSES: &[(PrerequisiteStatus, &str)] = &[
    (PrerequisiteStatus::Satisfied, "satisfied"),
    (PrerequisiteStatus::Missing, "missing"),
    (PrerequisiteStatus::Drifted, "drifted"),
    (PrerequisiteStatus::Unverifiable, "unverifiable"),
    (PrerequisiteStatus::PolicyBlocked, "policy_blocked"),
    (PrerequisiteStatus::NotYetMeasured, "not_yet_measured"),
    (PrerequisiteStatus::Unavailable, "unavailable"),
];

// ─────────────────────────────────────────────────────────────────────────────
// 1. Per-variant JSON tag
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn prerequisite_status_json_tag_pinned_per_variant() {
    for (variant, expected) in ALL_STATUSES {
        let json = serde_json::to_string(variant).expect("serialize");
        assert_eq!(
            json,
            format!("\"{expected}\""),
            "ACTIVATION-STAGE REGRESSION: PrerequisiteStatus JSON tag drift on {variant:?} — \
             onboarding dashboards filter on this exact token"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. JSON + CBOR round-trip per variant
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn prerequisite_status_json_roundtrip_per_variant() {
    for (variant, _) in ALL_STATUSES {
        let json = serde_json::to_string(variant).expect("serialize");
        let back: PrerequisiteStatus = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*variant, back);
    }
}

#[test]
fn prerequisite_status_cbor_roundtrip_per_variant() {
    for (variant, _) in ALL_STATUSES {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(variant, &mut buf).expect("encode");
        let back: PrerequisiteStatus = ciborium::de::from_reader(buf.as_slice()).expect("decode");
        assert_eq!(*variant, back);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. CBOR encodes as Text not integer
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn prerequisite_status_cbor_encodes_as_text_not_integer() {
    for (variant, expected) in ALL_STATUSES {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(variant, &mut buf).expect("encode");
        let value: CborValue = ciborium::de::from_reader(buf.as_slice()).expect("decode as Value");
        match value {
            CborValue::Text(s) => assert_eq!(s, *expected, "CBOR Text drift on {variant:?}"),
            other => panic!(
                "PrerequisiteStatus MUST encode as CBOR Text({expected:?}); got {other:?}"
            ),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Multi-word variants use underscore
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn policy_blocked_uses_underscore_not_hyphen_or_smush() {
    let json = serde_json::to_string(&PrerequisiteStatus::PolicyBlocked).unwrap();
    assert_eq!(json, r#""policy_blocked""#);
    assert!(!json.contains('-'), "snake_case MUST NOT use hyphens");
    assert_ne!(json, r#""policyblocked""#);
    assert_ne!(json, r#""policyBlocked""#);
}

#[test]
fn not_yet_measured_uses_double_underscore_separator() {
    let json = serde_json::to_string(&PrerequisiteStatus::NotYetMeasured).unwrap();
    assert_eq!(
        json, r#""not_yet_measured""#,
        "Three-word variant MUST be `not_yet_measured` not `notYetMeasured` or `not-yet-measured`"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. PascalCase + unknown rejected
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn prerequisite_status_rejects_pascal_case_and_unknown() {
    for bad in [
        r#""Satisfied""#,
        r#""PolicyBlocked""#,
        r#""NotYetMeasured""#,
        r#""policy-blocked""#,
        r#""policyBlocked""#,
        r#""ready""#,
        r#""""#,
    ] {
        let parsed = serde_json::from_str::<PrerequisiteStatus>(bad);
        assert!(
            parsed.is_err(),
            "{bad} MUST be rejected — only documented snake_case is canonical"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. 7-variant count + pairwise distinct
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn prerequisite_status_documented_count_is_seven() {
    assert_eq!(
        ALL_STATUSES.len(),
        7,
        "PrerequisiteStatus has 7 documented variants — count drifted"
    );
}

#[test]
fn prerequisite_status_variants_pairwise_distinct() {
    let mut seen = std::collections::HashSet::new();
    for (_, label) in ALL_STATUSES {
        assert!(seen.insert(*label), "duplicate token {label}");
    }
    assert_eq!(seen.len(), ALL_STATUSES.len());

    for i in 0..ALL_STATUSES.len() {
        for j in (i + 1)..ALL_STATUSES.len() {
            assert_ne!(
                ALL_STATUSES[i].0, ALL_STATUSES[j].0,
                "{:?} and {:?} MUST be distinct",
                ALL_STATUSES[i].0, ALL_STATUSES[j].0
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. From<PrerequisiteStatus> → DescriptorStatus truth table
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn prerequisite_status_to_descriptor_status_truth_table() {
    // Mapping pinned by connector_descriptors.rs:372-383:
    //   Satisfied      → Ready
    //   Missing        → Missing
    //   Drifted        → Drifted
    //   Unverifiable   → Unverifiable
    //   PolicyBlocked  → PolicyBlocked
    //   NotYetMeasured → NotYetMeasured
    //   Unavailable    → Unavailable
    //
    // Note: only `Satisfied → Ready` renames; the rest are
    // identity-named projections. Pin the lossy rename loud.
    let cases = [
        (PrerequisiteStatus::Satisfied, DescriptorStatus::Ready),
        (PrerequisiteStatus::Missing, DescriptorStatus::Missing),
        (PrerequisiteStatus::Drifted, DescriptorStatus::Drifted),
        (PrerequisiteStatus::Unverifiable, DescriptorStatus::Unverifiable),
        (PrerequisiteStatus::PolicyBlocked, DescriptorStatus::PolicyBlocked),
        (PrerequisiteStatus::NotYetMeasured, DescriptorStatus::NotYetMeasured),
        (PrerequisiteStatus::Unavailable, DescriptorStatus::Unavailable),
    ];
    for (prereq, expected_descriptor) in cases {
        let projected: DescriptorStatus = prereq.into();
        assert_eq!(
            projected, expected_descriptor,
            "PrerequisiteStatus → DescriptorStatus mapping drift on {prereq:?}"
        );
    }
}

#[test]
fn satisfied_renames_to_ready_in_descriptor_projection() {
    // The only rename in the projection: Satisfied → Ready.
    // Pin loud since the token changes when crossing the boundary
    // (operator dashboards see `satisfied` from prerequisites and
    // `ready` from descriptors — same semantic state, different
    // token).
    let projected: DescriptorStatus = PrerequisiteStatus::Satisfied.into();
    assert_eq!(projected, DescriptorStatus::Ready);

    let prereq_json = serde_json::to_string(&PrerequisiteStatus::Satisfied).unwrap();
    let descriptor_json = serde_json::to_string(&projected).unwrap();
    assert_eq!(prereq_json, r#""satisfied""#);
    assert_eq!(descriptor_json, r#""ready""#);
    assert_ne!(
        prereq_json, descriptor_json,
        "Satisfied (prereq) and Ready (descriptor) MUST surface as distinct tokens"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. DescriptorStatus tokens for projected variants match by-name
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn projected_descriptor_status_tokens_match_prerequisite_tokens_by_name() {
    // For the 6 variants that project identity (everything except
    // Satisfied → Ready), the JSON tokens MUST match byte-for-byte
    // — operators reading the audit log expect the same token
    // before and after the projection.
    let identity_pairs = [
        (PrerequisiteStatus::Missing, "missing"),
        (PrerequisiteStatus::Drifted, "drifted"),
        (PrerequisiteStatus::Unverifiable, "unverifiable"),
        (PrerequisiteStatus::PolicyBlocked, "policy_blocked"),
        (PrerequisiteStatus::NotYetMeasured, "not_yet_measured"),
        (PrerequisiteStatus::Unavailable, "unavailable"),
    ];
    for (prereq, expected_token) in identity_pairs {
        let prereq_json = serde_json::to_string(&prereq).unwrap();
        assert_eq!(prereq_json, format!("\"{expected_token}\""));
        let projected: DescriptorStatus = prereq.into();
        let descriptor_json = serde_json::to_string(&projected).unwrap();
        assert_eq!(
            descriptor_json,
            format!("\"{expected_token}\""),
            "{prereq:?} projection MUST produce the same JSON token byte-for-byte"
        );
        assert_eq!(prereq_json, descriptor_json);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. Token format invariants
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn every_token_is_snake_case_lowercase_ascii() {
    for (variant, label) in ALL_STATUSES {
        assert!(!label.is_empty(), "{variant:?}: empty");
        assert!(
            label.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
            "{variant:?}: label MUST be lowercase a-z plus `_` ({label:?})"
        );
        assert!(!label.starts_with('_'));
        assert!(!label.ends_with('_'));
        assert!(!label.contains("__"));
    }
}
