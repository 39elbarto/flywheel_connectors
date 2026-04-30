//! Pin `PcsEventType` + `ResumeReasonCode` serde tag matrix — the
//! closest analogues to "ZoneEvent serde tag matrix"
//! (flywheel_connectors-ifkle).
//!
//! Bead asks for `ZoneEvent serde tag JSON+CBOR roundtrip`. No type
//! literally named `ZoneEvent` exists in fcp-core. The event-shaped
//! classifier surface covers many already-pinned enums:
//! - ConnectorEvent (already pinned by connector_event_serde_tags.rs)
//! - EventSeverity (already pinned by event_severity_ordering.rs)
//! - OrderingPolicy (already pinned by schedule_policy_variant_matrix.rs)
//!
//! Two unpinned event-type classifiers in the zone-event surface:
//!
//!  - `PcsEventType` (pcs.rs:463) — 6 variants for PCS audit
//!    logging (`GroupCreated` / `EpochAdvanced` / `MemberAdded` /
//!    `MemberRemoved` / `ZoneKeyDerived` / `CompromiseRecovery`)
//!    with `#[serde(rename_all = "snake_case")]`.
//!  - `ResumeReasonCode` (connector_state.rs:1201) — 8 variants
//!    for timeline events emitted during checkpoint export,
//!    handoff, and resume (`CheckpointExported` / `HandoffAuthorized`
//!    / `CheckpointFresh` / `CheckpointStale` / `DuplicateClassified`
//!    / `ResumeAccepted` / `ResumeDenied` / `EvidenceConflict`)
//!    with `rename_all = "snake_case"`.
//!
//! These are the canonical "zone event" classifiers that operators
//! see in zone audit logs (PCS group lifecycle + resume timeline).
//!
//! Targets:
//!
//!   1. **`PcsEventType` per-variant JSON tag** in snake_case
//!      (group_created / epoch_advanced / member_added /
//!      member_removed / zone_key_derived / compromise_recovery).
//!   2. **`PcsEventType` JSON + CBOR round-trip** per variant.
//!   3. **`PcsEventType` CBOR encodes as Text** (cross-language).
//!   4. **`PcsEventType` PascalCase + unknown rejected**.
//!   5. **`PcsEventType` 6-variant count + pairwise distinct**.
//!   6. **`ResumeReasonCode` per-variant JSON tag** in snake_case
//!      (checkpoint_exported / handoff_authorized / checkpoint_fresh
//!      / checkpoint_stale / duplicate_classified / resume_accepted
//!      / resume_denied / evidence_conflict).
//!   7. **`ResumeReasonCode` JSON + CBOR round-trip** per variant.
//!   8. **Multi-word variants use underscore** (no camelCase /
//!      kebab-case).
//!   9. **`ResumeReasonCode` 8-variant count + pairwise distinct**.
//!  10. **Cross-enum disjoint token spaces** — operator dashboards
//!      reading both PCS and resume audit streams MUST be able to
//!      distinguish event types by token alone.

use ciborium::value::Value as CborValue;
use fcp_core::ResumeReasonCode;
use fcp_core::pcs::PcsEventType;

const PCS_EVENT_TYPE_CASES: &[(PcsEventType, &str)] = &[
    (PcsEventType::GroupCreated, "group_created"),
    (PcsEventType::EpochAdvanced, "epoch_advanced"),
    (PcsEventType::MemberAdded, "member_added"),
    (PcsEventType::MemberRemoved, "member_removed"),
    (PcsEventType::ZoneKeyDerived, "zone_key_derived"),
    (PcsEventType::CompromiseRecovery, "compromise_recovery"),
];

const RESUME_REASON_CODE_CASES: &[(ResumeReasonCode, &str)] = &[
    (ResumeReasonCode::CheckpointExported, "checkpoint_exported"),
    (ResumeReasonCode::HandoffAuthorized, "handoff_authorized"),
    (ResumeReasonCode::CheckpointFresh, "checkpoint_fresh"),
    (ResumeReasonCode::CheckpointStale, "checkpoint_stale"),
    (
        ResumeReasonCode::DuplicateClassified,
        "duplicate_classified",
    ),
    (ResumeReasonCode::ResumeAccepted, "resume_accepted"),
    (ResumeReasonCode::ResumeDenied, "resume_denied"),
    (ResumeReasonCode::EvidenceConflict, "evidence_conflict"),
];

// ─────────────────────────────────────────────────────────────────────────────
// 1. PcsEventType per-variant JSON tag
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn pcs_event_type_json_tag_pinned_per_variant() {
    for (variant, expected) in PCS_EVENT_TYPE_CASES {
        let json = serde_json::to_string(variant).expect("serialize");
        assert_eq!(
            json,
            format!("\"{expected}\""),
            "ZONE-EVENT REGRESSION: PcsEventType tag drift on {variant:?} — \
             PCS audit logs filter on this exact token"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. PcsEventType JSON + CBOR round-trip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn pcs_event_type_json_roundtrip_per_variant() {
    for (variant, _) in PCS_EVENT_TYPE_CASES {
        let json = serde_json::to_string(variant).expect("serialize");
        let back: PcsEventType = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*variant, back);
    }
}

#[test]
fn pcs_event_type_cbor_roundtrip_per_variant() {
    for (variant, _) in PCS_EVENT_TYPE_CASES {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(variant, &mut buf).expect("encode");
        let back: PcsEventType = ciborium::de::from_reader(buf.as_slice()).expect("decode");
        assert_eq!(*variant, back);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. PcsEventType CBOR encodes as Text
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn pcs_event_type_cbor_encodes_as_text_not_integer() {
    for (variant, expected) in PCS_EVENT_TYPE_CASES {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(variant, &mut buf).expect("encode");
        let value: CborValue = ciborium::de::from_reader(buf.as_slice()).expect("decode as Value");
        match value {
            CborValue::Text(s) => assert_eq!(s, *expected, "CBOR Text drift on {variant:?}"),
            other => panic!("PcsEventType MUST encode as Text({expected:?}); got {other:?}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. PcsEventType PascalCase + unknown rejected
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn pcs_event_type_rejects_pascal_case_and_unknown() {
    for bad in [
        r#""GroupCreated""#,
        r#""EpochAdvanced""#,
        r#""ZoneKeyDerived""#,
        r#""CompromiseRecovery""#,
        r#""groupCreated""#,
        r#""group-created""#,
        r#""key_rotation""#,
        r#""""#,
    ] {
        let parsed = serde_json::from_str::<PcsEventType>(bad);
        assert!(parsed.is_err(), "{bad} MUST be rejected");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. PcsEventType 6-variant count + pairwise distinct
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn pcs_event_type_count_is_six() {
    assert_eq!(PCS_EVENT_TYPE_CASES.len(), 6);
}

#[test]
fn pcs_event_type_variants_pairwise_distinct() {
    let mut seen = std::collections::HashSet::new();
    for (_, label) in PCS_EVENT_TYPE_CASES {
        assert!(seen.insert(*label), "duplicate token {label}");
    }
    assert_eq!(seen.len(), PCS_EVENT_TYPE_CASES.len());

    for i in 0..PCS_EVENT_TYPE_CASES.len() {
        for j in (i + 1)..PCS_EVENT_TYPE_CASES.len() {
            assert_ne!(PCS_EVENT_TYPE_CASES[i].0, PCS_EVENT_TYPE_CASES[j].0);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. ResumeReasonCode per-variant JSON tag
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn resume_reason_code_json_tag_pinned_per_variant() {
    for (variant, expected) in RESUME_REASON_CODE_CASES {
        let json = serde_json::to_string(variant).expect("serialize");
        assert_eq!(
            json,
            format!("\"{expected}\""),
            "ResumeReasonCode tag drift on {variant:?} — \
             resume timeline audit logs filter on this exact token"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. ResumeReasonCode JSON + CBOR round-trip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn resume_reason_code_json_roundtrip_per_variant() {
    for (variant, _) in RESUME_REASON_CODE_CASES {
        let json = serde_json::to_string(variant).expect("serialize");
        let back: ResumeReasonCode = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*variant, back);
    }
}

#[test]
fn resume_reason_code_cbor_roundtrip_per_variant() {
    for (variant, _) in RESUME_REASON_CODE_CASES {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(variant, &mut buf).expect("encode");
        let back: ResumeReasonCode = ciborium::de::from_reader(buf.as_slice()).expect("decode");
        assert_eq!(*variant, back);
    }
}

#[test]
fn resume_reason_code_cbor_encodes_as_text_not_integer() {
    for (variant, expected) in RESUME_REASON_CODE_CASES {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(variant, &mut buf).expect("encode");
        let value: CborValue = ciborium::de::from_reader(buf.as_slice()).expect("decode as Value");
        match value {
            CborValue::Text(s) => assert_eq!(s, *expected, "CBOR Text drift on {variant:?}"),
            other => {
                panic!("ResumeReasonCode MUST encode as Text({expected:?}); got {other:?}")
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. Multi-word variants use underscore
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn pcs_multi_word_variants_use_underscore_not_camel_case() {
    let cases = [
        (PcsEventType::GroupCreated, "group_created"),
        (PcsEventType::ZoneKeyDerived, "zone_key_derived"),
        (PcsEventType::CompromiseRecovery, "compromise_recovery"),
    ];
    for (variant, expected) in cases {
        let json = serde_json::to_string(&variant).unwrap();
        assert_eq!(json, format!("\"{expected}\""));
        assert!(!json.contains('-'), "snake_case MUST NOT use hyphens");
    }
}

#[test]
fn resume_multi_word_variants_use_underscore_not_camel_case() {
    let cases = [
        (ResumeReasonCode::CheckpointExported, "checkpoint_exported"),
        (
            ResumeReasonCode::DuplicateClassified,
            "duplicate_classified",
        ),
        (ResumeReasonCode::EvidenceConflict, "evidence_conflict"),
    ];
    for (variant, expected) in cases {
        let json = serde_json::to_string(&variant).unwrap();
        assert_eq!(json, format!("\"{expected}\""));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. ResumeReasonCode 8-variant count + pairwise distinct
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn resume_reason_code_count_is_eight() {
    assert_eq!(RESUME_REASON_CODE_CASES.len(), 8);
}

#[test]
fn resume_reason_code_variants_pairwise_distinct() {
    let mut seen = std::collections::HashSet::new();
    for (_, label) in RESUME_REASON_CODE_CASES {
        assert!(seen.insert(*label));
    }
    assert_eq!(seen.len(), RESUME_REASON_CODE_CASES.len());

    for i in 0..RESUME_REASON_CODE_CASES.len() {
        for j in (i + 1)..RESUME_REASON_CODE_CASES.len() {
            assert_ne!(RESUME_REASON_CODE_CASES[i].0, RESUME_REASON_CODE_CASES[j].0);
        }
    }
}

#[test]
fn resume_reason_code_rejects_pascal_case() {
    for bad in [
        r#""CheckpointExported""#,
        r#""HandoffAuthorized""#,
        r#""ResumeAccepted""#,
        r#""checkpoint-exported""#,
        r#""abandoned""#,
    ] {
        let parsed = serde_json::from_str::<ResumeReasonCode>(bad);
        assert!(parsed.is_err(), "{bad} MUST be rejected");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. Cross-enum disjoint token spaces
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn pcs_event_type_and_resume_reason_code_use_disjoint_token_spaces() {
    // Operator dashboards reading both PCS audit and resume timeline
    // streams MUST distinguish event types by token alone. Pin
    // disjoint label spaces.
    let pcs_tokens: std::collections::HashSet<&str> =
        PCS_EVENT_TYPE_CASES.iter().map(|(_, s)| *s).collect();
    let resume_tokens: std::collections::HashSet<&str> =
        RESUME_REASON_CODE_CASES.iter().map(|(_, s)| *s).collect();
    let intersection: Vec<&&str> = pcs_tokens.intersection(&resume_tokens).collect();
    assert!(
        intersection.is_empty(),
        "PcsEventType and ResumeReasonCode tokens MUST be disjoint; \
         got collisions: {intersection:?}"
    );
}

#[test]
fn every_event_token_is_snake_case_lowercase_ascii() {
    let all: Vec<(&str, &str)> = PCS_EVENT_TYPE_CASES
        .iter()
        .map(|(_, s)| ("PcsEventType", *s))
        .chain(
            RESUME_REASON_CODE_CASES
                .iter()
                .map(|(_, s)| ("ResumeReasonCode", *s)),
        )
        .collect();
    for (enum_name, label) in all {
        assert!(!label.is_empty(), "{enum_name}: empty label");
        assert!(
            label.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
            "{enum_name}: {label:?} not snake_case lowercase ASCII"
        );
        assert!(!label.starts_with('_'));
        assert!(!label.ends_with('_'));
        assert!(!label.contains("__"));
    }
}
