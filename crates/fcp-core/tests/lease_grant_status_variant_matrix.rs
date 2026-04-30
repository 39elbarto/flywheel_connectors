//! Pin `ResumeCause` + `DuplicateDeliveryClass` resume-grant variant matrix
//! — the closest analogue to "LeaseGrantStatus variant matrix"
//! (flywheel_connectors-0axe1).
//!
//! Bead asks for `LeaseGrantStatus` Display + serde tag pinning. No type
//! literally named `LeaseGrantStatus` exists in fcp-core. The closest
//! grant-shaped status enums in the lease/resume protocol are:
//!   * [`ResumeCause`] at `crates/fcp-core/src/connector_state.rs:1069` —
//!     4-variant: under WHAT condition was a lease/computation granted
//!     resumption (PlannedHandoff / Failover / CrashRecovery / OperatorRepair),
//!   * [`DuplicateDeliveryClass`] at `crates/fcp-core/src/connector_state.rs:1096`
//!     — 5-variant: HOW the resume grant interacts with prior partial work
//!     (Fresh / DuplicateCommitted / ReplaySafeRetry / AmbiguousExternal /
//!     EvidenceConflict).
//!
//! `LeaseResponse` (the immediate grant verdict) is pinned by
//! `lease_grant_display_serde.rs`. ResumeOutcome / ResumeDisposition /
//! ResumeReasonCode are pinned by `registry_acceptance_variants.rs` +
//! `zone_event_serde_tag_matrix.rs`. ResumeCause + DuplicateDeliveryClass
//! are residual — `grep ResumeCause` + `grep DuplicateDeliveryClass` in
//! `crates/fcp-core/tests/` returns empty.
//!
//! Coverage:
//!   * 4-variant ResumeCause snake_case serde + label() pinning,
//!   * 5-variant DuplicateDeliveryClass snake_case serde + label() pinning,
//!   * Cross-enum disjoint-token-space sentinel: ResumeCause and
//!     DuplicateDeliveryClass tokens MUST NOT alias (operator dashboards
//!     filter on both),
//!   * JSON + CBOR Text-scalar round-trip per variant,
//!   * PascalCase rejection sentinel,
//!   * label() == serde wire form (audit-log/wire alignment),
//!   * HashMap-key behavior for status grouping.

use ciborium::Value as CborValue;
use fcp_core::{DuplicateDeliveryClass, ResumeCause};
use serde_json::json;

const ALL_RESUME_CAUSES: &[(ResumeCause, &str)] = &[
    (ResumeCause::PlannedHandoff, "planned_handoff"),
    (ResumeCause::Failover, "failover"),
    (ResumeCause::CrashRecovery, "crash_recovery"),
    (ResumeCause::OperatorRepair, "operator_repair"),
];

const ALL_DUPLICATE_CLASSES: &[(DuplicateDeliveryClass, &str)] = &[
    (DuplicateDeliveryClass::Fresh, "fresh"),
    (DuplicateDeliveryClass::DuplicateCommitted, "duplicate_committed"),
    (DuplicateDeliveryClass::ReplaySafeRetry, "replay_safe_retry"),
    (DuplicateDeliveryClass::AmbiguousExternal, "ambiguous_external"),
    (DuplicateDeliveryClass::EvidenceConflict, "evidence_conflict"),
];

#[test]
fn resume_cause_serde_uses_snake_case_for_every_variant() {
    for &(variant, wire) in ALL_RESUME_CAUSES {
        let v = serde_json::to_value(variant).unwrap();
        assert_eq!(v, json!(wire), "{variant:?} must serialize to `{wire}`");
        let back: ResumeCause = serde_json::from_value(v).unwrap();
        assert_eq!(back, variant);
    }
}

#[test]
fn resume_cause_label_matches_serde_wire_form() {
    // label() is the documented stable token for logs/evidence; it must
    // agree with serde wire form so audit logs and on-disk records stay
    // aligned.
    for &(variant, wire) in ALL_RESUME_CAUSES {
        assert_eq!(
            variant.label(),
            wire,
            "ResumeCause::{variant:?}.label() != serde wire `{wire}`"
        );
    }
}

#[test]
fn resume_cause_cbor_text_scalar_per_variant() {
    for &(variant, expected) in ALL_RESUME_CAUSES {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&variant, &mut bytes).unwrap();
        let back: ResumeCause = ciborium::de::from_reader(&bytes[..]).unwrap();
        assert_eq!(back, variant);

        let value: CborValue = ciborium::de::from_reader(&bytes[..]).unwrap();
        match value {
            CborValue::Text(text) => assert_eq!(text, expected),
            other => panic!("ResumeCause must be CBOR Text, got {other:?}"),
        }
    }
}

#[test]
fn resume_cause_rejects_pascal_case() {
    let bad: Result<ResumeCause, _> = serde_json::from_value(json!("PlannedHandoff"));
    assert!(bad.is_err(), "PascalCase must reject: {bad:?}");
    let bad: Result<ResumeCause, _> = serde_json::from_value(json!("FAILOVER"));
    assert!(bad.is_err(), "SCREAMING must reject: {bad:?}");
}

#[test]
fn resume_cause_distinct_variants_serialize_distinctly() {
    let mut seen = std::collections::HashSet::new();
    for &(variant, _) in ALL_RESUME_CAUSES {
        let v = serde_json::to_value(variant).unwrap();
        assert!(seen.insert(v.clone()), "duplicate JSON for {variant:?}: {v:?}");
    }
}

#[test]
fn duplicate_delivery_class_serde_uses_snake_case_for_every_variant() {
    for &(variant, wire) in ALL_DUPLICATE_CLASSES {
        let v = serde_json::to_value(variant).unwrap();
        assert_eq!(v, json!(wire), "{variant:?} must serialize to `{wire}`");
        let back: DuplicateDeliveryClass = serde_json::from_value(v).unwrap();
        assert_eq!(back, variant);
    }
}

#[test]
fn duplicate_delivery_class_label_matches_serde_wire_form() {
    for &(variant, wire) in ALL_DUPLICATE_CLASSES {
        assert_eq!(
            variant.label(),
            wire,
            "DuplicateDeliveryClass::{variant:?}.label() != serde wire `{wire}`"
        );
    }
}

#[test]
fn duplicate_delivery_class_cbor_text_scalar_per_variant() {
    for &(variant, expected) in ALL_DUPLICATE_CLASSES {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&variant, &mut bytes).unwrap();
        let back: DuplicateDeliveryClass = ciborium::de::from_reader(&bytes[..]).unwrap();
        assert_eq!(back, variant);

        let value: CborValue = ciborium::de::from_reader(&bytes[..]).unwrap();
        match value {
            CborValue::Text(text) => assert_eq!(text, expected),
            other => panic!("DuplicateDeliveryClass must be CBOR Text, got {other:?}"),
        }
    }
}

#[test]
fn duplicate_delivery_class_rejects_pascal_case() {
    let bad: Result<DuplicateDeliveryClass, _> = serde_json::from_value(json!("Fresh"));
    assert!(bad.is_err(), "PascalCase must reject: {bad:?}");
    let bad: Result<DuplicateDeliveryClass, _> =
        serde_json::from_value(json!("DuplicateCommitted"));
    assert!(bad.is_err(), "PascalCase must reject: {bad:?}");
}

#[test]
fn duplicate_delivery_class_distinct_variants_serialize_distinctly() {
    let mut seen = std::collections::HashSet::new();
    for &(variant, _) in ALL_DUPLICATE_CLASSES {
        let v = serde_json::to_value(variant).unwrap();
        assert!(seen.insert(v.clone()), "duplicate JSON for {variant:?}: {v:?}");
    }
}

#[test]
fn cross_enum_token_space_is_disjoint() {
    // Loud sentinel: ResumeCause and DuplicateDeliveryClass tokens must
    // NOT alias. Operator dashboards filter on both — accidentally
    // converging would silently merge two distinct status streams.
    let resume_tokens: std::collections::HashSet<&str> =
        ALL_RESUME_CAUSES.iter().map(|&(_, t)| t).collect();
    let class_tokens: std::collections::HashSet<&str> =
        ALL_DUPLICATE_CLASSES.iter().map(|&(_, t)| t).collect();

    let intersection: std::collections::HashSet<_> =
        resume_tokens.intersection(&class_tokens).copied().collect();
    assert!(
        intersection.is_empty(),
        "ResumeCause + DuplicateDeliveryClass token-space collision: {intersection:?}"
    );

    // Also pin the total count: 4 + 5 = 9 distinct tokens.
    let mut all = resume_tokens.clone();
    all.extend(class_tokens);
    assert_eq!(all.len(), 9, "expected 9 distinct status tokens, got {}", all.len());
}

#[test]
fn resume_cause_eq_partition_groups_via_linear_count() {
    // ResumeCause does NOT derive Hash, so direct HashMap-key bucketing
    // isn't available; pin grouping via linear PartialEq count instead.
    // This is the canonical pattern callers must use.
    let observed = [
        ResumeCause::PlannedHandoff,
        ResumeCause::Failover,
        ResumeCause::PlannedHandoff,
        ResumeCause::PlannedHandoff,
        ResumeCause::Failover,
    ];
    let planned_count = observed
        .iter()
        .filter(|c| **c == ResumeCause::PlannedHandoff)
        .count();
    let failover_count = observed
        .iter()
        .filter(|c| **c == ResumeCause::Failover)
        .count();
    let crash_count = observed
        .iter()
        .filter(|c| **c == ResumeCause::CrashRecovery)
        .count();
    assert_eq!(planned_count, 3);
    assert_eq!(failover_count, 2);
    assert_eq!(crash_count, 0);
}

#[test]
fn duplicate_delivery_class_eq_partition_groups_via_linear_count() {
    // Same: DuplicateDeliveryClass lacks Hash; pin grouping via
    // PartialEq filter.
    let observed = [
        DuplicateDeliveryClass::Fresh,
        DuplicateDeliveryClass::EvidenceConflict,
        DuplicateDeliveryClass::Fresh,
    ];
    let fresh_count = observed
        .iter()
        .filter(|c| **c == DuplicateDeliveryClass::Fresh)
        .count();
    let conflict_count = observed
        .iter()
        .filter(|c| **c == DuplicateDeliveryClass::EvidenceConflict)
        .count();
    let retry_count = observed
        .iter()
        .filter(|c| **c == DuplicateDeliveryClass::ReplaySafeRetry)
        .count();
    assert_eq!(fresh_count, 2);
    assert_eq!(conflict_count, 1);
    assert_eq!(retry_count, 0);
}

#[test]
fn fresh_is_the_initial_default_class_per_documentation() {
    // Documentation pins Fresh as "no conflicting prior effect has been
    // observed" — i.e. the initial classification when no prior work
    // exists. Pin via the snake_case wire form (initial classification
    // = {"class": "fresh"} on the wire when serialized in a context).
    assert_eq!(DuplicateDeliveryClass::Fresh.label(), "fresh");
    let v = serde_json::to_value(DuplicateDeliveryClass::Fresh).unwrap();
    assert_eq!(v, json!("fresh"));
}

#[test]
fn evidence_conflict_signals_operator_attention_via_distinct_token() {
    // Loud sentinel: EvidenceConflict is the highest-severity class
    // ("durable evidence objects disagree and require operator attention").
    // Pin its distinct wire form so operator-dashboard alerts don't
    // silently collapse into the lower-severity classes.
    let target = "evidence_conflict";
    assert_eq!(DuplicateDeliveryClass::EvidenceConflict.label(), target);

    for &(variant, wire) in ALL_DUPLICATE_CLASSES {
        if variant != DuplicateDeliveryClass::EvidenceConflict {
            assert_ne!(wire, target, "{variant:?} accidentally aliases EvidenceConflict");
        }
    }
}

#[test]
fn operator_repair_is_distinct_from_failover_and_crash_recovery() {
    // OperatorRepair is the documented escape-hatch cause distinct from
    // automatic Failover or CrashRecovery. Pin distinct tokens so
    // dashboards can filter "operator-initiated" vs "automatic" causes.
    assert_ne!(
        ResumeCause::OperatorRepair.label(),
        ResumeCause::Failover.label()
    );
    assert_ne!(
        ResumeCause::OperatorRepair.label(),
        ResumeCause::CrashRecovery.label()
    );
}
