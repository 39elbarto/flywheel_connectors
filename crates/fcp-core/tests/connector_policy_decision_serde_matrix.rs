//! Pin `DecisionReasonCode` 35-variant serde matrix with Display /
//! serde dual-encoding sentinel (flywheel_connectors-zx5bz).
//!
//! Bead asks for `ConnectorPolicyDecision serde JSON+CBOR
//! roundtrip`. fcp-core has no type literally named
//! `ConnectorPolicyDecision`. The closest decision classifier is
//! `DecisionReasonCode` (policy.rs:2060) — the 35-variant NORMATIVE
//! reason-code enum produced by `PolicyEngine::evaluate_invoke`
//! and surfaced in audit logs. Many decision-shaped types are
//! already pinned (Decision by qyq9l, CheckOutcome by qyq9l,
//! PolicyPreviewDecision by zncpi, VerificationDecision by zncpi,
//! ResumeDecision-shaped by zncpi); a 7-variant subset of
//! DecisionReasonCode is pinned by `policy_match_result_variants.rs`.
//! This test pins the FULL 35-variant matrix and the critical
//! dual-encoding contract:
//!
//! **DISPLAY vs SERDE diverge**: `DecisionReasonCode::as_str` /
//! `Display` returns dotted tokens (`"capability.insufficient"`,
//! `"zone_policy.principal_denied"`) but the serde wire form uses
//! `#[serde(rename_all = "snake_case")]` which produces snake_case
//! WITHOUT dots (`"capability_insufficient"`,
//! `"zone_policy_principal_denied"`). Operator dashboards reading
//! audit logs MUST know which channel uses which form.
//!
//! Targets:
//!
//!   1. **Per-variant Display token** (dotted) for all 35 variants.
//!   2. **Per-variant serde JSON tag** (snake_case, no dots).
//!   3. **Display ≠ serde tag for every variant with a `.` in
//!      Display** — pin the divergence loud.
//!   4. **JSON + CBOR round-trip** per variant.
//!   5. **CBOR encodes as Text** (cross-language).
//!   6. **35-variant count + pairwise distinct**.
//!   7. **PascalCase + dotted-form rejected on the wire** — drift
//!      sentinel.
//!   8. **Hash + Eq + Copy correctness** for HashMap-key usage.

use ciborium::value::Value as CborValue;
use fcp_core::DecisionReasonCode;

/// (variant, Display token from as_str, serde JSON tag from rename_all).
/// For variants where Display contains `.`, the serde form replaces
/// it with `_`. For dot-free variants the two forms agree.
const ALL_REASON_CODES: &[(DecisionReasonCode, &str, &str)] = &[
    (DecisionReasonCode::Allow, "allow", "allow"),
    (
        DecisionReasonCode::CapabilityInsufficient,
        "capability.insufficient",
        "capability_insufficient",
    ),
    (
        DecisionReasonCode::CheckpointStaleFrontier,
        "checkpoint.stale_frontier",
        "checkpoint_stale_frontier",
    ),
    (
        DecisionReasonCode::RevocationStaleFrontier,
        "revocation.stale_frontier",
        "revocation_stale_frontier",
    ),
    (
        DecisionReasonCode::TaintPublicInputDangerous,
        "taint.public_input_dangerous",
        "taint_public_input_dangerous",
    ),
    (
        DecisionReasonCode::TaintUnverifiedLinkRisky,
        "taint.unverified_link_risky",
        "taint_unverified_link_risky",
    ),
    (
        DecisionReasonCode::TaintMaliciousInput,
        "taint.malicious_input",
        "taint_malicious_input",
    ),
    (
        DecisionReasonCode::TaintRiskyRequiresElevation,
        "taint.risky_requires_elevation",
        "taint_risky_requires_elevation",
    ),
    (
        DecisionReasonCode::TaintCrossZoneUnapproved,
        "taint.cross_zone_unapproved",
        "taint_cross_zone_unapproved",
    ),
    (
        DecisionReasonCode::IntegrityInsufficient,
        "integrity.insufficient",
        "integrity_insufficient",
    ),
    (
        DecisionReasonCode::ZonePolicyPrincipalDenied,
        "zone_policy.principal_denied",
        "zone_policy_principal_denied",
    ),
    (
        DecisionReasonCode::ZonePolicyConnectorDenied,
        "zone_policy.connector_denied",
        "zone_policy_connector_denied",
    ),
    (
        DecisionReasonCode::ZonePolicyCapabilityDenied,
        "zone_policy.capability_denied",
        "zone_policy_capability_denied",
    ),
    (
        DecisionReasonCode::ZonePolicyPrincipalNotAllowed,
        "zone_policy.principal_not_allowed",
        "zone_policy_principal_not_allowed",
    ),
    (
        DecisionReasonCode::ZonePolicyConnectorNotAllowed,
        "zone_policy.connector_not_allowed",
        "zone_policy_connector_not_allowed",
    ),
    (
        DecisionReasonCode::ZonePolicyCapabilityNotAllowed,
        "zone_policy.capability_not_allowed",
        "zone_policy_capability_not_allowed",
    ),
    (
        DecisionReasonCode::ApprovalMissingElevation,
        "approval.missing_elevation",
        "approval_missing_elevation",
    ),
    (
        DecisionReasonCode::ApprovalMissingDeclassification,
        "approval.missing_declassification",
        "approval_missing_declassification",
    ),
    (
        DecisionReasonCode::ApprovalMissingExecution,
        "approval.missing_execution",
        "approval_missing_execution",
    ),
    (
        DecisionReasonCode::ApprovalElevationScopeMismatch,
        "approval.elevation_scope_mismatch",
        "approval_elevation_scope_mismatch",
    ),
    (
        DecisionReasonCode::ApprovalExecutionScopeMismatch,
        "approval.execution_scope_mismatch",
        "approval_execution_scope_mismatch",
    ),
    (
        DecisionReasonCode::ApprovalExpired,
        "approval.expired",
        "approval_expired",
    ),
    (
        DecisionReasonCode::ApprovalZoneMismatch,
        "approval.zone_mismatch",
        "approval_zone_mismatch",
    ),
    (
        DecisionReasonCode::ApprovalTokenInvalid,
        "approval.token_invalid",
        "approval_token_invalid",
    ),
    (
        DecisionReasonCode::TransportDerpForbidden,
        "transport.derp_forbidden",
        "transport_derp_forbidden",
    ),
    (
        DecisionReasonCode::TransportFunnelForbidden,
        "transport.funnel_forbidden",
        "transport_funnel_forbidden",
    ),
    (
        DecisionReasonCode::TransportLanForbidden,
        "transport.lan_forbidden",
        "transport_lan_forbidden",
    ),
    (
        DecisionReasonCode::SanitizerReceiptInvalid,
        "taint.sanitizer_invalid",
        "sanitizer_receipt_invalid",
    ),
    (
        DecisionReasonCode::SanitizerCoverageInsufficient,
        "taint.sanitizer_coverage_insufficient",
        "sanitizer_coverage_insufficient",
    ),
    (
        DecisionReasonCode::PostureAttestationMissing,
        "posture.attestation_missing",
        "posture_attestation_missing",
    ),
    (
        DecisionReasonCode::PostureAttestationExpired,
        "posture.attestation_expired",
        "posture_attestation_expired",
    ),
    (
        DecisionReasonCode::PostureAttestationInvalid,
        "posture.attestation_invalid",
        "posture_attestation_invalid",
    ),
    (
        DecisionReasonCode::PostureRequirementNotMet,
        "posture.requirement_not_met",
        "posture_requirement_not_met",
    ),
    (
        DecisionReasonCode::PostureVerifierNotAllowed,
        "posture.verifier_not_allowed",
        "posture_verifier_not_allowed",
    ),
    (
        DecisionReasonCode::OperationForbidden,
        "operation.forbidden",
        "operation_forbidden",
    ),
];

// ─────────────────────────────────────────────────────────────────────────────
// 1. Per-variant Display token (dotted) for all 35 variants
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn display_token_pinned_per_variant() {
    for (variant, expected_display, _) in ALL_REASON_CODES {
        assert_eq!(
            variant.to_string(),
            *expected_display,
            "AUDIT REGRESSION: DecisionReasonCode Display drift on {variant:?}"
        );
        assert_eq!(variant.as_str(), *expected_display);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Per-variant serde JSON tag (snake_case, no dots)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn serde_json_tag_pinned_per_variant() {
    for (variant, _, expected_serde) in ALL_REASON_CODES {
        let json = serde_json::to_string(variant).expect("serialize");
        assert_eq!(
            json,
            format!("\"{expected_serde}\""),
            "POLICY-DECISION REGRESSION: DecisionReasonCode serde tag drift on {variant:?} — \
             serde wire form uses snake_case (NOT the dotted Display form)"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Display ≠ serde tag for every variant with a `.` in Display
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn display_and_serde_diverge_on_dotted_variants() {
    // Loud pin: Display form uses dots (`capability.insufficient`)
    // but the serde wire form uses underscores
    // (`capability_insufficient`). Operator dashboards MUST know
    // which channel emits which form.
    let mut divergent_count = 0;
    for (variant, display, serde_tag) in ALL_REASON_CODES {
        if display.contains('.') {
            assert_ne!(
                display, serde_tag,
                "{variant:?}: Display ({display}) and serde tag ({serde_tag}) MUST diverge \
                 when Display contains a dot"
            );
            divergent_count += 1;
        } else {
            // Dot-free Display tokens (Allow only) MUST agree with
            // serde tag.
            assert_eq!(
                display, serde_tag,
                "{variant:?}: dot-free Display MUST equal serde tag"
            );
        }
    }
    // 34 of 35 variants have a dot in Display (only Allow doesn't).
    assert_eq!(
        divergent_count, 34,
        "34 variants MUST have divergent Display/serde forms; got {divergent_count}"
    );
}

#[test]
fn capability_insufficient_dual_encoding_pinned_explicitly() {
    // Pin the canonical example loud: Display = "capability.insufficient",
    // serde = "capability_insufficient".
    let variant = DecisionReasonCode::CapabilityInsufficient;
    assert_eq!(variant.to_string(), "capability.insufficient");
    assert_eq!(
        serde_json::to_string(&variant).unwrap(),
        r#""capability_insufficient""#
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. JSON + CBOR round-trip per variant
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn json_roundtrip_preserves_every_variant() {
    for (variant, _, _) in ALL_REASON_CODES {
        let json = serde_json::to_string(variant).expect("serialize");
        let back: DecisionReasonCode = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*variant, back, "JSON round-trip lost {variant:?}");
    }
}

#[test]
fn cbor_roundtrip_preserves_every_variant() {
    for (variant, _, _) in ALL_REASON_CODES {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(variant, &mut buf).expect("encode");
        let back: DecisionReasonCode = ciborium::de::from_reader(buf.as_slice()).expect("decode");
        assert_eq!(*variant, back, "CBOR round-trip lost {variant:?}");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. CBOR encodes as Text
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn cbor_encodes_as_text_using_serde_form() {
    for (variant, _, expected_serde) in ALL_REASON_CODES {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(variant, &mut buf).expect("encode");
        let value: CborValue = ciborium::de::from_reader(buf.as_slice()).expect("decode as Value");
        match value {
            CborValue::Text(s) => assert_eq!(
                s, *expected_serde,
                "CBOR Text MUST be serde form (snake_case, no dot) for {variant:?}"
            ),
            other => {
                panic!("DecisionReasonCode MUST encode as Text({expected_serde:?}); got {other:?}")
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. 35-variant count + pairwise distinct
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn decision_reason_code_count_is_thirty_five() {
    assert_eq!(
        ALL_REASON_CODES.len(),
        35,
        "DecisionReasonCode has 35 documented variants — count drifted"
    );
}

#[test]
fn variants_pairwise_distinct_in_both_encodings() {
    let mut display_seen = std::collections::HashSet::new();
    let mut serde_seen = std::collections::HashSet::new();
    for (_, display, serde_tag) in ALL_REASON_CODES {
        assert!(display_seen.insert(*display), "duplicate Display {display}");
        assert!(
            serde_seen.insert(*serde_tag),
            "duplicate serde tag {serde_tag}"
        );
    }
    assert_eq!(display_seen.len(), 35);
    assert_eq!(serde_seen.len(), 35);
}

#[test]
fn variants_pairwise_unequal() {
    for i in 0..ALL_REASON_CODES.len() {
        for j in (i + 1)..ALL_REASON_CODES.len() {
            assert_ne!(
                ALL_REASON_CODES[i].0, ALL_REASON_CODES[j].0,
                "{:?} and {:?} MUST be distinct",
                ALL_REASON_CODES[i].0, ALL_REASON_CODES[j].0
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. PascalCase + dotted-form rejected on the wire
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn rejects_pascal_case_variant_name() {
    for bad in [
        r#""Allow""#,
        r#""CapabilityInsufficient""#,
        r#""ZonePolicyPrincipalDenied""#,
    ] {
        let parsed = serde_json::from_str::<DecisionReasonCode>(bad);
        assert!(parsed.is_err(), "{bad} MUST be rejected");
    }
}

#[test]
fn rejects_dotted_display_form_on_wire() {
    // The Display form ("capability.insufficient") is NOT the wire
    // form. Pin that the dotted form is rejected even though
    // operators see it in audit logs — only the snake_case serde
    // form decodes.
    for bad in [
        r#""capability.insufficient""#,
        r#""zone_policy.principal_denied""#,
        r#""approval.expired""#,
        r#""posture.requirement_not_met""#,
    ] {
        let parsed = serde_json::from_str::<DecisionReasonCode>(bad);
        assert!(
            parsed.is_err(),
            "{bad} MUST be rejected — dotted Display form is NOT the wire form"
        );
    }
}

#[test]
fn rejects_unknown_reason_code() {
    for bad in [r#""unknown_reason""#, r#""custom.code""#, r#""""#] {
        let parsed = serde_json::from_str::<DecisionReasonCode>(bad);
        assert!(parsed.is_err(), "{bad} MUST be rejected");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. Hash + Eq + Copy correctness
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn decision_reason_code_serves_as_hashmap_key() {
    use std::collections::HashMap;
    let mut map: HashMap<DecisionReasonCode, &'static str> = HashMap::new();
    for (variant, display, _) in ALL_REASON_CODES {
        map.insert(*variant, display);
    }
    assert_eq!(map.len(), 35);
    for (variant, display, _) in ALL_REASON_CODES {
        assert_eq!(map.get(variant), Some(display));
    }
}

#[test]
fn copy_preserves_equality_for_every_variant() {
    for (variant, _, _) in ALL_REASON_CODES {
        let copied: DecisionReasonCode = *variant;
        let cloned = copied;
        assert_eq!(*variant, copied);
        assert_eq!(*variant, cloned);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. Variant family invariants — every dotted Display has a single
//    namespace prefix
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn every_dotted_display_has_exactly_one_namespace_dot() {
    // Format: "<namespace>.<rest>" where <rest> may itself contain
    // underscores. Pin that exactly one `.` appears (not multiple).
    for (variant, display, _) in ALL_REASON_CODES {
        if display.contains('.') {
            let dot_count = display.chars().filter(|c| *c == '.').count();
            assert_eq!(
                dot_count, 1,
                "{variant:?}: Display ({display}) MUST have exactly one dot"
            );
        }
    }
}

#[test]
fn namespaces_used_in_display_are_documented_set() {
    // Document the namespace set that policy audit logs use as
    // the prefix vocabulary. Drift here surfaces a new namespace
    // without cross-team review.
    let mut namespaces = std::collections::HashSet::new();
    for (_, display, _) in ALL_REASON_CODES {
        if let Some((ns, _)) = display.split_once('.') {
            namespaces.insert(ns.to_string());
        }
    }
    let mut sorted: Vec<String> = namespaces.into_iter().collect();
    sorted.sort();
    assert_eq!(
        sorted,
        vec![
            "approval".to_string(),
            "capability".to_string(),
            "checkpoint".to_string(),
            "integrity".to_string(),
            "operation".to_string(),
            "posture".to_string(),
            "revocation".to_string(),
            "taint".to_string(),
            "transport".to_string(),
            "zone_policy".to_string(),
        ],
        "DecisionReasonCode namespace vocabulary drifted from documented set"
    );
}
