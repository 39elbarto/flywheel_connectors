//! Pin the exported policy verdict Display and serde-token contract.
//!
//! fcp-core does not expose a type literally named `PolicyVerdict`. The policy
//! verdict surface with both stable Display text and serde tags is
//! `DecisionReasonCode`, carried by `PolicyDecision`.
//!
//! Since a258d6976 ("align `DecisionReasonCode` serde tags with dotted
//! Display form") the serde wire tag IS the dotted Display token. The
//! pre-alignment
//! `snake_case` tags are pinned only so we can assert they stay rejected on
//! the wire.

use ciborium::value::Value as CborValue;
use fcp_core::DecisionReasonCode;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// `(verdict, canonical dotted token, legacy snake_case tag)`.
///
/// The canonical token is simultaneously the Display form and the serde wire
/// tag. The legacy tag column preserves the pre-a258d6976 wire form so the
/// rejection test can prove old tags are not silently accepted.
const POLICY_VERDICT_CASES: &[(DecisionReasonCode, &str, &str)] = &[
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

#[test]
fn policy_verdict_matrix_is_unique_and_complete() {
    let mut variants = std::collections::HashSet::new();
    let mut canonical_tokens = std::collections::HashSet::new();

    for (verdict, canonical_token, _) in POLICY_VERDICT_CASES {
        assert!(variants.insert(*verdict), "duplicate verdict {verdict:?}");
        assert!(
            canonical_tokens.insert(*canonical_token),
            "duplicate canonical token {canonical_token}"
        );
    }

    assert_eq!(
        variants.len(),
        35,
        "DecisionReasonCode has 35 documented verdict variants"
    );
}

#[test]
fn policy_verdict_display_tokens_are_pinned() {
    for (verdict, canonical_token, _) in POLICY_VERDICT_CASES {
        assert_eq!(verdict.as_str(), *canonical_token);
        assert_eq!(verdict.to_string(), *canonical_token);
        assert_eq!(format!("{verdict}"), *canonical_token);
    }
}

#[test]
fn policy_verdict_json_tags_are_pinned_and_roundtrip() -> TestResult {
    for (verdict, canonical_token, _) in POLICY_VERDICT_CASES {
        let json = serde_json::to_value(verdict)?;
        assert_eq!(json, serde_json::json!(canonical_token));

        let json_text = serde_json::to_string(verdict)?;
        assert_eq!(json_text, format!("\"{canonical_token}\""));

        let decoded: DecisionReasonCode = serde_json::from_value(json)?;
        assert_eq!(decoded, *verdict);
    }

    Ok(())
}

#[test]
fn policy_verdict_cbor_tags_are_text_and_roundtrip() -> TestResult {
    for (verdict, canonical_token, _) in POLICY_VERDICT_CASES {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(verdict, &mut bytes)?;

        let value: CborValue = ciborium::de::from_reader(bytes.as_slice())?;
        assert_eq!(value, CborValue::Text((*canonical_token).to_string()));

        let decoded: DecisionReasonCode = ciborium::de::from_reader(bytes.as_slice())?;
        assert_eq!(decoded, *verdict);
    }

    Ok(())
}

#[test]
fn policy_verdict_display_and_serde_tags_are_aligned() -> TestResult {
    // The a258d6976 contract: every verdict's serde wire tag equals its
    // Display token, so receipts and wire payloads carry the same string
    // operators read in logs.
    for (verdict, canonical_token, _) in POLICY_VERDICT_CASES {
        let wire_tag = serde_json::to_value(verdict)?;
        assert_eq!(
            wire_tag,
            serde_json::json!(verdict.to_string()),
            "Display token and serde wire tag must stay aligned for {verdict:?}"
        );
        assert_eq!(verdict.as_str(), *canonical_token);
    }

    Ok(())
}

#[test]
fn policy_verdict_rejects_legacy_snake_case_tags() {
    for (verdict, canonical_token, legacy_tag) in POLICY_VERDICT_CASES {
        if canonical_token == legacy_tag {
            // `allow` never changed shape.
            continue;
        }

        let legacy_json = format!("\"{legacy_tag}\"");
        assert!(
            serde_json::from_str::<DecisionReasonCode>(&legacy_json).is_err(),
            "legacy snake_case tag {legacy_json} must not be accepted as a wire tag for {verdict:?}"
        );
    }
}
