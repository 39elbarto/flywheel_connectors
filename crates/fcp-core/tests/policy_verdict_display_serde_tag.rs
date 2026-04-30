//! Pin the exported policy verdict Display and serde-token contract.
//!
//! fcp-core does not expose a type literally named `PolicyVerdict`. The policy
//! verdict surface with both stable Display text and serde tags is
//! `DecisionReasonCode`, carried by `PolicyDecision`.

use ciborium::value::Value as CborValue;
use fcp_core::DecisionReasonCode;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

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
    let mut display_tokens = std::collections::HashSet::new();
    let mut serde_tags = std::collections::HashSet::new();

    for (verdict, display_token, serde_tag) in POLICY_VERDICT_CASES {
        assert!(variants.insert(*verdict), "duplicate verdict {verdict:?}");
        assert!(
            display_tokens.insert(*display_token),
            "duplicate Display token {display_token}"
        );
        assert!(
            serde_tags.insert(*serde_tag),
            "duplicate serde tag {serde_tag}"
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
    for (verdict, display_token, _) in POLICY_VERDICT_CASES {
        assert_eq!(verdict.as_str(), *display_token);
        assert_eq!(verdict.to_string(), *display_token);
        assert_eq!(format!("{verdict}"), *display_token);
    }
}

#[test]
fn policy_verdict_json_tags_are_pinned_and_roundtrip() -> TestResult {
    for (verdict, _, serde_tag) in POLICY_VERDICT_CASES {
        let json = serde_json::to_value(verdict)?;
        assert_eq!(json, serde_json::json!(serde_tag));

        let json_text = serde_json::to_string(verdict)?;
        assert_eq!(json_text, format!("\"{serde_tag}\""));

        let decoded: DecisionReasonCode = serde_json::from_value(json)?;
        assert_eq!(decoded, *verdict);
    }

    Ok(())
}

#[test]
fn policy_verdict_cbor_tags_are_text_and_roundtrip() -> TestResult {
    for (verdict, _, serde_tag) in POLICY_VERDICT_CASES {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(verdict, &mut bytes)?;

        let value: CborValue = ciborium::de::from_reader(bytes.as_slice())?;
        assert_eq!(value, CborValue::Text((*serde_tag).to_string()));

        let decoded: DecisionReasonCode = ciborium::de::from_reader(bytes.as_slice())?;
        assert_eq!(decoded, *verdict);
    }

    Ok(())
}

#[test]
fn policy_verdict_display_tokens_are_not_accepted_as_wire_tags_when_dotted() {
    for (verdict, display_token, serde_tag) in POLICY_VERDICT_CASES {
        if display_token == serde_tag {
            continue;
        }

        assert!(
            display_token.contains('.'),
            "test sentinel assumes {verdict:?} has a dotted Display token"
        );

        let display_json = format!("\"{display_token}\"");
        assert!(
            serde_json::from_str::<DecisionReasonCode>(&display_json).is_err(),
            "Display token {display_json} must not be accepted as serde wire tag"
        );
    }
}
