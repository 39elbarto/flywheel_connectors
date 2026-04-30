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
        DecisionReasonCode::ZonePolicyPrincipalDenied,
        "zone_policy.principal_denied",
        "zone_policy_principal_denied",
    ),
    (
        DecisionReasonCode::ApprovalMissingExecution,
        "approval.missing_execution",
        "approval_missing_execution",
    ),
    (
        DecisionReasonCode::OperationForbidden,
        "operation.forbidden",
        "operation_forbidden",
    ),
];

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
