//! Pin the fcp-core recall-policy display and serde matrix.
//!
//! There is no public type literally named `RecallPolicy` in fcp-core. The
//! recall/cached-data policy surface is `FreshnessPolicy`: it controls whether
//! a caller must recall a fresh revocation frontier, may use bounded cached
//! data with a warning, or may proceed best-effort with stale cached data.

use ciborium::value::Value as CborValue;
use fcp_core::FreshnessPolicy as RecallPolicy;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const CASES: &[(RecallPolicy, &str, &str)] = &[
    (RecallPolicy::Strict, "strict", "Strict"),
    (RecallPolicy::Warn, "warn", "Warn"),
    (RecallPolicy::BestEffort, "best_effort", "BestEffort"),
];

#[test]
fn recall_policy_display_tokens_are_pinned() {
    assert_eq!(
        CASES.len(),
        3,
        "RecallPolicy/FreshnessPolicy has three documented variants"
    );

    for (policy, display_token, _) in CASES {
        assert_eq!(policy.as_str(), *display_token);
        assert_eq!(policy.to_string(), *display_token);
    }
}

#[test]
fn recall_policy_json_tags_are_pinned_and_roundtrip() -> TestResult {
    for (policy, _, serde_tag) in CASES {
        let json_text = serde_json::to_string(policy)?;
        assert_eq!(json_text, format!("\"{serde_tag}\""));

        let json = serde_json::to_value(policy)?;
        assert_eq!(json, serde_json::json!(serde_tag));

        let decoded: RecallPolicy = serde_json::from_str(&json_text)?;
        assert_eq!(decoded, *policy);
    }

    Ok(())
}

#[test]
fn recall_policy_cbor_tags_are_text_and_roundtrip() -> TestResult {
    for (policy, _, serde_tag) in CASES {
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(policy, &mut encoded)?;

        let value: CborValue = ciborium::de::from_reader(encoded.as_slice())?;
        assert_eq!(value, CborValue::Text((*serde_tag).to_string()));

        let decoded: RecallPolicy = ciborium::de::from_reader(encoded.as_slice())?;
        assert_eq!(decoded, *policy);
    }

    Ok(())
}

#[test]
fn recall_policy_display_tokens_are_not_json_wire_tags() {
    for (_, display_token, serde_tag) in CASES {
        assert_ne!(
            *display_token, *serde_tag,
            "display token and serde tag should remain independently pinned"
        );

        let display_json = format!("\"{display_token}\"");
        assert!(
            serde_json::from_str::<RecallPolicy>(&display_json).is_err(),
            "human display token {display_json} must not be accepted as the serde wire tag"
        );
    }
}
