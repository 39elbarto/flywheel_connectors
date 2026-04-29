//! Pin operation-intent resolution tags.
//!
//! fcp-core has no public type literally named `IntentResolution`; the
//! operation intent resolution surface is `IntentStatus`, which records whether
//! an intent is pending, in progress, completed, failed, or orphaned.

use ciborium::value::Value as CborValue;
use fcp_core::IntentStatus;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const CASES: &[(IntentStatus, &str)] = &[
    (IntentStatus::Pending, "pending"),
    (IntentStatus::InProgress, "in_progress"),
    (IntentStatus::Completed, "completed"),
    (IntentStatus::Failed, "failed"),
    (IntentStatus::Orphaned, "orphaned"),
];

#[test]
fn intent_resolution_display_tokens_are_stable() {
    for (status, expected) in CASES {
        assert_eq!(status.to_string(), *expected);
        assert_eq!(format!("{status}"), *expected);
    }
}

#[test]
fn intent_resolution_json_serde_tags_match_display() -> TestResult {
    for (status, expected) in CASES {
        let json = serde_json::to_string(status)?;
        assert_eq!(json, format!(r#""{expected}""#));

        let decoded: IntentStatus = serde_json::from_str(&json)?;
        assert_eq!(decoded, *status);

        let displayed = status.to_string();
        let value = serde_json::to_value(status)?;
        assert_eq!(value.as_str(), Some(*expected));
        assert_eq!(value.as_str(), Some(displayed.as_str()));
    }

    Ok(())
}

#[test]
fn intent_resolution_cbor_serde_tags_are_text_and_roundtrip() -> TestResult {
    for (status, expected) in CASES {
        let mut bytes = Vec::new();
        ciborium::into_writer(status, &mut bytes)?;

        let value: CborValue = ciborium::from_reader(bytes.as_slice())?;
        assert_eq!(value, CborValue::Text((*expected).to_owned()));

        let decoded: IntentStatus = ciborium::from_reader(bytes.as_slice())?;
        assert_eq!(decoded, *status);
    }

    Ok(())
}

#[test]
fn intent_resolution_rejects_noncanonical_json_tags() {
    for invalid in [
        r#""Pending""#,
        r#""InProgress""#,
        r#""in-progress""#,
        r#""completed_receipt""#,
        r#""intent_resolution""#,
    ] {
        assert!(serde_json::from_str::<IntentStatus>(invalid).is_err());
    }
}
