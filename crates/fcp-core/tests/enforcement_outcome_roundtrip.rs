//! Pin enforcement outcome serde roundtrips.
//!
//! fcp-core exposes enforcement outcomes as `CheckOutcome`; there is no
//! separate public `EnforcementOutcome` type. These tests pin the variant set
//! and the JSON/CBOR tag contract used by enforcement audit records.

use ciborium::value::Value as CborValue;
use fcp_core::CheckOutcome;
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn cbor_outcome_tag(outcome: &CheckOutcome) -> TestResult<Option<String>> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(outcome, &mut bytes)?;
    let value: CborValue = ciborium::de::from_reader(bytes.as_slice())?;
    let CborValue::Map(entries) = value else {
        return Ok(None);
    };

    Ok(entries
        .iter()
        .find_map(|(key, value)| match (key, value) {
            (CborValue::Text(key), CborValue::Text(tag)) if key == "outcome" => Some(tag.clone()),
            _ => None,
        }))
}

#[test]
fn enforcement_outcome_variants_json_and_cbor_roundtrip() -> TestResult {
    let cases = [
        (CheckOutcome::Allow, json!({ "outcome": "allow" }), "allow"),
        (
            CheckOutcome::Deny {
                reason_code: "capability.denied".to_string(),
                explanation: "capability was not granted".to_string(),
            },
            json!({
                "outcome": "deny",
                "reason_code": "capability.denied",
                "explanation": "capability was not granted"
            }),
            "deny",
        ),
        (
            CheckOutcome::Skip {
                reason: "not applicable for this request".to_string(),
            },
            json!({
                "outcome": "skip",
                "reason": "not applicable for this request"
            }),
            "skip",
        ),
    ];

    assert_eq!(
        cases.len(),
        3,
        "CheckOutcome should remain the three enforcement outcomes: allow, deny, skip"
    );

    for (original, expected_json, expected_tag) in cases {
        let json_value = serde_json::to_value(&original)?;
        assert_eq!(json_value, expected_json);
        let json_back: CheckOutcome = serde_json::from_value(json_value)?;
        assert_eq!(json_back, original);

        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&original, &mut bytes)?;
        let cbor_back: CheckOutcome = ciborium::de::from_reader(bytes.as_slice())?;
        assert_eq!(cbor_back, original);
        assert_eq!(cbor_outcome_tag(&original)?, Some(expected_tag.to_string()));
    }

    Ok(())
}

#[test]
fn enforcement_outcome_rejects_non_canonical_json_tags() {
    for json in [
        r#"{"outcome":"Allow"}"#,
        r#"{"outcome":"denied"}"#,
        r#"{"type":"allow"}"#,
    ] {
        assert!(
            serde_json::from_str::<CheckOutcome>(json).is_err(),
            "CheckOutcome must reject non-canonical JSON tag shape: {json}"
        );
    }
}
