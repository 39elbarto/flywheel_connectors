//! Pin the public operation outcome wire surface.
//!
//! fcp-core does not currently expose a type literally named
//! `OperationOutcome`; operation result state is represented publicly by
//! `OperationStatus`.

use ciborium::value::Value as CborValue;
use fcp_core::OperationStatus;
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Case {
    status: OperationStatus,
    tag: &'static str,
}

const CASES: &[Case] = &[
    Case {
        status: OperationStatus::Pending,
        tag: "Pending",
    },
    Case {
        status: OperationStatus::Running,
        tag: "Running",
    },
    Case {
        status: OperationStatus::Completed,
        tag: "Completed",
    },
    Case {
        status: OperationStatus::Failed,
        tag: "Failed",
    },
];

#[test]
fn operation_outcome_status_json_and_cbor_tags_roundtrip() -> TestResult {
    for case in CASES {
        let json_value = serde_json::to_value(case.status)?;
        assert_eq!(json_value, json!(case.tag));

        let json_back: OperationStatus = serde_json::from_value(json_value)?;
        assert_eq!(json_back, case.status);

        let mut cbor_bytes = Vec::new();
        ciborium::ser::into_writer(&case.status, &mut cbor_bytes)?;

        let cbor_value: CborValue = ciborium::de::from_reader(cbor_bytes.as_slice())?;
        assert_eq!(cbor_value, CborValue::Text(case.tag.to_string()));

        let cbor_back: OperationStatus = ciborium::de::from_reader(cbor_bytes.as_slice())?;
        assert_eq!(cbor_back, case.status);
    }

    Ok(())
}

#[test]
fn operation_outcome_status_tags_are_case_sensitive() {
    for invalid in [
        r#""pending""#,
        r#""running""#,
        r#""completed""#,
        r#""failed""#,
        r#""succeeded""#,
    ] {
        assert!(
            serde_json::from_str::<OperationStatus>(invalid).is_err(),
            "non-canonical operation outcome tag accepted: {invalid}"
        );
    }
}
