use fcp_core::OperationStatus;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct OperationStatusCase {
    value: OperationStatus,
    json_tag: &'static str,
    cbor_hex: &'static str,
}

const CASES: &[OperationStatusCase] = &[
    OperationStatusCase {
        value: OperationStatus::Pending,
        json_tag: r#""Pending""#,
        cbor_hex: "6750656e64696e67",
    },
    OperationStatusCase {
        value: OperationStatus::Running,
        json_tag: r#""Running""#,
        cbor_hex: "6752756e6e696e67",
    },
    OperationStatusCase {
        value: OperationStatus::Completed,
        json_tag: r#""Completed""#,
        cbor_hex: "69436f6d706c65746564",
    },
    OperationStatusCase {
        value: OperationStatus::Failed,
        json_tag: r#""Failed""#,
        cbor_hex: "664661696c6564",
    },
];

#[test]
fn operation_status_json_tags_are_stable_and_roundtrip() -> TestResult {
    for case in CASES {
        let encoded = serde_json::to_string(&case.value)?;
        assert_eq!(encoded, case.json_tag);

        let decoded: OperationStatus = serde_json::from_str(case.json_tag)?;
        assert_eq!(decoded, case.value);
    }

    Ok(())
}

#[test]
fn operation_status_cbor_tags_are_stable_and_roundtrip() -> TestResult {
    for case in CASES {
        let mut encoded = Vec::new();
        ciborium::into_writer(&case.value, &mut encoded)?;
        assert_eq!(hex::encode(&encoded), case.cbor_hex);

        let decoded: OperationStatus = ciborium::from_reader(encoded.as_slice())?;
        assert_eq!(decoded, case.value);
    }

    Ok(())
}

#[test]
fn operation_status_rejects_unknown_json_tags() {
    for invalid in [
        r#""pending""#,
        r#""InProgress""#,
        r#""Succeeded""#,
        r#""Cancelled""#,
    ] {
        assert!(
            serde_json::from_str::<OperationStatus>(invalid).is_err(),
            "{invalid}"
        );
    }
}
