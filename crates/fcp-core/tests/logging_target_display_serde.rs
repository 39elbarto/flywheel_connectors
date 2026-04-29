use ciborium::value::Value as CborValue;
use fcp_core::LoggingTarget;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct LoggingTargetCase {
    value: LoggingTarget,
    tag: &'static str,
    cbor_hex: &'static str,
}

const CASES: &[LoggingTargetCase] = &[
    LoggingTargetCase {
        value: LoggingTarget::Stdout,
        tag: "stdout",
        cbor_hex: "667374646f7574",
    },
    LoggingTargetCase {
        value: LoggingTarget::Stderr,
        tag: "stderr",
        cbor_hex: "66737464657272",
    },
    LoggingTargetCase {
        value: LoggingTarget::Host,
        tag: "host",
        cbor_hex: "64686f7374",
    },
    LoggingTargetCase {
        value: LoggingTarget::Audit,
        tag: "audit",
        cbor_hex: "656175646974",
    },
];

#[test]
fn logging_target_display_matches_canonical_serde_tag() {
    for case in CASES {
        assert_eq!(case.value.as_str(), case.tag);
        assert_eq!(case.value.to_string(), case.tag);
    }
}

#[test]
fn logging_target_json_tags_are_stable_and_roundtrip() -> TestResult {
    for case in CASES {
        let expected_json = format!(r#""{}""#, case.tag);
        let encoded = serde_json::to_string(&case.value)?;
        assert_eq!(encoded, expected_json);

        let decoded: LoggingTarget = serde_json::from_str(&expected_json)?;
        assert_eq!(decoded, case.value);
    }

    Ok(())
}

#[test]
fn logging_target_cbor_tags_are_text_and_roundtrip() -> TestResult {
    for case in CASES {
        let mut encoded = Vec::new();
        ciborium::into_writer(&case.value, &mut encoded)?;
        assert_eq!(hex::encode(&encoded), case.cbor_hex);

        let value: CborValue = ciborium::from_reader(encoded.as_slice())?;
        assert_eq!(value, CborValue::Text(case.tag.to_owned()));

        let decoded: LoggingTarget = ciborium::from_reader(encoded.as_slice())?;
        assert_eq!(decoded, case.value);
    }

    Ok(())
}

#[test]
fn logging_target_tags_are_pairwise_distinct() {
    assert_eq!(CASES.len(), 4);

    for (left_index, left) in CASES.iter().enumerate() {
        for right in &CASES[left_index + 1..] {
            assert_ne!(left.value, right.value);
            assert_ne!(left.tag, right.tag);
            assert_ne!(left.value.to_string(), right.value.to_string());
        }
    }
}

#[test]
fn logging_target_rejects_noncanonical_json_tags() {
    for invalid in [
        r#""Stdout""#,
        r#""STDERR""#,
        r#""std_out""#,
        r#""audit-log""#,
        r#""metrics""#,
        r#""""#,
    ] {
        assert!(
            serde_json::from_str::<LoggingTarget>(invalid).is_err(),
            "{invalid}"
        );
    }
}
