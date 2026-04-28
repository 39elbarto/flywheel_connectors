use fcp_core::DescriptorStatus as LiveStatus;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct LiveStatusCase {
    value: LiveStatus,
    json_tag: &'static str,
    cbor_hex: &'static str,
}

const CASES: &[LiveStatusCase] = &[
    LiveStatusCase {
        value: LiveStatus::Ready,
        json_tag: r#""ready""#,
        cbor_hex: "657265616479",
    },
    LiveStatusCase {
        value: LiveStatus::Degraded,
        json_tag: r#""degraded""#,
        cbor_hex: "686465677261646564",
    },
    LiveStatusCase {
        value: LiveStatus::Failed,
        json_tag: r#""failed""#,
        cbor_hex: "666661696c6564",
    },
    LiveStatusCase {
        value: LiveStatus::Missing,
        json_tag: r#""missing""#,
        cbor_hex: "676d697373696e67",
    },
    LiveStatusCase {
        value: LiveStatus::Drifted,
        json_tag: r#""drifted""#,
        cbor_hex: "6764726966746564",
    },
    LiveStatusCase {
        value: LiveStatus::Unverifiable,
        json_tag: r#""unverifiable""#,
        cbor_hex: "6c756e76657269666961626c65",
    },
    LiveStatusCase {
        value: LiveStatus::PolicyBlocked,
        json_tag: r#""policy_blocked""#,
        cbor_hex: "6e706f6c6963795f626c6f636b6564",
    },
    LiveStatusCase {
        value: LiveStatus::Unsupported,
        json_tag: r#""unsupported""#,
        cbor_hex: "6b756e737570706f72746564",
    },
    LiveStatusCase {
        value: LiveStatus::Unknown,
        json_tag: r#""unknown""#,
        cbor_hex: "67756e6b6e6f776e",
    },
    LiveStatusCase {
        value: LiveStatus::NotYetMeasured,
        json_tag: r#""not_yet_measured""#,
        cbor_hex: "706e6f745f7965745f6d65617375726564",
    },
    LiveStatusCase {
        value: LiveStatus::Unavailable,
        json_tag: r#""unavailable""#,
        cbor_hex: "6b756e617661696c61626c65",
    },
];

#[test]
fn live_status_json_tags_are_stable_and_roundtrip() -> TestResult {
    for case in CASES {
        let encoded = serde_json::to_string(&case.value)?;
        assert_eq!(encoded, case.json_tag);

        let decoded: LiveStatus = serde_json::from_str(case.json_tag)?;
        assert_eq!(decoded, case.value);
    }

    Ok(())
}

#[test]
fn live_status_cbor_tags_are_stable_and_roundtrip() -> TestResult {
    for case in CASES {
        let mut encoded = Vec::new();
        ciborium::into_writer(&case.value, &mut encoded)?;
        assert_eq!(hex::encode(&encoded), case.cbor_hex);

        let decoded: LiveStatus = ciborium::from_reader(encoded.as_slice())?;
        assert_eq!(decoded, case.value);
    }

    Ok(())
}
