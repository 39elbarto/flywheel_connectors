use fcp_core::ConnectorAlertLevel;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct ConnectorAlertLevelCase {
    value: ConnectorAlertLevel,
    tag: &'static str,
    cbor_hex: &'static str,
}

const CASES: &[ConnectorAlertLevelCase] = &[
    ConnectorAlertLevelCase {
        value: ConnectorAlertLevel::Ok,
        tag: "ok",
        cbor_hex: "626f6b",
    },
    ConnectorAlertLevelCase {
        value: ConnectorAlertLevel::Warning,
        tag: "warning",
        cbor_hex: "677761726e696e67",
    },
    ConnectorAlertLevelCase {
        value: ConnectorAlertLevel::Critical,
        tag: "critical",
        cbor_hex: "68637269746963616c",
    },
    ConnectorAlertLevelCase {
        value: ConnectorAlertLevel::Exceeded,
        tag: "exceeded",
        cbor_hex: "686578636565646564",
    },
];

#[test]
fn connector_alert_level_ordering_is_low_to_high_severity() {
    let expected = [
        ConnectorAlertLevel::Ok,
        ConnectorAlertLevel::Warning,
        ConnectorAlertLevel::Critical,
        ConnectorAlertLevel::Exceeded,
    ];
    let mut shuffled = [
        ConnectorAlertLevel::Critical,
        ConnectorAlertLevel::Ok,
        ConnectorAlertLevel::Exceeded,
        ConnectorAlertLevel::Warning,
    ];

    shuffled.sort();

    assert_eq!(shuffled, expected);
    assert!(ConnectorAlertLevel::Ok < ConnectorAlertLevel::Warning);
    assert!(ConnectorAlertLevel::Warning < ConnectorAlertLevel::Critical);
    assert!(ConnectorAlertLevel::Critical < ConnectorAlertLevel::Exceeded);
}

#[test]
fn connector_alert_level_display_matches_canonical_serde_tag() {
    for case in CASES {
        assert_eq!(case.value.as_str(), case.tag);
        assert_eq!(case.value.to_string(), case.tag);
    }
}

#[test]
fn connector_alert_level_json_tags_are_stable_and_roundtrip() -> TestResult {
    for case in CASES {
        let expected_json = format!(r#""{}""#, case.tag);
        let encoded = serde_json::to_string(&case.value)?;
        assert_eq!(encoded, expected_json);

        let decoded: ConnectorAlertLevel = serde_json::from_str(&expected_json)?;
        assert_eq!(decoded, case.value);
    }

    Ok(())
}

#[test]
fn connector_alert_level_cbor_tags_are_stable_and_roundtrip() -> TestResult {
    for case in CASES {
        let mut encoded = Vec::new();
        ciborium::into_writer(&case.value, &mut encoded)?;
        assert_eq!(hex::encode(&encoded), case.cbor_hex);

        let decoded: ConnectorAlertLevel = ciborium::from_reader(encoded.as_slice())?;
        assert_eq!(decoded, case.value);
    }

    Ok(())
}

#[test]
fn connector_alert_level_rejects_undocumented_tags() {
    for invalid in [
        r#""OK""#,
        r#""warn""#,
        r#""critical-alert""#,
        r#""over_budget""#,
    ] {
        assert!(
            serde_json::from_str::<ConnectorAlertLevel>(invalid).is_err(),
            "{invalid}"
        );
    }
}
