//! Pin `ConnectorRecoveryAction` variant Display and serde tags.

use fcp_core::ConnectorRecoveryAction;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct ConnectorRecoveryActionCase {
    value: ConnectorRecoveryAction,
    tag: &'static str,
    cbor_hex: &'static str,
}

const CASES: &[ConnectorRecoveryActionCase] = &[
    ConnectorRecoveryActionCase {
        value: ConnectorRecoveryAction::RestartConnector,
        tag: "restart_connector",
        cbor_hex: "71726573746172745f636f6e6e6563746f72",
    },
    ConnectorRecoveryActionCase {
        value: ConnectorRecoveryAction::RepairConnector,
        tag: "repair_connector",
        cbor_hex: "707265706169725f636f6e6e6563746f72",
    },
    ConnectorRecoveryActionCase {
        value: ConnectorRecoveryAction::ReinstallConnector,
        tag: "reinstall_connector",
        cbor_hex: "737265696e7374616c6c5f636f6e6e6563746f72",
    },
    ConnectorRecoveryActionCase {
        value: ConnectorRecoveryAction::CompleteRollout,
        tag: "complete_rollout",
        cbor_hex: "70636f6d706c6574655f726f6c6c6f7574",
    },
    ConnectorRecoveryActionCase {
        value: ConnectorRecoveryAction::DisableConnector,
        tag: "disable_connector",
        cbor_hex: "7164697361626c655f636f6e6e6563746f72",
    },
    ConnectorRecoveryActionCase {
        value: ConnectorRecoveryAction::Investigate,
        tag: "investigate",
        cbor_hex: "6b696e766573746967617465",
    },
];

#[test]
fn connector_recovery_action_display_tokens_are_stable() {
    for case in CASES {
        assert_eq!(case.value.to_string(), case.tag);
        assert_eq!(case.value.label(), case.tag);
    }
}

#[test]
fn connector_recovery_action_json_tags_are_stable_and_roundtrip() -> TestResult {
    for case in CASES {
        let encoded = serde_json::to_string(&case.value)?;
        assert_eq!(encoded, format!("\"{}\"", case.tag));
        assert_eq!(encoded.trim_matches('"'), case.value.to_string());

        let decoded: ConnectorRecoveryAction = serde_json::from_str(&encoded)?;
        assert_eq!(decoded, case.value);
    }

    Ok(())
}

#[test]
fn connector_recovery_action_cbor_tags_are_stable_and_roundtrip() -> TestResult {
    for case in CASES {
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&case.value, &mut encoded)?;
        assert_eq!(hex::encode(&encoded), case.cbor_hex);

        let decoded: ConnectorRecoveryAction = ciborium::de::from_reader(encoded.as_slice())?;
        assert_eq!(decoded, case.value);
    }

    Ok(())
}

#[test]
fn connector_recovery_action_tags_are_pairwise_distinct() {
    for (left_index, left) in CASES.iter().enumerate() {
        for right in &CASES[left_index + 1..] {
            assert_ne!(left.value, right.value);
            assert_ne!(left.tag, right.tag);
            assert_ne!(left.cbor_hex, right.cbor_hex);
        }
    }
}

#[test]
fn connector_recovery_action_rejects_noncanonical_json_tags() {
    for invalid in [
        r#""RestartConnector""#,
        r#""restart-connector""#,
        r#""restart""#,
        r#""repair""#,
        r#""disable""#,
        r#""manual_resolution""#,
        r#""""#,
    ] {
        assert!(
            serde_json::from_str::<ConnectorRecoveryAction>(invalid).is_err(),
            "{invalid} must not decode as a canonical connector recovery action"
        );
    }
}
