//! Pin fcp-core recovery-strategy variant Display and serde tags.
//!
//! fcp-core has no exported type literally named `RecoveryStrategy`. The
//! recovery protocol's public strategy enum is `ForkResolution`, which selects
//! how forked connector-state heads recover.

use fcp_core::ForkResolution;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct RecoveryStrategyCase {
    value: ForkResolution,
    display: &'static str,
    json_tag: &'static str,
    cbor_hex: &'static str,
}

const CASES: &[RecoveryStrategyCase] = &[
    RecoveryStrategyCase {
        value: ForkResolution::ChooseByLease,
        display: "choose_by_lease",
        json_tag: r#""choose_by_lease""#,
        cbor_hex: "6f63686f6f73655f62795f6c65617365",
    },
    RecoveryStrategyCase {
        value: ForkResolution::ManualResolution,
        display: "manual_resolution",
        json_tag: r#""manual_resolution""#,
        cbor_hex: "716d616e75616c5f7265736f6c7574696f6e",
    },
    RecoveryStrategyCase {
        value: ForkResolution::CrdtMerge,
        display: "crdt_merge",
        json_tag: r#""crdt_merge""#,
        cbor_hex: "6a637264745f6d65726765",
    },
];

#[test]
fn recovery_strategy_display_tokens_are_stable() {
    for case in CASES {
        assert_eq!(case.value.to_string(), case.display);
    }
}

#[test]
fn recovery_strategy_json_tags_are_stable_and_roundtrip() -> TestResult {
    for case in CASES {
        let encoded = serde_json::to_string(&case.value)?;
        assert_eq!(encoded, case.json_tag);
        assert_eq!(encoded.trim_matches('"'), case.display);

        let decoded: ForkResolution = serde_json::from_str(case.json_tag)?;
        assert_eq!(decoded, case.value);
    }

    Ok(())
}

#[test]
fn recovery_strategy_cbor_tags_are_stable_and_roundtrip() -> TestResult {
    for case in CASES {
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&case.value, &mut encoded)?;
        assert_eq!(hex::encode(&encoded), case.cbor_hex);

        let decoded: ForkResolution = ciborium::de::from_reader(encoded.as_slice())?;
        assert_eq!(decoded, case.value);
    }

    Ok(())
}

#[test]
fn recovery_strategy_rejects_noncanonical_json_tags() {
    for invalid in [
        r#""ChooseByLease""#,
        r#""choose-by-lease""#,
        r#""manual""#,
        r#""crdt""#,
        r#""replay_safe_retry""#,
    ] {
        assert!(
            serde_json::from_str::<ForkResolution>(invalid).is_err(),
            "{invalid} must not decode as a canonical recovery strategy"
        );
    }
}
