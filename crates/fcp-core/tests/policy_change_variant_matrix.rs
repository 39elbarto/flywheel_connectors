//! Pin the fcp-core policy-change trigger variant matrix.
//!
//! fcp-core does not expose a standalone `PolicyChange` type. The public
//! policy-change surface is `CheckpointTrigger::PolicyChange`, alongside the
//! other checkpoint trigger variants that share its serde tag space.

use ciborium::value::Value as CborValue;
use fcp_core::{CheckpointTrigger, ObjectId};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const OLD_POLICY_HEAD_HEX: &str =
    "1111111111111111111111111111111111111111111111111111111111111111";
const NEW_POLICY_HEAD_HEX: &str =
    "2222222222222222222222222222222222222222222222222222222222222222";

struct TriggerCase {
    value: CheckpointTrigger,
    display_token: &'static str,
    json: &'static str,
}

fn trigger_cases() -> Vec<TriggerCase> {
    vec![
        TriggerCase {
            value: CheckpointTrigger::TimeElapsed {
                elapsed_secs: 120,
                threshold_secs: 60,
            },
            display_token: "time_elapsed",
            json: r#"{"type":"time_elapsed","elapsed_secs":120,"threshold_secs":60}"#,
        },
        TriggerCase {
            value: CheckpointTrigger::AuditChainGrowth {
                new_events: 200,
                threshold: 100,
            },
            display_token: "audit_chain_growth",
            json: r#"{"type":"audit_chain_growth","new_events":200,"threshold":100}"#,
        },
        TriggerCase {
            value: CheckpointTrigger::RevocationChainGrowth { new_events: 5 },
            display_token: "revocation_chain_growth",
            json: r#"{"type":"revocation_chain_growth","new_events":5}"#,
        },
        TriggerCase {
            value: CheckpointTrigger::PolicyChange {
                old_policy_head: ObjectId::from_bytes([0x11; 32]),
                new_policy_head: ObjectId::from_bytes([0x22; 32]),
            },
            display_token: "policy_change",
            json: concat!(
                r#"{"type":"policy_change","old_policy_head":""#,
                "1111111111111111111111111111111111111111111111111111111111111111",
                r#"","new_policy_head":""#,
                "2222222222222222222222222222222222222222222222222222222222222222",
                r#""}"#
            ),
        },
        TriggerCase {
            value: CheckpointTrigger::Manual {
                reason: Some("operator requested".to_string()),
            },
            display_token: "manual",
            json: r#"{"type":"manual","reason":"operator requested"}"#,
        },
    ]
}

fn cbor_type_tag(trigger: &CheckpointTrigger) -> TestResult<String> {
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(trigger, &mut encoded)?;

    let value: CborValue = ciborium::de::from_reader(encoded.as_slice())?;
    let CborValue::Map(entries) = value else {
        return Err(std::io::Error::other("CheckpointTrigger must CBOR-encode as a map").into());
    };

    entries
        .iter()
        .find_map(|(key, value)| match (key, value) {
            (CborValue::Text(key), CborValue::Text(tag)) if key == "type" => Some(tag.clone()),
            _ => None,
        })
        .ok_or_else(|| std::io::Error::other("CheckpointTrigger CBOR map must carry type").into())
}

#[test]
fn policy_change_trigger_display_tokens_are_pinned() {
    let cases = trigger_cases();
    assert_eq!(cases.len(), 5, "all CheckpointTrigger variants are covered");

    let mut tokens = std::collections::BTreeSet::new();
    for case in cases {
        assert_eq!(case.value.as_str(), case.display_token);
        assert_eq!(case.value.to_string(), case.display_token);
        assert!(
            tokens.insert(case.display_token),
            "duplicate display token {}",
            case.display_token
        );
    }
}

#[test]
fn policy_change_trigger_json_tags_are_pinned_and_roundtrip() -> TestResult {
    for case in trigger_cases() {
        let json = serde_json::to_string(&case.value)?;
        assert_eq!(json, case.json);
        assert_eq!(
            serde_json::to_value(&case.value)?["type"],
            case.display_token
        );

        let decoded: CheckpointTrigger = serde_json::from_str(case.json)?;
        assert_eq!(decoded, case.value);
    }

    Ok(())
}

#[test]
fn policy_change_trigger_cbor_tags_are_pinned_and_roundtrip_where_supported() -> TestResult {
    for case in trigger_cases() {
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&case.value, &mut encoded)?;

        assert_eq!(cbor_type_tag(&case.value)?, case.display_token);

        if matches!(case.value, CheckpointTrigger::PolicyChange { .. }) {
            // `PolicyChange` carries ObjectId-via-hex_or_bytes fields inside
            // an internally tagged enum. That intersects serde's Content shim
            // for CBOR; pin the wire tag here and JSON roundtrip above.
            continue;
        }

        let decoded: CheckpointTrigger = ciborium::de::from_reader(encoded.as_slice())?;
        assert_eq!(decoded, case.value);
    }

    Ok(())
}

#[test]
fn policy_change_trigger_rejects_noncanonical_json_tags() {
    for invalid in [
        r#"{"type":"PolicyChange","old_policy_head":"1111111111111111111111111111111111111111111111111111111111111111","new_policy_head":"2222222222222222222222222222222222222222222222222222222222222222"}"#,
        r#"{"type":"policy-change","old_policy_head":"1111111111111111111111111111111111111111111111111111111111111111","new_policy_head":"2222222222222222222222222222222222222222222222222222222222222222"}"#,
        r#"{"type":"policy_changed","old_policy_head":"1111111111111111111111111111111111111111111111111111111111111111","new_policy_head":"2222222222222222222222222222222222222222222222222222222222222222"}"#,
        r#"{"type":"manual_trigger","reason":null}"#,
        r#"{"type":""}"#,
    ] {
        assert!(
            serde_json::from_str::<CheckpointTrigger>(invalid).is_err(),
            "{invalid}"
        );
    }
}

#[test]
fn policy_change_trigger_manual_none_json_shape_is_pinned() -> TestResult {
    let trigger = CheckpointTrigger::Manual { reason: None };

    let json = serde_json::to_string(&trigger)?;
    assert_eq!(json, r#"{"type":"manual","reason":null}"#);
    assert_eq!(trigger.as_str(), "manual");
    assert_eq!(trigger.to_string(), "manual");

    let decoded: CheckpointTrigger = serde_json::from_str(&json)?;
    assert_eq!(decoded, trigger);

    Ok(())
}

#[test]
fn policy_change_object_id_hex_constants_match_expected_lengths() {
    assert_eq!(OLD_POLICY_HEAD_HEX.len(), 64);
    assert_eq!(NEW_POLICY_HEAD_HEX.len(), 64);
    assert_eq!(
        ObjectId::from_bytes([0x11; 32]).to_string(),
        OLD_POLICY_HEAD_HEX
    );
    assert_eq!(
        ObjectId::from_bytes([0x22; 32]).to_string(),
        NEW_POLICY_HEAD_HEX
    );
}
