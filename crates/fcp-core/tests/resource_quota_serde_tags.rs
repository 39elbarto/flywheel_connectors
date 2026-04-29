//! Pin the fcp-core resource-quota serde tag contract.
//!
//! There is no public `ResourceQuota` type in fcp-core. Resource-quota
//! violations are represented by the rate-limit/resource-limit classifier
//! `LimitType::Quota`, including when embedded in throttle violation records.
//! This test pins that canonical JSON and CBOR wire tag.

use fcp_core::{LimitType, ThrottleViolationInput, ZoneId};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn resource_quota_limit_type_json_tag_is_stable_and_roundtrips() -> TestResult {
    let encoded = serde_json::to_string(&LimitType::Quota)?;
    assert_eq!(encoded, r#""quota""#);

    let decoded: LimitType = serde_json::from_str(r#""quota""#)?;
    assert_eq!(decoded, LimitType::Quota);

    Ok(())
}

#[test]
fn resource_quota_limit_type_cbor_tag_is_stable_and_roundtrips() -> TestResult {
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&LimitType::Quota, &mut encoded)?;
    assert_eq!(hex::encode(&encoded), "6571756f7461");

    let decoded: LimitType = ciborium::de::from_reader(encoded.as_slice())?;
    assert_eq!(decoded, LimitType::Quota);

    let expected_cbor = [0x65, b'q', b'u', b'o', b't', b'a'];
    let decoded_from_expected: LimitType = ciborium::de::from_reader(expected_cbor.as_slice())?;
    assert_eq!(decoded_from_expected, LimitType::Quota);

    Ok(())
}

#[test]
fn throttle_violation_input_preserves_resource_quota_tag_in_json_and_cbor() -> TestResult {
    let input = quota_violation_input();

    let json_value = serde_json::to_value(&input)?;
    assert_eq!(json_value["limit_type"], "quota");

    let json_roundtrip: ThrottleViolationInput = serde_json::from_value(json_value)?;
    assert_eq!(json_roundtrip.limit_type, LimitType::Quota);
    assert_eq!(json_roundtrip.limit_value, 10_000);
    assert_eq!(json_roundtrip.current_value, 10_001);

    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&input, &mut cbor)?;
    let cbor_roundtrip: ThrottleViolationInput = ciborium::de::from_reader(cbor.as_slice())?;
    assert_eq!(cbor_roundtrip.limit_type, LimitType::Quota);
    assert_eq!(cbor_roundtrip.limit_value, 10_000);
    assert_eq!(cbor_roundtrip.current_value, 10_001);

    Ok(())
}

#[test]
fn resource_quota_rejects_noncanonical_json_tags() {
    for invalid in [
        r#""Quota""#,
        r#""resource_quota""#,
        r#""resource-quota""#,
        r#""quota_limit""#,
        r#""QUOTA""#,
    ] {
        assert!(
            serde_json::from_str::<LimitType>(invalid).is_err(),
            "{invalid} must not decode as the canonical quota tag"
        );
    }
}

fn quota_violation_input() -> ThrottleViolationInput {
    ThrottleViolationInput {
        timestamp_ms: 1_700_000_000_000,
        zone_id: ZoneId::work(),
        connector_id: None,
        operation_id: None,
        limit_type: LimitType::Quota,
        limit_value: 10_000,
        current_value: 10_001,
        retry_after_ms: 60_000,
    }
}
