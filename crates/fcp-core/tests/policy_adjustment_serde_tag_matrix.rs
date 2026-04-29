//! Pin the policy adjustment serde tag matrix.
//!
//! fcp-core does not expose a literal `PolicyAdjustment` type. The
//! proof-carrying policy adjustment surface is `LabelAdjustment`,
//! classified by `AdjustmentKind`.

use ciborium::value::Value as CborValue;
use fcp_core::{AdjustmentKind, ConfidentialityLevel, IntegrityLevel, LabelAdjustment, ObjectId};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const CASES: &[(AdjustmentKind, &str)] = &[
    (AdjustmentKind::Elevation, "elevation"),
    (AdjustmentKind::Declassification, "declassification"),
];

fn elevation_adjustment() -> LabelAdjustment {
    LabelAdjustment {
        timestamp_ms: 1_775_000_001,
        kind: AdjustmentKind::Elevation,
        approval_token_id: ObjectId::from_bytes([0xA1; 32]),
        prev_integrity: Some(IntegrityLevel::Work),
        new_integrity: Some(IntegrityLevel::Owner),
        prev_confidentiality: None,
        new_confidentiality: None,
    }
}

fn declassification_adjustment() -> LabelAdjustment {
    LabelAdjustment {
        timestamp_ms: 1_775_000_002,
        kind: AdjustmentKind::Declassification,
        approval_token_id: ObjectId::from_bytes([0xD1; 32]),
        prev_integrity: None,
        new_integrity: None,
        prev_confidentiality: Some(ConfidentialityLevel::Owner),
        new_confidentiality: Some(ConfidentialityLevel::Work),
    }
}

fn assert_adjustment_eq(actual: &LabelAdjustment, expected: &LabelAdjustment) {
    assert_eq!(actual.timestamp_ms, expected.timestamp_ms);
    assert_eq!(actual.kind, expected.kind);
    assert_eq!(actual.approval_token_id, expected.approval_token_id);
    assert_eq!(actual.prev_integrity, expected.prev_integrity);
    assert_eq!(actual.new_integrity, expected.new_integrity);
    assert_eq!(actual.prev_confidentiality, expected.prev_confidentiality);
    assert_eq!(actual.new_confidentiality, expected.new_confidentiality);
}

#[test]
fn adjustment_kind_json_tags_are_stable_and_roundtrip() -> TestResult {
    for (kind, expected_tag) in CASES {
        let json = serde_json::to_string(kind)?;
        assert_eq!(json, format!("\"{expected_tag}\""));

        let decoded: AdjustmentKind = serde_json::from_str(&json)?;
        assert_eq!(decoded, *kind);
    }

    Ok(())
}

#[test]
fn adjustment_kind_cbor_tags_are_stable_and_roundtrip() -> TestResult {
    for (kind, expected_tag) in CASES {
        let mut encoded = Vec::new();
        ciborium::into_writer(kind, &mut encoded)?;

        let value: CborValue = ciborium::from_reader(encoded.as_slice())?;
        assert_eq!(
            value,
            CborValue::Text((*expected_tag).to_string()),
            "AdjustmentKind CBOR tag drift for {kind:?}"
        );

        let decoded: AdjustmentKind = ciborium::from_reader(encoded.as_slice())?;
        assert_eq!(decoded, *kind);
    }

    Ok(())
}

#[test]
fn adjustment_kind_rejects_non_snake_case_json_tags() {
    for invalid in [
        r#""Elevation""#,
        r#""Declassification""#,
        r#""de-classification""#,
        r#""policy_adjustment""#,
    ] {
        assert!(
            serde_json::from_str::<AdjustmentKind>(invalid).is_err(),
            "{invalid}"
        );
    }
}

#[test]
fn label_adjustment_json_roundtrip_preserves_adjustment_kind() -> TestResult {
    for original in [elevation_adjustment(), declassification_adjustment()] {
        let value = serde_json::to_value(&original)?;
        let object = value
            .as_object()
            .ok_or_else(|| std::io::Error::other("LabelAdjustment is JSON object"))?;
        let expected_kind = match original.kind {
            AdjustmentKind::Elevation => "elevation",
            AdjustmentKind::Declassification => "declassification",
        };
        assert_eq!(
            object.get("kind").and_then(|v| v.as_str()),
            Some(expected_kind)
        );

        let decoded: LabelAdjustment = serde_json::from_value(value)?;
        assert_adjustment_eq(&decoded, &original);
    }

    Ok(())
}

#[test]
fn label_adjustment_cbor_roundtrip_preserves_adjustment_kind() -> TestResult {
    for original in [elevation_adjustment(), declassification_adjustment()] {
        let mut encoded = Vec::new();
        ciborium::into_writer(&original, &mut encoded)?;

        let value: CborValue = ciborium::from_reader(encoded.as_slice())?;
        let CborValue::Map(entries) = value else {
            return Err(std::io::Error::other("LabelAdjustment must CBOR-encode as a map").into());
        };
        let expected_kind = match original.kind {
            AdjustmentKind::Elevation => "elevation",
            AdjustmentKind::Declassification => "declassification",
        };
        assert!(entries.contains(&(
            CborValue::Text("kind".to_string()),
            CborValue::Text(expected_kind.to_string()),
        )));

        let decoded: LabelAdjustment = ciborium::from_reader(encoded.as_slice())?;
        assert_adjustment_eq(&decoded, &original);
    }

    Ok(())
}
