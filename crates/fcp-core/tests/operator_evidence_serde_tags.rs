use ciborium::value::Value as CborValue;
use fcp_core::{CorrelationId, ObjectId, OperatorEvidence, Uuid};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn test_error(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.into())
}

fn object_id(byte: u8) -> ObjectId {
    ObjectId::from_bytes([byte; 32])
}

fn correlation_id() -> CorrelationId {
    CorrelationId(Uuid::from_u128(0x1234_5678_9abc_def0_1234_5678_9abc_def0))
}

fn cases() -> Vec<(OperatorEvidence, &'static str)> {
    vec![
        (
            OperatorEvidence::AuditEvent {
                event_id: object_id(0x11),
            },
            "audit_event",
        ),
        (
            OperatorEvidence::DecisionReceipt {
                receipt_id: object_id(0x22),
            },
            "decision_receipt",
        ),
        (
            OperatorEvidence::OperationReceipt {
                receipt_id: object_id(0x33),
            },
            "operation_receipt",
        ),
        (
            OperatorEvidence::TraceContext {
                correlation_id: correlation_id(),
            },
            "trace_context",
        ),
        (
            OperatorEvidence::DurableObject {
                object_id: object_id(0x44),
            },
            "durable_object",
        ),
        (
            OperatorEvidence::LocalArtifact {
                path: "artifacts/operator/evidence.jsonl".to_string(),
                digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
            },
            "local_artifact",
        ),
    ]
}

fn json_type_tag(value: &OperatorEvidence) -> TestResult<String> {
    let json = serde_json::to_value(value)?;
    let tag = json
        .get("type")
        .and_then(|tag| tag.as_str())
        .ok_or_else(|| test_error(format!("missing JSON type tag in {json}")))?;
    Ok(tag.to_string())
}

fn cbor_type_tag(value: &OperatorEvidence) -> TestResult<String> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(value, &mut bytes)?;
    let cbor: CborValue = ciborium::de::from_reader(bytes.as_slice())?;
    let CborValue::Map(map) = cbor else {
        return Err(test_error("operator evidence MUST encode as a CBOR map").into());
    };

    let tag = map
        .iter()
        .find_map(|(key, value)| match (key, value) {
            (CborValue::Text(key), CborValue::Text(value)) if key == "type" => Some(value.clone()),
            _ => None,
        })
        .ok_or_else(|| test_error("missing CBOR type tag"))?;
    Ok(tag)
}

#[test]
fn operator_evidence_json_type_tags_are_pinned() -> TestResult {
    for (evidence, expected_tag) in cases() {
        assert_eq!(json_type_tag(&evidence)?, expected_tag);
    }
    Ok(())
}

#[test]
fn operator_evidence_json_roundtrips_every_tagged_variant() -> TestResult {
    for (evidence, _expected_tag) in cases() {
        let json = serde_json::to_string(&evidence)?;
        let decoded: OperatorEvidence = serde_json::from_str(&json)?;

        assert_eq!(decoded, evidence);
    }
    Ok(())
}

#[test]
fn operator_evidence_cbor_type_tags_are_pinned() -> TestResult {
    for (evidence, expected_tag) in cases() {
        assert_eq!(cbor_type_tag(&evidence)?, expected_tag);
    }
    Ok(())
}

#[test]
fn operator_evidence_cbor_roundtrips_every_tagged_variant() -> TestResult {
    for (evidence, _expected_tag) in cases() {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&evidence, &mut bytes)?;
        let decoded: OperatorEvidence = ciborium::de::from_reader(bytes.as_slice())?;

        assert_eq!(decoded, evidence);
    }
    Ok(())
}

#[test]
fn operator_evidence_rejects_unknown_json_type_tag() {
    let parsed = serde_json::from_str::<OperatorEvidence>(
        r#"{"type":"operator_note","message":"not a stable evidence handle"}"#,
    );

    assert!(parsed.is_err());
}
