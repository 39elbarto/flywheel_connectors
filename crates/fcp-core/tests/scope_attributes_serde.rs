//! Pin serde round-trips for the exported approval-scope attribute payloads.
//!
//! There is no literal `ScopeAttributes` type in fcp-core today. The wire
//! attributes carried by approval scopes are the concrete payload structs below.

use fcp_core::{
    ConfidentialityLevel, DeclassificationScope, ElevationScope, ExecutionScope, InputConstraint,
    IntegrityLevel, ObjectId, ZoneId,
};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Value};

fn object_id(byte: u8) -> ObjectId {
    ObjectId::from_bytes([byte; 32])
}

fn elevation_scope() -> ElevationScope {
    ElevationScope {
        operation_id: "operation.scope.elevate".to_string(),
        original_provenance_id: object_id(0x11),
        target_integrity: IntegrityLevel::Owner,
    }
}

fn declassification_scope() -> DeclassificationScope {
    DeclassificationScope {
        from_zone: ZoneId::private(),
        to_zone: ZoneId::public(),
        object_ids: vec![object_id(0x22), object_id(0x23)],
        target_confidentiality: ConfidentialityLevel::Public,
    }
}

fn execution_scope() -> ExecutionScope {
    ExecutionScope {
        connector_id: "connector.scope-test".to_string(),
        method_pattern: "messages.send".to_string(),
        request_object_id: Some(object_id(0x33)),
        input_hash: Some([0x44; 32]),
        input_constraints: vec![
            InputConstraint {
                pointer: "/body/channel".to_string(),
                expected: json!("ops"),
            },
            InputConstraint {
                pointer: "/body/urgent".to_string(),
                expected: json!(true),
            },
        ],
    }
}

fn json_value<T: Serialize>(value: &T) -> Value {
    serde_json::to_value(value).expect("serialize to JSON value")
}

fn assert_json_roundtrip<T>(value: &T)
where
    T: Serialize + DeserializeOwned,
{
    let expected = json_value(value);
    let encoded = serde_json::to_vec(value).expect("encode JSON");
    let decoded: T = serde_json::from_slice(&encoded).expect("decode JSON");

    assert_eq!(json_value(&decoded), expected);
}

fn assert_cbor_roundtrip<T>(value: &T)
where
    T: Serialize + DeserializeOwned,
{
    let expected = json_value(value);
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(value, &mut encoded).expect("encode CBOR");
    let decoded: T = ciborium::de::from_reader(encoded.as_slice()).expect("decode CBOR");

    assert_eq!(json_value(&decoded), expected);
}

#[test]
fn scope_attributes_json_roundtrip_for_all_payload_kinds() {
    assert_json_roundtrip(&elevation_scope());
    assert_json_roundtrip(&declassification_scope());
    assert_json_roundtrip(&execution_scope());
}

#[test]
fn scope_attributes_cbor_roundtrip_for_all_payload_kinds() {
    assert_cbor_roundtrip(&elevation_scope());
    assert_cbor_roundtrip(&declassification_scope());
    assert_cbor_roundtrip(&execution_scope());
}

#[test]
fn execution_scope_attributes_preserve_optional_fields_and_constraints() {
    let value = json_value(&execution_scope());

    assert_eq!(value["connector_id"], "connector.scope-test");
    assert_eq!(value["method_pattern"], "messages.send");
    assert!(value.get("request_object_id").is_some());
    assert_eq!(value["input_hash"], Value::Array(vec![json!(0x44); 32]));
    assert_eq!(
        value["input_constraints"],
        json!([
            {
                "pointer": "/body/channel",
                "expected": "ops"
            },
            {
                "pointer": "/body/urgent",
                "expected": true
            }
        ])
    );
}

#[test]
fn declassification_scope_attributes_preserve_zone_and_object_lists() {
    let value = json_value(&declassification_scope());

    assert_eq!(value["from_zone"], "z:private");
    assert_eq!(value["to_zone"], "z:public");
    assert_eq!(
        value["object_ids"]
            .as_array()
            .expect("object_ids array")
            .len(),
        2
    );
    assert_eq!(value["target_confidentiality"], "Public");
}
