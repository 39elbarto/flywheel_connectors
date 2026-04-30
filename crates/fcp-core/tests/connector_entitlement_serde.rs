//! Pin `CapabilityGrant` serde shape — the closest analogue to
//! "ConnectorEntitlement serde" (flywheel_connectors-g5oxv).
//!
//! Bead asks for `ConnectorEntitlement serde JSON+CBOR roundtrip`.
//! No type literally named `ConnectorEntitlement` exists in fcp-core.
//! The closest "entitlement" analogue is `CapabilityGrant`
//! (capability.rs:1465) — a single capability grant within a token,
//! with the documented shape:
//!
//! ```text
//! CapabilityGrant {
//!     capability: CapabilityId,
//!     operation: Option<OperationId>,  // skip_serializing_if = None
//! }
//! ```
//!
//! Used in fixtures across policy_golden_vectors.rs but NOT yet
//! pinned for its own serde shape. The `operation: Option<...>`
//! field carries `#[serde(skip_serializing_if = "Option::is_none")]`
//! so the wire form differs based on Some/None.
//!
//! Targets:
//!
//!   1. **CapabilityGrant JSON shape with operation Some**.
//!   2. **CapabilityGrant JSON shape with operation None** —
//!      operation field omitted via skip_serializing_if (just the
//!      `capability` field appears).
//!   3. **operation defaults to None** when missing from wire form
//!      (combined with skip_serializing_if it's a round-trippable
//!      omission; pin via partial-JSON deserialize).
//!   4. **JSON round-trip preserves both shapes**.
//!   5. **CBOR round-trip preserves both shapes**.
//!   6. **Equality semantics** — CapabilityGrant derives PartialEq;
//!      structurally identical grants are equal, distinct in any
//!      field are unequal.
//!   7. **Vec<CapabilityGrant> serialization preserves order**.
//!   8. **Distinct grants produce distinct serialization** (capability
//!      and operation axes).
//!   9. **Cross-format consistency** — JSON and CBOR decode to the
//!      same CapabilityGrant.

use fcp_core::{CapabilityGrant, CapabilityId, OperationId};

fn cap(s: &str) -> CapabilityId {
    CapabilityId::from_static(Box::leak(s.to_string().into_boxed_str()))
}

fn op(s: &str) -> OperationId {
    OperationId::new(s).expect("valid operation id")
}

fn grant_with_operation() -> CapabilityGrant {
    CapabilityGrant {
        capability: cap("cap.read"),
        operation: Some(op("read")),
    }
}

fn grant_without_operation() -> CapabilityGrant {
    CapabilityGrant {
        capability: cap("cap.write"),
        operation: None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. JSON shape with operation Some
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn capability_grant_json_shape_pinned_with_operation_some() {
    let grant = grant_with_operation();
    let value = serde_json::to_value(&grant).expect("serialize");
    let obj = value.as_object().expect("object");
    assert_eq!(obj.len(), 2, "exactly 2 fields when operation is Some");
    assert_eq!(
        obj.get("capability").and_then(|v| v.as_str()),
        Some("cap.read")
    );
    assert_eq!(obj.get("operation").and_then(|v| v.as_str()), Some("read"));
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. JSON shape with operation None
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn capability_grant_json_shape_omits_operation_when_none() {
    let grant = grant_without_operation();
    let value = serde_json::to_value(&grant).expect("serialize");
    let obj = value.as_object().expect("object");
    assert_eq!(
        obj.len(),
        1,
        "exactly 1 field when operation is None — operation MUST be omitted"
    );
    assert!(
        !obj.contains_key("operation"),
        "operation MUST be omitted via skip_serializing_if when None"
    );
    assert_eq!(
        obj.get("capability").and_then(|v| v.as_str()),
        Some("cap.write")
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. operation defaults to None when missing from wire form
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn capability_grant_operation_defaults_to_none_when_missing() {
    // Pin that omitting `operation` from the wire form
    // round-trips into None — the symmetric counterpart of
    // skip_serializing_if.
    let json = r#"{"capability": "cap.read"}"#;
    let grant: CapabilityGrant = serde_json::from_str(json).expect("deserialize");
    assert_eq!(grant.capability, cap("cap.read"));
    assert!(
        grant.operation.is_none(),
        "operation MUST default to None when missing from wire form"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. JSON round-trip preserves both shapes
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn json_roundtrip_preserves_grant_with_operation() {
    let original = grant_with_operation();
    let json = serde_json::to_string(&original).expect("serialize");
    let back: CapabilityGrant = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, original);
    assert_eq!(back.capability, original.capability);
    assert_eq!(back.operation, original.operation);
}

#[test]
fn json_roundtrip_preserves_grant_without_operation() {
    let original = grant_without_operation();
    let json = serde_json::to_string(&original).expect("serialize");
    let back: CapabilityGrant = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, original);
    assert_eq!(back.operation, None);
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. CBOR round-trip preserves both shapes
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn cbor_roundtrip_preserves_grant_with_operation() {
    let original = grant_with_operation();
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&original, &mut buf).expect("encode");
    let back: CapabilityGrant = ciborium::de::from_reader(buf.as_slice()).expect("decode");
    assert_eq!(back, original);
}

#[test]
fn cbor_roundtrip_preserves_grant_without_operation() {
    let original = grant_without_operation();
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&original, &mut buf).expect("encode");
    let back: CapabilityGrant = ciborium::de::from_reader(buf.as_slice()).expect("decode");
    assert_eq!(back, original);
    assert_eq!(back.operation, None);
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Equality semantics
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn structurally_identical_grants_are_equal() {
    let a = CapabilityGrant {
        capability: cap("cap.read"),
        operation: Some(op("read")),
    };
    let b = CapabilityGrant {
        capability: cap("cap.read"),
        operation: Some(op("read")),
    };
    assert_eq!(a, b);
}

#[test]
fn grants_with_different_capability_are_unequal() {
    let a = CapabilityGrant {
        capability: cap("cap.alpha"),
        operation: None,
    };
    let b = CapabilityGrant {
        capability: cap("cap.beta"),
        operation: None,
    };
    assert_ne!(a, b);
}

#[test]
fn grants_with_different_operation_are_unequal() {
    let a = CapabilityGrant {
        capability: cap("cap.x"),
        operation: Some(op("read")),
    };
    let b = CapabilityGrant {
        capability: cap("cap.x"),
        operation: Some(op("write")),
    };
    assert_ne!(a, b);
}

#[test]
fn grant_with_some_operation_differs_from_grant_with_none() {
    let with_op = CapabilityGrant {
        capability: cap("cap.x"),
        operation: Some(op("read")),
    };
    let without_op = CapabilityGrant {
        capability: cap("cap.x"),
        operation: None,
    };
    assert_ne!(
        with_op, without_op,
        "Some(operation) and None MUST be structurally distinct grants"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. Vec<CapabilityGrant> preserves order
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn vec_of_capability_grants_preserves_insertion_order_through_json_roundtrip() {
    let original = vec![
        CapabilityGrant {
            capability: cap("cap.a"),
            operation: None,
        },
        CapabilityGrant {
            capability: cap("cap.b"),
            operation: Some(op("read")),
        },
        CapabilityGrant {
            capability: cap("cap.c"),
            operation: Some(op("write")),
        },
    ];
    let json = serde_json::to_string(&original).expect("serialize");
    let back: Vec<CapabilityGrant> = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, original);
    // Order matters on the wire — pin via byte-level distinction
    // from a reordered version.
    let mut reversed = original.clone();
    reversed.reverse();
    let reversed_json = serde_json::to_string(&reversed).expect("serialize");
    assert_ne!(
        json, reversed_json,
        "Vec<CapabilityGrant> ordering MUST be observable on the wire"
    );
}

#[test]
fn vec_of_capability_grants_cbor_roundtrip_preserves_order() {
    let original = vec![
        CapabilityGrant {
            capability: cap("cap.a"),
            operation: Some(op("read")),
        },
        CapabilityGrant {
            capability: cap("cap.b"),
            operation: None,
        },
    ];
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&original, &mut buf).expect("encode");
    let back: Vec<CapabilityGrant> = ciborium::de::from_reader(buf.as_slice()).expect("decode");
    assert_eq!(back, original);
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. Distinct grants produce distinct serialization
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn distinct_capability_produces_distinct_json() {
    let a = CapabilityGrant {
        capability: cap("cap.alpha"),
        operation: None,
    };
    let b = CapabilityGrant {
        capability: cap("cap.beta"),
        operation: None,
    };
    assert_ne!(
        serde_json::to_string(&a).unwrap(),
        serde_json::to_string(&b).unwrap()
    );
}

#[test]
fn distinct_operation_produces_distinct_json() {
    let a = CapabilityGrant {
        capability: cap("cap.x"),
        operation: Some(op("read")),
    };
    let b = CapabilityGrant {
        capability: cap("cap.x"),
        operation: Some(op("write")),
    };
    assert_ne!(
        serde_json::to_string(&a).unwrap(),
        serde_json::to_string(&b).unwrap()
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. Cross-format consistency
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn json_and_cbor_decode_to_same_grant() {
    let original = grant_with_operation();

    let json = serde_json::to_string(&original).expect("JSON serialize");
    let from_json: CapabilityGrant = serde_json::from_str(&json).expect("JSON deserialize");

    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&original, &mut cbor).expect("CBOR encode");
    let from_cbor: CapabilityGrant =
        ciborium::de::from_reader(cbor.as_slice()).expect("CBOR decode");

    assert_eq!(from_json, from_cbor);
    assert_eq!(from_json, original);
}

#[test]
fn json_and_cbor_decode_to_same_grant_when_operation_is_none() {
    let original = grant_without_operation();

    let json = serde_json::to_string(&original).expect("JSON serialize");
    let from_json: CapabilityGrant = serde_json::from_str(&json).expect("JSON deserialize");

    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&original, &mut cbor).expect("CBOR encode");
    let from_cbor: CapabilityGrant =
        ciborium::de::from_reader(cbor.as_slice()).expect("CBOR decode");

    assert_eq!(from_json, from_cbor);
    assert_eq!(from_json.operation, None);
    assert_eq!(from_cbor.operation, None);
}
