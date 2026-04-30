//! Pin serde round-trips for the principal kind wire field.
//!
//! fcp-core does not currently export a literal `PrincipalKind` enum. The
//! principal-kind contract is the `Principal.kind` string field, documented on
//! `Principal` as values such as `user`, `agent`, `service`, and `webhook`.

use fcp_core::{Principal, TrustLevel};
use serde_json::{json, Value};

fn principal(kind: &str, id: &str, trust: TrustLevel, display: Option<&str>) -> Principal {
    Principal {
        kind: kind.to_string(),
        id: id.to_string(),
        trust,
        display: display.map(str::to_string),
    }
}

fn cases() -> Vec<Principal> {
    vec![
        principal("user", "alice", TrustLevel::Paired, Some("Alice")),
        principal("agent", "planner", TrustLevel::Admin, Some("Planner")),
        principal("service", "vault", TrustLevel::Owner, None),
        principal("webhook", "github", TrustLevel::Untrusted, None),
    ]
}

fn json_value(value: &Principal) -> Value {
    serde_json::to_value(value).expect("serialize principal to JSON value")
}

fn assert_same_wire_shape(actual: &Principal, expected: &Principal) {
    assert_eq!(actual.kind, expected.kind);
    assert_eq!(actual.id, expected.id);
    assert_eq!(actual.trust, expected.trust);
    assert_eq!(actual.display, expected.display);
    assert_eq!(json_value(actual), json_value(expected));
}

#[test]
fn principal_kind_json_roundtrip_preserves_representative_kinds() {
    for expected in cases() {
        let encoded = serde_json::to_string(&expected).expect("encode JSON");
        let decoded: Principal = serde_json::from_str(&encoded).expect("decode JSON");

        assert_same_wire_shape(&decoded, &expected);
    }
}

#[test]
fn principal_kind_cbor_roundtrip_preserves_representative_kinds() {
    for expected in cases() {
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&expected, &mut encoded).expect("encode CBOR");
        let decoded: Principal =
            ciborium::de::from_reader(encoded.as_slice()).expect("decode CBOR");

        assert_same_wire_shape(&decoded, &expected);
    }
}

#[test]
fn principal_kind_json_shape_pins_field_name_and_string_values() {
    let value = json_value(&principal("agent", "planner", TrustLevel::Admin, Some("Planner")));

    assert_eq!(
        value,
        json!({
            "kind": "agent",
            "id": "planner",
            "trust": "admin",
            "display": "Planner"
        })
    );
}

#[test]
fn principal_kind_none_display_is_omitted_but_kind_is_preserved() {
    let value = json_value(&principal("service", "vault", TrustLevel::Owner, None));

    assert_eq!(
        value,
        json!({
            "kind": "service",
            "id": "vault",
            "trust": "owner"
        })
    );
}

#[test]
fn principal_kinds_remain_distinct_after_json_and_cbor_roundtrip() {
    let original = cases();
    let mut seen = std::collections::BTreeSet::new();

    for principal in original {
        let json_back: Principal =
            serde_json::from_str(&serde_json::to_string(&principal).expect("encode JSON"))
                .expect("decode JSON");

        let mut cbor = Vec::new();
        ciborium::ser::into_writer(&principal, &mut cbor).expect("encode CBOR");
        let cbor_back: Principal = ciborium::de::from_reader(cbor.as_slice()).expect("decode CBOR");

        assert_eq!(json_back.kind, principal.kind);
        assert_eq!(cbor_back.kind, principal.kind);
        assert!(
            seen.insert(json_back.kind),
            "principal kind collided after roundtrip"
        );
    }

    let expected: std::collections::BTreeSet<String> = ["agent", "service", "user", "webhook"]
        .into_iter()
        .map(String::from)
        .collect();
    assert_eq!(seen, expected);
}
