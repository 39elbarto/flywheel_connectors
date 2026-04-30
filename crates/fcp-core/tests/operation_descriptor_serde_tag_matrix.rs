//! Pin `OperationInfo` JSON+CBOR serde matrix — the closest analogue to
//! "OperationDescriptor serde tag matrix" (flywheel_connectors-v0uat).
//!
//! Bead asks for `OperationDescriptor` JSON+CBOR roundtrip pinning. No type
//! literally named `OperationDescriptor` exists in fcp-core. The closest
//! analogue is [`OperationInfo`] at `crates/fcp-core/src/protocol.rs:2019`,
//! the per-operation introspection record returned by connectors.
//! `ConnectorDescriptor` exists in `connector_descriptors.rs:149` but
//! describes the connector as a whole, not a single operation.
//!
//! No existing test pins OperationInfo's wire shape — `grep` for
//! `OperationInfo` in `crates/fcp-core/tests/` returns empty.
//!
//! Coverage:
//!   * 12-field JSON shape pinned (id, summary, description, input_schema,
//!     output_schema, capability, risk_level, safety_tier, idempotency,
//!     ai_hints, rate_limit, requires_approval),
//!   * skip-when-None for description + rate_limit + requires_approval,
//!   * Required field set always present (9 fields when minimal),
//!   * RiskLevel + SafetyTier + IdempotencyClass embedded snake_case
//!     serde tags ride through round-trip,
//!   * AgentHint nested struct round-trip,
//!   * `input_schema` / `output_schema` are arbitrary serde_json::Value
//!     (object / array / scalar all preserved),
//!   * JSON + CBOR cross-format equality on the populated struct,
//!   * Distinct safety_tier values produce distinct JSON.

use fcp_core::{
    AgentHint, ApprovalMode, CapabilityId, IdempotencyClass, OperationId, OperationInfo, RateLimit,
    RiskLevel, SafetyTier,
};
use serde_json::json;

fn populated() -> OperationInfo {
    OperationInfo {
        id: OperationId::from_static("op.read"),
        summary: "Read an object".to_string(),
        description: Some("Reads the object identified by the input id.".to_string()),
        input_schema: json!({
            "type": "object",
            "required": ["id"],
            "properties": { "id": { "type": "string" } }
        }),
        output_schema: json!({
            "type": "object",
            "properties": { "data": { "type": "string" } }
        }),
        capability: CapabilityId::from_static("cap.read"),
        risk_level: RiskLevel::Low,
        safety_tier: SafetyTier::Safe,
        idempotency: IdempotencyClass::Strict,
        ai_hints: AgentHint {
            when_to_use: "Use when fetching a single object by id.".to_string(),
            common_mistakes: vec!["passing an opaque id without scope".to_string()],
            examples: vec![r#"{ "id": "obj-1" }"#.to_string()],
            related: vec![CapabilityId::from_static("cap.write")],
        },
        rate_limit: Some(RateLimit {
            max: 100,
            per_ms: 60_000,
            burst: Some(10),
            scope: Some("per_connector".to_string()),
            pool_name: Some("default".to_string()),
        }),
        requires_approval: Some(ApprovalMode::Policy),
    }
}

fn minimal() -> OperationInfo {
    OperationInfo {
        id: OperationId::from_static("op.minimal"),
        summary: "Minimal op".to_string(),
        description: None,
        input_schema: json!({}),
        output_schema: json!({}),
        capability: CapabilityId::from_static("cap.read"),
        risk_level: RiskLevel::Low,
        safety_tier: SafetyTier::Safe,
        idempotency: IdempotencyClass::None,
        ai_hints: AgentHint::default(),
        rate_limit: None,
        requires_approval: None,
    }
}

#[test]
fn populated_full_field_set_pinned() {
    let info = populated();
    let v = serde_json::to_value(&info).unwrap();
    let obj = v.as_object().expect("must be object");

    let expected: std::collections::BTreeSet<&str> = [
        "id",
        "summary",
        "description",
        "input_schema",
        "output_schema",
        "capability",
        "risk_level",
        "safety_tier",
        "idempotency",
        "ai_hints",
        "rate_limit",
        "requires_approval",
    ]
    .into_iter()
    .collect();
    let actual: std::collections::BTreeSet<&str> = obj.keys().map(String::as_str).collect();
    assert_eq!(actual, expected, "OperationInfo shape drift: {obj:?}");
}

#[test]
fn minimal_omits_skip_when_none_optional_fields() {
    // description, rate_limit, requires_approval all use skip_serializing_if
    // = "Option::is_none". When None, they must be OMITTED from the wire form.
    let info = minimal();
    let v = serde_json::to_value(&info).unwrap();
    let obj = v.as_object().expect("must be object");

    assert!(
        !obj.contains_key("description"),
        "description must be omitted when None"
    );
    assert!(
        !obj.contains_key("rate_limit"),
        "rate_limit must be omitted when None"
    );
    assert!(
        !obj.contains_key("requires_approval"),
        "requires_approval must be omitted when None"
    );

    // Required fields still present (9-field minimal shape).
    let expected_required: std::collections::BTreeSet<&str> = [
        "id",
        "summary",
        "input_schema",
        "output_schema",
        "capability",
        "risk_level",
        "safety_tier",
        "idempotency",
        "ai_hints",
    ]
    .into_iter()
    .collect();
    let actual: std::collections::BTreeSet<&str> = obj.keys().map(String::as_str).collect();
    assert_eq!(
        actual, expected_required,
        "OperationInfo minimal shape: {obj:?}"
    );
}

#[test]
fn risk_level_and_safety_tier_and_idempotency_serialize_as_snake_case() {
    let info = populated();
    let v = serde_json::to_value(&info).unwrap();
    let obj = v.as_object().unwrap();

    assert_eq!(obj.get("risk_level"), Some(&json!("low")));
    assert_eq!(obj.get("safety_tier"), Some(&json!("safe")));
    assert_eq!(obj.get("idempotency"), Some(&json!("strict")));
    // requires_approval: Some(Policy) → "policy"
    assert_eq!(obj.get("requires_approval"), Some(&json!("policy")));
}

#[test]
fn json_roundtrip_preserves_all_decision_critical_fields() {
    let info = populated();
    let bytes = serde_json::to_vec(&info).unwrap();
    let back: OperationInfo = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(back.id, info.id);
    assert_eq!(back.summary, info.summary);
    assert_eq!(back.description, info.description);
    assert_eq!(back.capability, info.capability);
    assert_eq!(back.risk_level, info.risk_level);
    assert_eq!(back.safety_tier, info.safety_tier);
    assert_eq!(back.idempotency, info.idempotency);
    assert_eq!(back.requires_approval, info.requires_approval);

    // input/output_schema are arbitrary JSON values; check structural equality.
    assert_eq!(back.input_schema, info.input_schema);
    assert_eq!(back.output_schema, info.output_schema);

    // Nested AgentHint round-trips.
    assert_eq!(back.ai_hints.when_to_use, info.ai_hints.when_to_use);
    assert_eq!(back.ai_hints.common_mistakes, info.ai_hints.common_mistakes);
    assert_eq!(back.ai_hints.examples, info.ai_hints.examples);
    assert_eq!(back.ai_hints.related, info.ai_hints.related);

    // Nested RateLimit round-trips.
    let rl = back.rate_limit.unwrap();
    assert_eq!(rl.max, 100);
    assert_eq!(rl.per_ms, 60_000);
    assert_eq!(rl.burst, Some(10));
}

#[test]
fn cbor_roundtrip_preserves_all_decision_critical_fields() {
    let info = populated();
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&info, &mut bytes).unwrap();
    let back: OperationInfo = ciborium::de::from_reader(&bytes[..]).unwrap();

    assert_eq!(back.id, info.id);
    assert_eq!(back.summary, info.summary);
    assert_eq!(back.capability, info.capability);
    assert_eq!(back.risk_level, info.risk_level);
    assert_eq!(back.safety_tier, info.safety_tier);
    assert_eq!(back.idempotency, info.idempotency);
    assert_eq!(back.requires_approval, info.requires_approval);

    // input_schema / output_schema preserve the JSON Value through CBOR.
    assert_eq!(back.input_schema, info.input_schema);
    assert_eq!(back.output_schema, info.output_schema);
}

#[test]
fn json_and_cbor_decode_to_equivalent_struct() {
    let info = populated();
    let json_bytes = serde_json::to_vec(&info).unwrap();
    let mut cbor_bytes = Vec::new();
    ciborium::ser::into_writer(&info, &mut cbor_bytes).unwrap();

    let from_json: OperationInfo = serde_json::from_slice(&json_bytes).unwrap();
    let from_cbor: OperationInfo = ciborium::de::from_reader(&cbor_bytes[..]).unwrap();

    assert_eq!(from_json.id, from_cbor.id);
    assert_eq!(from_json.risk_level, from_cbor.risk_level);
    assert_eq!(from_json.safety_tier, from_cbor.safety_tier);
    assert_eq!(from_json.idempotency, from_cbor.idempotency);
    assert_eq!(from_json.requires_approval, from_cbor.requires_approval);
    assert_eq!(from_json.input_schema, from_cbor.input_schema);
    assert_eq!(from_json.output_schema, from_cbor.output_schema);
}

#[test]
fn distinct_safety_tier_values_produce_distinct_json() {
    let mut a = minimal();
    let mut b = minimal();
    let mut c = minimal();
    a.safety_tier = SafetyTier::Safe;
    b.safety_tier = SafetyTier::Risky;
    c.safety_tier = SafetyTier::Dangerous;

    let av = serde_json::to_value(&a).unwrap();
    let bv = serde_json::to_value(&b).unwrap();
    let cv = serde_json::to_value(&c).unwrap();

    assert_ne!(av, bv, "Safe vs Risky must differ");
    assert_ne!(bv, cv, "Risky vs Dangerous must differ");
    assert_ne!(av, cv, "Safe vs Dangerous must differ");
}

#[test]
fn distinct_idempotency_values_produce_distinct_json() {
    let mut a = minimal();
    let mut b = minimal();
    let mut c = minimal();
    a.idempotency = IdempotencyClass::None;
    b.idempotency = IdempotencyClass::BestEffort;
    c.idempotency = IdempotencyClass::Strict;

    let av = serde_json::to_value(&a).unwrap();
    let bv = serde_json::to_value(&b).unwrap();
    let cv = serde_json::to_value(&c).unwrap();
    assert_ne!(av, bv);
    assert_ne!(bv, cv);
    assert_ne!(av, cv);
}

#[test]
fn input_schema_preserves_arbitrary_json_value_shapes() {
    // input_schema is `serde_json::Value` — pin that arbitrary JSON shapes
    // (not just objects) survive the round-trip. This is the contract for
    // operations declaring scalar / array / nested-object schemas.
    for shape in [
        json!({}),
        json!({ "type": "object", "properties": {} }),
        json!([1, 2, 3]),
        json!("scalar string"),
        json!(42),
        json!(null),
        json!({
            "type": "object",
            "properties": {
                "nested": {
                    "type": "object",
                    "properties": {
                        "field": { "type": "integer" }
                    }
                }
            }
        }),
    ] {
        let mut info = minimal();
        info.input_schema = shape.clone();

        let bytes = serde_json::to_vec(&info).unwrap();
        let back: OperationInfo = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.input_schema, shape, "JSON shape drift on `{shape:?}`");

        let mut cbor_bytes = Vec::new();
        ciborium::ser::into_writer(&info, &mut cbor_bytes).unwrap();
        let back_cbor: OperationInfo = ciborium::de::from_reader(&cbor_bytes[..]).unwrap();
        assert_eq!(
            back_cbor.input_schema, shape,
            "CBOR shape drift on `{shape:?}`"
        );
    }
}

#[test]
fn agent_hint_default_serializes_as_empty_strings_and_arrays() {
    let info = minimal();
    let v = serde_json::to_value(&info).unwrap();
    let hints = v.get("ai_hints").unwrap().as_object().unwrap();
    // when_to_use is required; default is "".
    assert_eq!(hints.get("when_to_use"), Some(&json!("")));
    // common_mistakes / examples / related: serde(default) but also serialize
    // when empty (no skip_serializing_if). Consumers see [] not missing key.
    assert_eq!(hints.get("common_mistakes"), Some(&json!([])));
    assert_eq!(hints.get("examples"), Some(&json!([])));
    assert_eq!(hints.get("related"), Some(&json!([])));
}

#[test]
fn rate_limit_optional_fields_omitted_when_none() {
    // RateLimit's burst, scope, and pool_name use skip_serializing_if =
    // Option::is_none. Pin so a minimum-shaped RateLimit produces only the
    // 2 required fields.
    let mut info = minimal();
    info.rate_limit = Some(RateLimit {
        max: 5,
        per_ms: 1_000,
        burst: None,
        scope: None,
        pool_name: None,
    });
    let v = serde_json::to_value(&info).unwrap();
    let rl = v.get("rate_limit").unwrap().as_object().unwrap();

    assert_eq!(rl.get("max"), Some(&json!(5)));
    assert_eq!(rl.get("per_ms"), Some(&json!(1_000)));
    assert!(!rl.contains_key("burst"));
    assert!(!rl.contains_key("scope"));
    assert!(!rl.contains_key("pool_name"));
}
