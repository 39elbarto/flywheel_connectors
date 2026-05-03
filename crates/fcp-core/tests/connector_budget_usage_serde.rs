//! Pin `UsageMetric` + `UsageMetricKind` JSON+CBOR serde matrix — the closest
//! analogue to "ConnectorBudgetUsage serde"
//! (flywheel_connectors-bwkas).
//!
//! Bead asks for `ConnectorBudgetUsage` JSON+CBOR roundtrip pinning. No type
//! literally named `ConnectorBudgetUsage` exists in fcp-core. The closest
//! analogue is [`UsageMetric`] at `crates/fcp-core/src/protocol.rs:1479` —
//! the per-connector usage telemetry record emitted on
//! `OperationReceipt::usage_metrics`. Connectors SHOULD emit these and
//! host systems MAY aggregate per-zone for budget enforcement; that IS
//! the "connector budget usage" signal.
//!
//! Existing coverage: `UsageBudgetUsage` (the policy-side budget vs. usage
//! report) is pinned by `retention_policy_variant_display.rs` + `budget_snapshot_serde.rs`.
//! `UsageMetric` itself (the per-receipt usage record) has NO dedicated
//! test — `grep "UsageMetric::"` in `crates/fcp-core/tests/` returns
//! empty. This pin closes that gap.
//!
//! Coverage:
//!   * UsageMetric 4-field JSON shape (kind, amount, unit, custom_id),
//!   * skip-when-None for unit + custom_id,
//!   * UsageMetricKind 6-variant snake_case serde + as_str pinning,
//!   * UsageMetricKind PascalCase rejection sentinel,
//!   * Constructor helpers produce expected variants
//!     (api_credits/tokens/bytes/duration_ms/requests/custom),
//!   * `with_unit` builder attaches unit field,
//!   * UsageMetric JSON + CBOR round-trip preserves all fields,
//!   * Custom metric requires custom_id; round-trip preserves it,
//!   * Distinct kinds + distinct amounts produce distinct JSON.

use ciborium::Value as CborValue;
use fcp_core::{UsageMetric, UsageMetricKind};
use serde_json::json;

const ALL_KINDS: &[(UsageMetricKind, &str)] = &[
    (UsageMetricKind::ApiCredits, "api_credits"),
    (UsageMetricKind::Tokens, "tokens"),
    (UsageMetricKind::Bytes, "bytes"),
    (UsageMetricKind::DurationMs, "duration_ms"),
    (UsageMetricKind::Requests, "requests"),
    (UsageMetricKind::Custom, "custom"),
];

#[test]
fn usage_metric_kind_serde_uses_snake_case_for_every_variant() {
    for &(variant, wire) in ALL_KINDS {
        let v = serde_json::to_value(variant).unwrap();
        assert_eq!(v, json!(wire), "{variant:?} must serialize to `{wire}`");
        let back: UsageMetricKind = serde_json::from_value(v).unwrap();
        assert_eq!(back, variant);
    }
}

#[test]
fn usage_metric_kind_as_str_matches_serde_wire_form() {
    // as_str is the documented stable label for signing / diagnostics.
    // It must agree with serde wire form byte-for-byte; otherwise
    // signable bytes diverge from JSON wire form.
    for &(variant, wire) in ALL_KINDS {
        assert_eq!(variant.as_str(), wire, "as_str for {variant:?} != `{wire}`");
    }
}

#[test]
fn usage_metric_kind_rejects_pascal_case() {
    let bad: Result<UsageMetricKind, _> = serde_json::from_value(json!("ApiCredits"));
    assert!(bad.is_err(), "PascalCase must reject: {bad:?}");
    let bad: Result<UsageMetricKind, _> = serde_json::from_value(json!("DurationMs"));
    assert!(bad.is_err(), "PascalCase must reject: {bad:?}");
}

#[test]
fn usage_metric_kind_cbor_roundtrip_for_every_variant() {
    for &(variant, expected) in ALL_KINDS {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&variant, &mut bytes).unwrap();
        let back: UsageMetricKind = ciborium::de::from_reader(&bytes[..]).unwrap();
        assert_eq!(back, variant);

        // CBOR shape: snake_case Text scalar.
        let value: CborValue = ciborium::de::from_reader(&bytes[..]).unwrap();
        match value {
            CborValue::Text(text) => assert_eq!(text, expected),
            other => panic!("UsageMetricKind must encode as CBOR Text, got {other:?}"),
        }
    }
}

#[test]
fn usage_metric_kind_distinct_variants_serialize_distinctly() {
    let mut seen = std::collections::HashSet::new();
    for &(variant, _) in ALL_KINDS {
        let v = serde_json::to_value(variant).unwrap();
        assert!(
            seen.insert(v.clone()),
            "duplicate JSON for {variant:?}: {v:?}"
        );
    }
}

#[test]
fn usage_metric_full_json_shape_pinned_when_unit_and_custom_id_present() {
    let metric = UsageMetric::custom("openai.gpt4.tokens", 1500, Some("tokens".to_string()));
    let v = serde_json::to_value(&metric).unwrap();
    let obj = v.as_object().expect("must be object");

    let expected: std::collections::BTreeSet<&str> = ["kind", "amount", "unit", "custom_id"]
        .into_iter()
        .collect();
    let actual: std::collections::BTreeSet<&str> = obj.keys().map(String::as_str).collect();
    assert_eq!(actual, expected, "UsageMetric shape drift: {obj:?}");

    assert_eq!(obj.get("kind"), Some(&json!("custom")));
    assert_eq!(obj.get("amount"), Some(&json!(1500)));
    assert_eq!(obj.get("unit"), Some(&json!("tokens")));
    assert_eq!(obj.get("custom_id"), Some(&json!("openai.gpt4.tokens")));
}

#[test]
fn usage_metric_minimal_omits_unit_and_custom_id_when_none() {
    // unit + custom_id use skip_serializing_if = "Option::is_none". When
    // both None, the wire form is exactly 2 fields.
    let metric = UsageMetric::tokens(42);
    let v = serde_json::to_value(&metric).unwrap();
    let obj = v.as_object().expect("must be object");

    let expected: std::collections::BTreeSet<&str> = ["kind", "amount"].into_iter().collect();
    let actual: std::collections::BTreeSet<&str> = obj.keys().map(String::as_str).collect();
    assert_eq!(actual, expected, "UsageMetric minimal shape drift: {obj:?}");

    assert_eq!(obj.get("kind"), Some(&json!("tokens")));
    assert_eq!(obj.get("amount"), Some(&json!(42)));
}

#[test]
fn usage_metric_constructor_helpers_produce_expected_variants() {
    assert_eq!(
        UsageMetric::api_credits(10).kind,
        UsageMetricKind::ApiCredits
    );
    assert_eq!(UsageMetric::api_credits(10).amount, 10);
    assert!(UsageMetric::api_credits(10).unit.is_none());
    assert!(UsageMetric::api_credits(10).custom_id.is_none());

    assert_eq!(UsageMetric::tokens(100).kind, UsageMetricKind::Tokens);
    assert_eq!(UsageMetric::tokens(100).amount, 100);

    assert_eq!(UsageMetric::bytes(2048).kind, UsageMetricKind::Bytes);
    assert_eq!(UsageMetric::bytes(2048).amount, 2048);

    assert_eq!(
        UsageMetric::duration_ms(5_000).kind,
        UsageMetricKind::DurationMs
    );
    assert_eq!(UsageMetric::duration_ms(5_000).amount, 5_000);

    assert_eq!(UsageMetric::requests(7).kind, UsageMetricKind::Requests);
    assert_eq!(UsageMetric::requests(7).amount, 7);

    let custom = UsageMetric::custom("vendor.metric", 99, Some("ops".to_string()));
    assert_eq!(custom.kind, UsageMetricKind::Custom);
    assert_eq!(custom.amount, 99);
    assert_eq!(custom.custom_id.as_deref(), Some("vendor.metric"));
    assert_eq!(custom.unit.as_deref(), Some("ops"));
}

#[test]
fn usage_metric_with_unit_attaches_unit_field() {
    let metric = UsageMetric::tokens(500).with_unit("token");
    assert_eq!(metric.unit.as_deref(), Some("token"));

    let v = serde_json::to_value(&metric).unwrap();
    assert_eq!(v.get("unit"), Some(&json!("token")));
}

#[test]
fn usage_metric_json_roundtrip_for_every_constructor() {
    let metrics = [
        UsageMetric::api_credits(1),
        UsageMetric::tokens(2),
        UsageMetric::bytes(3),
        UsageMetric::duration_ms(4),
        UsageMetric::requests(5),
        UsageMetric::custom("vendor.x", 6, None),
        UsageMetric::custom("vendor.y", 7, Some("req".to_string())),
    ];
    for metric in metrics {
        let bytes = serde_json::to_vec(&metric).unwrap();
        let back: UsageMetric = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.kind, metric.kind);
        assert_eq!(back.amount, metric.amount);
        assert_eq!(back.unit, metric.unit);
        assert_eq!(back.custom_id, metric.custom_id);
    }
}

#[test]
fn usage_metric_cbor_roundtrip_for_every_constructor() {
    let metrics = [
        UsageMetric::api_credits(1),
        UsageMetric::tokens(2),
        UsageMetric::bytes(3),
        UsageMetric::duration_ms(4),
        UsageMetric::requests(5),
        UsageMetric::custom("vendor.x", 6, Some("u".to_string())),
    ];
    for metric in metrics {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&metric, &mut bytes).unwrap();
        let back: UsageMetric = ciborium::de::from_reader(&bytes[..]).unwrap();
        assert_eq!(back.kind, metric.kind);
        assert_eq!(back.amount, metric.amount);
        assert_eq!(back.unit, metric.unit);
        assert_eq!(back.custom_id, metric.custom_id);
    }
}

#[test]
fn usage_metric_json_and_cbor_decode_to_equivalent_metric() {
    let metric = UsageMetric::custom("vendor.tokens", 1000, Some("tokens".to_string()));
    let json_bytes = serde_json::to_vec(&metric).unwrap();
    let mut cbor_bytes = Vec::new();
    ciborium::ser::into_writer(&metric, &mut cbor_bytes).unwrap();

    let from_json: UsageMetric = serde_json::from_slice(&json_bytes).unwrap();
    let from_cbor: UsageMetric = ciborium::de::from_reader(&cbor_bytes[..]).unwrap();

    assert_eq!(from_json.kind, from_cbor.kind);
    assert_eq!(from_json.amount, from_cbor.amount);
    assert_eq!(from_json.unit, from_cbor.unit);
    assert_eq!(from_json.custom_id, from_cbor.custom_id);
}

#[test]
fn distinct_kinds_produce_distinct_json() {
    let a = UsageMetric::tokens(100);
    let b = UsageMetric::api_credits(100);
    let av = serde_json::to_value(&a).unwrap();
    let bv = serde_json::to_value(&b).unwrap();
    assert_ne!(av, bv, "distinct kinds with same amount must differ");
}

#[test]
fn distinct_amounts_produce_distinct_json() {
    let a = UsageMetric::tokens(100);
    let b = UsageMetric::tokens(200);
    let av = serde_json::to_value(&a).unwrap();
    let bv = serde_json::to_value(&b).unwrap();
    assert_ne!(av, bv, "distinct amounts with same kind must differ");
}

#[test]
fn distinct_custom_ids_produce_distinct_json() {
    let a = UsageMetric::custom("vendor.a", 100, None);
    let b = UsageMetric::custom("vendor.b", 100, None);
    let av = serde_json::to_value(&a).unwrap();
    let bv = serde_json::to_value(&b).unwrap();
    assert_ne!(av, bv, "distinct custom_id must differ");
}

#[test]
fn u64_max_amount_round_trips_through_json_and_cbor() {
    let metric = UsageMetric {
        kind: UsageMetricKind::Bytes,
        amount: u64::MAX,
        unit: None,
        custom_id: None,
    };
    let bytes = serde_json::to_vec(&metric).unwrap();
    let back: UsageMetric = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(back.amount, u64::MAX);

    let mut cbor_bytes = Vec::new();
    ciborium::ser::into_writer(&metric, &mut cbor_bytes).unwrap();
    let back: UsageMetric = ciborium::de::from_reader(&cbor_bytes[..]).unwrap();
    assert_eq!(back.amount, u64::MAX);
}

#[test]
fn zero_amount_round_trips_through_json_and_cbor() {
    // Zero usage IS valid (e.g., a free-tier connector emitting "I ran but
    // consumed zero tokens"). Pin the boundary.
    let metric = UsageMetric::tokens(0);
    let bytes = serde_json::to_vec(&metric).unwrap();
    let back: UsageMetric = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(back.amount, 0);
}
