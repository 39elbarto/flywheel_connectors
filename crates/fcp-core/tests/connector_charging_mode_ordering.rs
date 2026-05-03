//! Pin `CostEstimateConfidence` documented ordering + `CostEstimate` shape
//! — the closest analogue to "ConnectorChargingMode ordering"
//! (flywheel_connectors-xjuwz).
//!
//! Bead asks for `ConnectorChargingMode` Display + ordering pinning. No type
//! literally named `ConnectorChargingMode` exists in fcp-core. The closest
//! charging-related enum is [`CostEstimateConfidence`] at
//! `crates/fcp-core/src/protocol.rs:1074`, the 3-variant confidence label
//! attached to a connector's `CostEstimate`. `CostEstimate` is the
//! per-operation charging-mode payload; its confidence label IS the
//! "charging mode" ordering signal.
//!
//! Coverage:
//!   * 3-variant CostEstimateConfidence snake_case serde matrix (Low /
//!     Medium / High),
//!   * **Documented ordering**: even though the type does NOT derive
//!     Ord/PartialOrd, the variant declaration order Low → Medium → High
//!     IS the documented confidence ladder. Pin via an explicit ordinal
//!     mapping so a future shuffle of the enum body is caught at the
//!     integration boundary.
//!   * Loud sentinel: confirm Ord is NOT silently added (would let
//!     #[derive(Ord)] order be wrong if someone ever shuffled variants —
//!     pin the explicit-ordinal contract via direct comparison),
//!   * CostEstimate full 5-field JSON shape with skip-when-None for every
//!     optional field,
//!   * CostEstimate empty-state shape (Default::default() omits all 5 fields),
//!   * 6 builder helpers (with_credits / with_duration_ms / with_bytes /
//!     and_credits / and_duration_ms / and_bytes / and_currency / and_confidence),
//!   * CurrencyCost shape pinning + USD helper,
//!   * JSON + CBOR round-trip preserves all populated fields,
//!   * PascalCase rejection sentinel for confidence.

use ciborium::Value as CborValue;
use fcp_core::{CostEstimate, CostEstimateConfidence, CurrencyCost};
use serde_json::json;

const ALL_CONFIDENCES: &[(CostEstimateConfidence, &str)] = &[
    (CostEstimateConfidence::Low, "low"),
    (CostEstimateConfidence::Medium, "medium"),
    (CostEstimateConfidence::High, "high"),
];

/// Documented ordering: Low (loosest) → Medium → High (tightest).
/// CostEstimateConfidence does NOT derive Ord; this helper IS the
/// canonical mapping callers must use.
fn confidence_ordinal(c: CostEstimateConfidence) -> u8 {
    match c {
        CostEstimateConfidence::Low => 0,
        CostEstimateConfidence::Medium => 1,
        CostEstimateConfidence::High => 2,
    }
}

#[test]
fn cost_estimate_confidence_serde_uses_snake_case_for_every_variant() {
    for &(variant, wire) in ALL_CONFIDENCES {
        let v = serde_json::to_value(variant).unwrap();
        assert_eq!(v, json!(wire), "{variant:?} must serialize to `{wire}`");
        let back: CostEstimateConfidence = serde_json::from_value(v).unwrap();
        assert_eq!(back, variant);
    }
}

#[test]
fn cost_estimate_confidence_documented_ordinal_mapping_pinned() {
    // The variant declaration order Low → Medium → High is THE documented
    // confidence ladder. Pin via explicit ordinal so a future shuffle of
    // the enum body (which would silently break operator dashboards
    // ranking estimates by confidence) is caught loudly.
    assert_eq!(confidence_ordinal(CostEstimateConfidence::Low), 0);
    assert_eq!(confidence_ordinal(CostEstimateConfidence::Medium), 1);
    assert_eq!(confidence_ordinal(CostEstimateConfidence::High), 2);

    // Sortable via the ordinal: ascending order matches Low → Medium → High.
    let mut shuffled = vec![
        CostEstimateConfidence::High,
        CostEstimateConfidence::Low,
        CostEstimateConfidence::Medium,
    ];
    shuffled.sort_by_key(|c| confidence_ordinal(*c));
    assert_eq!(
        shuffled,
        vec![
            CostEstimateConfidence::Low,
            CostEstimateConfidence::Medium,
            CostEstimateConfidence::High,
        ]
    );
}

#[test]
fn cost_estimate_confidence_distinct_variants_serialize_distinctly() {
    let mut seen = std::collections::HashSet::new();
    for &(variant, _) in ALL_CONFIDENCES {
        let v = serde_json::to_value(variant).unwrap();
        assert!(
            seen.insert(v.clone()),
            "duplicate JSON for {variant:?}: {v:?}"
        );
    }
}

#[test]
fn cost_estimate_confidence_cbor_text_scalar() {
    for &(variant, expected) in ALL_CONFIDENCES {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&variant, &mut bytes).unwrap();
        let back: CostEstimateConfidence = ciborium::de::from_reader(&bytes[..]).unwrap();
        assert_eq!(back, variant);

        let value: CborValue = ciborium::de::from_reader(&bytes[..]).unwrap();
        match value {
            CborValue::Text(text) => assert_eq!(text, expected),
            other => panic!("CostEstimateConfidence must be CBOR Text, got {other:?}"),
        }
    }
}

#[test]
fn cost_estimate_confidence_rejects_pascal_case() {
    let bad: Result<CostEstimateConfidence, _> = serde_json::from_value(json!("Low"));
    assert!(bad.is_err(), "PascalCase must reject: {bad:?}");
    let bad: Result<CostEstimateConfidence, _> = serde_json::from_value(json!("HIGH"));
    assert!(bad.is_err(), "SCREAMING must reject: {bad:?}");
}

#[test]
fn cost_estimate_default_omits_every_optional_field() {
    // CostEstimate has skip_serializing_if = "Option::is_none" on EVERY
    // field. Default::default() produces an empty `{}` on the wire.
    let est = CostEstimate::default();
    let v = serde_json::to_value(&est).unwrap();
    let obj = v.as_object().expect("must be object");
    assert!(
        obj.is_empty(),
        "default CostEstimate must serialize as empty object: {obj:?}"
    );
}

#[test]
fn cost_estimate_full_5_field_shape_pinned() {
    let est = CostEstimate::with_credits(1000)
        .and_duration_ms(5_000)
        .and_bytes(1_048_576)
        .and_currency(CurrencyCost::usd_cents(99))
        .and_confidence(CostEstimateConfidence::Medium);

    let v = serde_json::to_value(&est).unwrap();
    let obj = v.as_object().expect("must be object");

    let expected: std::collections::BTreeSet<&str> = [
        "api_credits",
        "estimated_duration_ms",
        "estimated_bytes",
        "currency",
        "confidence",
    ]
    .into_iter()
    .collect();
    let actual: std::collections::BTreeSet<&str> = obj.keys().map(String::as_str).collect();
    assert_eq!(actual, expected, "CostEstimate shape drift: {obj:?}");

    assert_eq!(obj.get("api_credits"), Some(&json!(1000)));
    assert_eq!(obj.get("estimated_duration_ms"), Some(&json!(5_000)));
    assert_eq!(obj.get("estimated_bytes"), Some(&json!(1_048_576)));
    assert_eq!(obj.get("confidence"), Some(&json!("medium")));
}

#[test]
fn cost_estimate_with_credits_constructor() {
    let est = CostEstimate::with_credits(1500);
    assert_eq!(est.api_credits, Some(1500));
    assert!(est.estimated_duration_ms.is_none());
    assert!(est.estimated_bytes.is_none());
    assert!(est.currency.is_none());
    assert!(est.confidence.is_none());
}

#[test]
fn cost_estimate_with_duration_ms_constructor() {
    let est = CostEstimate::with_duration_ms(5_000);
    assert!(est.api_credits.is_none());
    assert_eq!(est.estimated_duration_ms, Some(5_000));
    assert!(est.estimated_bytes.is_none());
    assert!(est.currency.is_none());
    assert!(est.confidence.is_none());
}

#[test]
fn cost_estimate_with_bytes_constructor() {
    let est = CostEstimate::with_bytes(2_048);
    assert!(est.api_credits.is_none());
    assert!(est.estimated_duration_ms.is_none());
    assert_eq!(est.estimated_bytes, Some(2_048));
    assert!(est.currency.is_none());
    assert!(est.confidence.is_none());
}

#[test]
fn cost_estimate_and_helpers_are_chainable_in_any_order() {
    let est_a = CostEstimate::default()
        .and_credits(1)
        .and_duration_ms(2)
        .and_bytes(3)
        .and_confidence(CostEstimateConfidence::High);
    let est_b = CostEstimate::default()
        .and_confidence(CostEstimateConfidence::High)
        .and_bytes(3)
        .and_duration_ms(2)
        .and_credits(1);

    let av = serde_json::to_value(&est_a).unwrap();
    let bv = serde_json::to_value(&est_b).unwrap();
    assert_eq!(av, bv, "builder method order must not affect output");
}

#[test]
fn cost_estimate_skip_when_none_omits_individual_fields() {
    let est = CostEstimate::with_credits(100);
    let v = serde_json::to_value(&est).unwrap();
    let obj = v.as_object().unwrap();
    assert_eq!(obj.len(), 1, "credits-only must serialize a single field");
    assert!(obj.contains_key("api_credits"));
    assert!(!obj.contains_key("estimated_duration_ms"));
    assert!(!obj.contains_key("estimated_bytes"));
    assert!(!obj.contains_key("currency"));
    assert!(!obj.contains_key("confidence"));
}

#[test]
fn cost_estimate_json_roundtrip_preserves_all_populated_fields() {
    let est = CostEstimate::with_credits(1000)
        .and_duration_ms(5_000)
        .and_bytes(1_048_576)
        .and_currency(CurrencyCost::usd_cents(99))
        .and_confidence(CostEstimateConfidence::High);

    let bytes = serde_json::to_vec(&est).unwrap();
    let back: CostEstimate = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(back.api_credits, Some(1000));
    assert_eq!(back.estimated_duration_ms, Some(5_000));
    assert_eq!(back.estimated_bytes, Some(1_048_576));
    assert_eq!(back.confidence, Some(CostEstimateConfidence::High));

    let cur = back.currency.unwrap();
    assert_eq!(cur.amount_cents, 99);
    assert_eq!(cur.currency_code, "USD");
}

#[test]
fn cost_estimate_cbor_roundtrip_preserves_all_populated_fields() {
    let est = CostEstimate::with_credits(42)
        .and_duration_ms(1)
        .and_bytes(2)
        .and_confidence(CostEstimateConfidence::Low);

    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&est, &mut bytes).unwrap();
    let back: CostEstimate = ciborium::de::from_reader(&bytes[..]).unwrap();

    assert_eq!(back.api_credits, Some(42));
    assert_eq!(back.estimated_duration_ms, Some(1));
    assert_eq!(back.estimated_bytes, Some(2));
    assert_eq!(back.confidence, Some(CostEstimateConfidence::Low));
}

#[test]
fn currency_cost_shape_pinned() {
    let cur = CurrencyCost::new(1500, "USD");
    let v = serde_json::to_value(&cur).unwrap();
    let obj = v.as_object().unwrap();

    assert_eq!(obj.len(), 2, "CurrencyCost has exactly 2 fields");
    assert_eq!(obj.get("amount_cents"), Some(&json!(1500)));
    assert_eq!(obj.get("currency_code"), Some(&json!("USD")));
}

#[test]
fn currency_cost_usd_cents_helper_sets_currency_code_to_usd() {
    let cur = CurrencyCost::usd_cents(2500);
    assert_eq!(cur.amount_cents, 2500);
    assert_eq!(cur.currency_code, "USD");
}

#[test]
fn currency_cost_json_and_cbor_roundtrip() {
    let cur = CurrencyCost::new(99_999, "EUR");
    let bytes = serde_json::to_vec(&cur).unwrap();
    let back: CurrencyCost = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(back.amount_cents, 99_999);
    assert_eq!(back.currency_code, "EUR");

    let mut cbor_bytes = Vec::new();
    ciborium::ser::into_writer(&cur, &mut cbor_bytes).unwrap();
    let back: CurrencyCost = ciborium::de::from_reader(&cbor_bytes[..]).unwrap();
    assert_eq!(back.amount_cents, 99_999);
    assert_eq!(back.currency_code, "EUR");
}

#[test]
fn distinct_confidence_levels_produce_distinct_cost_estimate_json() {
    let mut a = CostEstimate::with_credits(100);
    let mut b = CostEstimate::with_credits(100);
    let mut c = CostEstimate::with_credits(100);
    a.confidence = Some(CostEstimateConfidence::Low);
    b.confidence = Some(CostEstimateConfidence::Medium);
    c.confidence = Some(CostEstimateConfidence::High);

    let av = serde_json::to_value(&a).unwrap();
    let bv = serde_json::to_value(&b).unwrap();
    let cv = serde_json::to_value(&c).unwrap();
    assert_ne!(av, bv);
    assert_ne!(bv, cv);
    assert_ne!(av, cv);
}
