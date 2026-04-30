//! Pin `DegradedModeReason` Display+serde divergence + `DegradedModeState`
//! shape — the closest analogue to "SelectorMode variant matrix"
//! (flywheel_connectors-wik35).
//!
//! Bead asks for `SelectorMode` variants Display + serde tag pinning. No
//! type literally named `SelectorMode` exists in fcp-core. The closest
//! "Mode" enum NOT yet pinned for variant Display+serde is
//! [`DegradedModeReason`] at `crates/fcp-core/src/quorum.rs:452`. Existing
//! pinned "Mode" enums:
//!   * `ApprovalMode` → `approval_reason_variant_display.rs`,
//!   * `TransportMode` → `zone_route_display_serde.rs`,
//!   * `PcsMode` + `KeyManagementMode` → `zone_route_hint_variant_display.rs`,
//!   * `ConnectorStateModel` → `connector_topology_serde.rs`.
//!
//! `DegradedModeReason` is critical: it has NO `rename_all` annotation,
//! so its serde form is **PascalCase by default** while Display via
//! `as_str()` is **snake_case**. This is the loud divergence sentinel
//! to pin: Display and serde return DIFFERENT strings for every variant.
//! Operator dashboards filter on Display tokens; wire payloads use
//! the serde form. Accidentally adding `rename_all = "snake_case"` (or
//! removing the snake_case mapping in `as_str`) would silently merge
//! the two streams.
//!
//! Coverage:
//!   * 5-variant DegradedModeReason snake_case Display matrix,
//!   * 5-variant DegradedModeReason DEFAULT PascalCase serde matrix,
//!   * Loud Display ≠ serde divergence sentinel per variant,
//!   * JSON + CBOR round-trip (PascalCase wire form survives both),
//!   * snake_case input rejection sentinel (the inverse: Display strings
//!     MUST NOT deserialize as the variant — pin so the divergence
//!     stays loud),
//!   * `DegradedModeState` shape with embedded reason Option,
//!   * Distinct-variant distinct-Display + distinct-JSON sentinels.

use ciborium::Value as CborValue;
use fcp_core::{DegradedModeReason, DegradedModeState};
use serde_json::json;

const ALL_REASONS: &[(DegradedModeReason, &str, &str)] = &[
    // (variant, display_token, serde_pascal_tag)
    (
        DegradedModeReason::NetworkPartition,
        "network_partition",
        "NetworkPartition",
    ),
    (
        DegradedModeReason::InsufficientNodes,
        "insufficient_nodes",
        "InsufficientNodes",
    ),
    (
        DegradedModeReason::NodeFailure,
        "node_failure",
        "NodeFailure",
    ),
    (
        DegradedModeReason::QuorumTimeout,
        "quorum_timeout",
        "QuorumTimeout",
    ),
    (
        DegradedModeReason::ManualOverride,
        "manual_override",
        "ManualOverride",
    ),
];

#[test]
fn degraded_mode_reason_display_uses_snake_case_for_every_variant() {
    for &(variant, display, _) in ALL_REASONS {
        assert_eq!(
            variant.to_string(),
            display,
            "Display for {variant:?} != `{display}`"
        );
        assert_eq!(variant.as_str(), display);
    }
}

#[test]
fn degraded_mode_reason_serde_uses_pascalcase_default_for_every_variant() {
    for &(variant, _, pascal) in ALL_REASONS {
        let v = serde_json::to_value(variant).unwrap();
        assert_eq!(
            v,
            json!(pascal),
            "DegradedModeReason has no rename_all → serde defaults to PascalCase. \
             {variant:?} must serialize as `{pascal}`, got {v:?}"
        );
        let back: DegradedModeReason = serde_json::from_value(v).unwrap();
        assert_eq!(back, variant);
    }
}

#[test]
fn loud_divergence_sentinel_display_never_equals_serde_form() {
    // Display = snake_case, serde = PascalCase. This divergence is THE
    // contract — pin so adding `rename_all = "snake_case"` (which would
    // silently break wire compatibility for any consumer filtering on
    // either form) is caught at the integration boundary.
    for &(variant, display, pascal) in ALL_REASONS {
        assert_ne!(
            display, pascal,
            "Test fixture sanity: Display `{display}` must differ from PascalCase `{pascal}`"
        );
        let serde_form = serde_json::to_value(variant).unwrap();
        assert_eq!(serde_form, json!(pascal));
        assert_ne!(
            serde_form,
            json!(display),
            "DegradedModeReason: Display=`{display}` accidentally aliased to serde form. \
             rename_all = \"snake_case\" would silently merge two distinct streams."
        );
    }
}

#[test]
fn snake_case_input_must_not_decode_as_degraded_mode_reason() {
    // The inverse of the divergence sentinel: snake_case Display tokens
    // are NOT valid serde inputs. Pin so a future addition of
    // rename_all = "snake_case" doesn't silently start accepting both
    // forms (which would let stale audit-log tokens reload as variants).
    for &(_, snake, _) in ALL_REASONS {
        let result: Result<DegradedModeReason, _> = serde_json::from_value(json!(snake));
        assert!(
            result.is_err(),
            "DegradedModeReason must reject snake_case `{snake}` (Display token \
             must not alias serde wire form), got {result:?}"
        );
    }
}

#[test]
fn pascal_case_input_decodes_for_every_variant() {
    for &(variant, _, pascal) in ALL_REASONS {
        let back: DegradedModeReason = serde_json::from_value(json!(pascal)).unwrap();
        assert_eq!(back, variant);
    }
}

#[test]
fn cbor_roundtrip_preserves_pascalcase_for_every_variant() {
    for &(variant, _, pascal) in ALL_REASONS {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&variant, &mut bytes).unwrap();
        let back: DegradedModeReason = ciborium::de::from_reader(&bytes[..]).unwrap();
        assert_eq!(back, variant);

        // CBOR shape: PascalCase Text scalar (no rename_all → no snake_case).
        let value: CborValue = ciborium::de::from_reader(&bytes[..]).unwrap();
        match value {
            CborValue::Text(text) => assert_eq!(
                text, pascal,
                "CBOR text form for {variant:?} must be PascalCase `{pascal}`"
            ),
            other => panic!("DegradedModeReason must encode as CBOR Text, got {other:?}"),
        }
    }
}

#[test]
fn distinct_variants_have_distinct_display_and_distinct_serde_forms() {
    let mut display_set = std::collections::HashSet::new();
    let mut serde_set = std::collections::HashSet::new();
    for &(variant, _, _) in ALL_REASONS {
        let d = variant.to_string();
        assert!(display_set.insert(d.clone()), "Display collision: `{d}`");
        let v = serde_json::to_value(variant).unwrap();
        assert!(serde_set.insert(v.clone()), "JSON collision: {v:?}");
    }
}

#[test]
fn degraded_mode_state_shape_pins_active_reason_optional_fields() {
    let state = DegradedModeState {
        active: true,
        reason: Some(DegradedModeReason::NodeFailure),
        entered_at: Some(1_700_000_000),
        available_nodes: 2,
        expected_nodes: 5,
    };
    let v = serde_json::to_value(&state).unwrap();
    let obj = v.as_object().expect("must be object");

    assert_eq!(obj.get("active"), Some(&json!(true)));
    assert_eq!(obj.get("reason"), Some(&json!("NodeFailure")));
    assert_eq!(obj.get("entered_at"), Some(&json!(1_700_000_000)));
    assert_eq!(obj.get("available_nodes"), Some(&json!(2)));
    assert_eq!(obj.get("expected_nodes"), Some(&json!(5)));

    let back: DegradedModeState = serde_json::from_value(v).unwrap();
    assert_eq!(back, state);
}

#[test]
fn degraded_mode_state_with_no_reason_serializes_optional_fields_as_null() {
    let state = DegradedModeState {
        active: false,
        reason: None,
        entered_at: None,
        available_nodes: 5,
        expected_nodes: 5,
    };
    let v = serde_json::to_value(&state).unwrap();
    let obj = v.as_object().expect("must be object");

    // No skip_serializing_if on these fields → present as null.
    assert!(obj.contains_key("reason"));
    assert_eq!(obj.get("reason"), Some(&json!(null)));
    assert!(obj.contains_key("entered_at"));
    assert_eq!(obj.get("entered_at"), Some(&json!(null)));

    let back: DegradedModeState = serde_json::from_value(v).unwrap();
    assert_eq!(back, state);
}

#[test]
fn degraded_mode_state_cbor_roundtrip_with_reason() {
    let state = DegradedModeState {
        active: true,
        reason: Some(DegradedModeReason::QuorumTimeout),
        entered_at: Some(1_700_000_500),
        available_nodes: 1,
        expected_nodes: 3,
    };
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&state, &mut bytes).unwrap();
    let back: DegradedModeState = ciborium::de::from_reader(&bytes[..]).unwrap();
    assert_eq!(back, state);
}

#[test]
fn degraded_mode_reason_works_as_hashmap_key() {
    // DegradedModeReason derives Hash + Eq for use in counters/registries.
    // Pin distinct buckets per variant.
    let mut counts: std::collections::HashMap<DegradedModeReason, u32> =
        std::collections::HashMap::new();
    *counts
        .entry(DegradedModeReason::NetworkPartition)
        .or_insert(0) += 2;
    *counts.entry(DegradedModeReason::NodeFailure).or_insert(0) += 1;

    assert_eq!(counts.get(&DegradedModeReason::NetworkPartition), Some(&2));
    assert_eq!(counts.get(&DegradedModeReason::NodeFailure), Some(&1));
    assert_eq!(counts.get(&DegradedModeReason::QuorumTimeout), None);
}
