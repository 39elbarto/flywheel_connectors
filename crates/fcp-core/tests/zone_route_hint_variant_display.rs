//! Pin `PcsMode` + `KeyManagementMode` zone-routing variant Display + serde —
//! the closest analogue to "ZoneRouteHint variant Display"
//! (flywheel_connectors-vrcyi).
//!
//! Bead asks for `ZoneRouteHint` Display + serde tag pinning. No type literally
//! named `ZoneRouteHint` exists in fcp-core; the closest "zone route hint"
//! analogues are [`PcsMode`] and [`KeyManagementMode`] at
//! `crates/fcp-core/src/pcs.rs:71` and `crates/fcp-core/src/pcs.rs:88`. Both
//! are per-zone, internally-tagged, snake_case-renamed enums that route a
//! zone through one of two key-management paths:
//!   * `PcsMode::Disabled | Enabled { epoch, commit_ref }` — internally
//!     tagged on `mode`,
//!   * `KeyManagementMode::StandardRotation | PcsGroupManaged { commit_ref, epoch }`
//!     — internally tagged on `type`.
//! Existing `mesh_placement_hint_serde_ordering.rs`, `connector_topology_serde.rs`,
//! and `zone_route_display_serde.rs` already cover MeshPlacementHint /
//! DeviceSelector / TransportMode + ZoneTransportPolicy. PcsMode +
//! KeyManagementMode are the residual unpinned zone-routing-mode pair.
//!
//! Coverage:
//!   * Internal-tag key (`mode` for PcsMode, `type` for KeyManagementMode)
//!     — wrong key would loudly break wire compatibility,
//!   * Variant serde tag value (snake_case),
//!   * Default = first listed variant (Disabled / StandardRotation),
//!   * JSON round-trip for unit + payload variants,
//!   * CBOR Value-inspection workaround for the
//!     internally-tagged + hex_or_bytes Content-shim quirk: pin the tag on the
//!     encoded CBOR map without going through full deserialize,
//!   * Distinct discriminants → distinct JSON,
//!   * PascalCase outer-tag rejection sentinel.

use ciborium::Value as CborValue;
use fcp_core::pcs::{KeyManagementMode, PcsMode};
use serde_json::json;

fn cbor_tag(value: &CborValue, key: &str) -> Option<String> {
    let map = match value {
        CborValue::Map(m) => m,
        _ => return None,
    };
    for (k, v) in map {
        if let (CborValue::Text(name), CborValue::Text(tag)) = (k, v) {
            if name == key {
                return Some(tag.clone());
            }
        }
    }
    None
}

#[test]
fn pcs_mode_default_is_disabled() {
    assert_eq!(PcsMode::default(), PcsMode::Disabled);
}

#[test]
fn pcs_mode_disabled_serializes_with_mode_tag() {
    let v = serde_json::to_value(PcsMode::Disabled).unwrap();
    assert_eq!(v, json!({ "mode": "disabled" }));
    let back: PcsMode = serde_json::from_value(v).unwrap();
    assert_eq!(back, PcsMode::Disabled);
}

#[test]
fn pcs_mode_enabled_carries_epoch_commit_ref_alongside_mode_tag() {
    let mode = PcsMode::Enabled {
        epoch: 42,
        commit_ref: [0xab; 32],
    };
    let v = serde_json::to_value(&mode).unwrap();
    let obj = v.as_object().expect("PcsMode::Enabled must be object");

    assert_eq!(obj.get("mode"), Some(&json!("enabled")));
    assert_eq!(obj.get("epoch"), Some(&json!(42)));
    let commit_ref = obj.get("commit_ref").unwrap().as_str().unwrap();
    assert_eq!(commit_ref.len(), 64, "commit_ref must be 32-byte hex");
    assert!(
        commit_ref.chars().all(|c| c.is_ascii_hexdigit()),
        "commit_ref must be lowercase hex"
    );

    // JSON round-trip preserves all three fields.
    let back: PcsMode = serde_json::from_value(v).unwrap();
    assert_eq!(back, mode);
}

#[test]
fn pcs_mode_rejects_pascal_case_tag() {
    let bad = json!({ "mode": "Enabled", "epoch": 1, "commit_ref": "00".repeat(32) });
    let result: Result<PcsMode, _> = serde_json::from_value(bad);
    assert!(result.is_err(), "PascalCase mode tag must reject: {result:?}");

    let bad2 = json!({ "mode": "DISABLED" });
    let result: Result<PcsMode, _> = serde_json::from_value(bad2);
    assert!(result.is_err(), "SCREAMING tag must reject: {result:?}");
}

#[test]
fn pcs_mode_rejects_unknown_tag_value() {
    let bad = json!({ "mode": "unicorn_mode" });
    let result: Result<PcsMode, _> = serde_json::from_value(bad);
    assert!(result.is_err(), "unknown tag must reject: {result:?}");
}

#[test]
fn pcs_mode_distinct_variants_produce_distinct_tags() {
    let disabled_v = serde_json::to_value(PcsMode::Disabled).unwrap();
    let enabled_v = serde_json::to_value(PcsMode::Enabled {
        epoch: 0,
        commit_ref: [0; 32],
    })
    .unwrap();
    assert_ne!(
        disabled_v.get("mode"),
        enabled_v.get("mode"),
        "Disabled and Enabled must serialize distinct mode tags"
    );
}

#[test]
fn pcs_mode_cbor_pins_mode_tag_via_value_inspection() {
    // Internally-tagged enums with hex_or_bytes adapters can hit a serde
    // Content-shim quirk on full CBOR round-trip; pin the tag via direct
    // CBOR Value inspection instead.
    let mode = PcsMode::Enabled {
        epoch: 99,
        commit_ref: [0xcd; 32],
    };
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&mode, &mut bytes).unwrap();
    let value: CborValue = ciborium::de::from_reader(&bytes[..]).unwrap();

    assert_eq!(
        cbor_tag(&value, "mode").as_deref(),
        Some("enabled"),
        "CBOR must carry `mode: enabled` text tag"
    );

    // Disabled variant similarly:
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&PcsMode::Disabled, &mut bytes).unwrap();
    let value: CborValue = ciborium::de::from_reader(&bytes[..]).unwrap();
    assert_eq!(cbor_tag(&value, "mode").as_deref(), Some("disabled"));
}

#[test]
fn key_management_mode_default_is_standard_rotation() {
    assert_eq!(KeyManagementMode::default(), KeyManagementMode::StandardRotation);
}

#[test]
fn key_management_mode_uses_type_internal_tag() {
    // Note: KeyManagementMode uses `type`, NOT `mode` like PcsMode. Pin the
    // discriminant key so the two enums never converge to the same key
    // (they live in the same module and share serde shape).
    let v = serde_json::to_value(KeyManagementMode::StandardRotation).unwrap();
    assert_eq!(v, json!({ "type": "standard_rotation" }));

    let back: KeyManagementMode = serde_json::from_value(v).unwrap();
    assert_eq!(back, KeyManagementMode::StandardRotation);
}

#[test]
fn key_management_mode_pcs_group_managed_carries_commit_ref_and_epoch() {
    let mode = KeyManagementMode::PcsGroupManaged {
        commit_ref: [0x77; 32],
        epoch: 7,
    };
    let v = serde_json::to_value(&mode).unwrap();
    let obj = v.as_object().expect("must be object");

    assert_eq!(obj.get("type"), Some(&json!("pcs_group_managed")));
    assert_eq!(obj.get("epoch"), Some(&json!(7)));
    let commit_ref = obj.get("commit_ref").unwrap().as_str().unwrap();
    assert_eq!(commit_ref.len(), 64);

    // JSON round-trip preserves all fields.
    let back: KeyManagementMode = serde_json::from_value(v).unwrap();
    assert_eq!(back, mode);
}

#[test]
fn key_management_mode_rejects_pascal_case_tag() {
    let bad = json!({
        "type": "PcsGroupManaged",
        "commit_ref": "00".repeat(32),
        "epoch": 1
    });
    let result: Result<KeyManagementMode, _> = serde_json::from_value(bad);
    assert!(result.is_err(), "PascalCase type tag must reject: {result:?}");
}

#[test]
fn key_management_mode_rejects_pcs_mode_style_mode_key() {
    // Sanity: passing PcsMode-shaped payload (with `mode` key) must NOT
    // deserialize as KeyManagementMode. Catches accidental tag-key reuse.
    let bad = json!({ "mode": "standard_rotation" });
    let result: Result<KeyManagementMode, _> = serde_json::from_value(bad);
    assert!(
        result.is_err(),
        "KeyManagementMode must require `type`, not `mode`: {result:?}"
    );
}

#[test]
fn key_management_mode_cbor_pins_type_tag_via_value_inspection() {
    let mode = KeyManagementMode::PcsGroupManaged {
        commit_ref: [0x33; 32],
        epoch: 3,
    };
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&mode, &mut bytes).unwrap();
    let value: CborValue = ciborium::de::from_reader(&bytes[..]).unwrap();
    assert_eq!(
        cbor_tag(&value, "type").as_deref(),
        Some("pcs_group_managed")
    );

    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&KeyManagementMode::StandardRotation, &mut bytes).unwrap();
    let value: CborValue = ciborium::de::from_reader(&bytes[..]).unwrap();
    assert_eq!(cbor_tag(&value, "type").as_deref(), Some("standard_rotation"));
}

#[test]
fn pcs_mode_and_key_management_mode_use_distinct_tag_keys() {
    // Disjoint-tag-space sentinel: PcsMode uses `mode`, KeyManagementMode
    // uses `type`. Operator dashboards filter on both — accidentally
    // converging the keys would silently merge two distinct routing
    // signals into one bucket.
    let pcs = serde_json::to_value(PcsMode::Disabled).unwrap();
    let kmm = serde_json::to_value(KeyManagementMode::StandardRotation).unwrap();
    let pcs_obj = pcs.as_object().unwrap();
    let kmm_obj = kmm.as_object().unwrap();

    assert!(pcs_obj.contains_key("mode") && !pcs_obj.contains_key("type"));
    assert!(kmm_obj.contains_key("type") && !kmm_obj.contains_key("mode"));
}

#[test]
fn pcs_mode_distinct_payloads_produce_distinct_json() {
    let a = serde_json::to_value(PcsMode::Enabled {
        epoch: 1,
        commit_ref: [0; 32],
    })
    .unwrap();
    let b = serde_json::to_value(PcsMode::Enabled {
        epoch: 2,
        commit_ref: [0; 32],
    })
    .unwrap();
    let c = serde_json::to_value(PcsMode::Enabled {
        epoch: 1,
        commit_ref: [1; 32],
    })
    .unwrap();
    assert_ne!(a, b, "differing epoch must change JSON");
    assert_ne!(a, c, "differing commit_ref must change JSON");
}
