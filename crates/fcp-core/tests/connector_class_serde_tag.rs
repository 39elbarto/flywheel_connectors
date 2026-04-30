//! Pin connector-classifier serde tags on the closest analogues to
//! "ConnectorClass" (flywheel_connectors-p7lst).
//!
//! Bead asks for `ConnectorClass serde tag JSON+CBOR roundtrip`. No
//! type literally named `ConnectorClass` exists in fcp-core. The
//! connector-classification surface splits across several enums:
//!
//!  - `ConnectorRoute` (connector.rs:199) — 10-variant interaction
//!    pattern classifier (already pinned by tcox6's
//!    connector_route_serde_tags.rs).
//!  - `ConnectorLifecycleState` (connector.rs:180) — 5-variant
//!    runtime state (already pinned by
//!    connector_lifecycle_state_display.rs).
//!  - `ConnectorStateModel` (connector_state.rs:171) — 3-variant
//!    state-persistence classifier (Stateless / SingletonWriter /
//!    Crdt) with internal `type` tag and snake_case rename. NOT yet
//!    covered for serde tag matrix.
//!  - `ConnectorHealth` (health.rs:216) — 3-variant operational
//!    classifier (Healthy / Degraded / Unavailable) with internal
//!    `status` tag and lowercase rename. NOT yet pinned for serde.
//!  - `CrdtType` (connector_state.rs:117) — 4-variant CRDT
//!    classifier nested inside ConnectorStateModel::Crdt.
//!
//! This test pins ConnectorStateModel + ConnectorHealth + CrdtType
//! since they're the unpinned classifier surface; the bead's
//! "ConnectorClass" maps best to ConnectorStateModel (the canonical
//! "what kind of connector is this from a state-model standpoint?"
//! discriminant).
//!
//! Targets:
//!
//!   1. **ConnectorStateModel per-variant serde tag** (snake_case
//!      via internal `type` tag): `stateless` / `singleton_writer`
//!      / `crdt`.
//!   2. **ConnectorStateModel Display per variant** including
//!      Crdt's parametrized form `crdt(<inner>)`.
//!   3. **ConnectorStateModel JSON round-trip** preserves variant +
//!      nested CrdtType.
//!   4. **ConnectorStateModel default is Stateless** — operator
//!      visible default posture.
//!   5. **ConnectorStateModel predicates truth table**
//!      (is_stateless / is_singleton_writer / is_crdt /
//!      crdt_type()).
//!   6. **CrdtType per-variant serde tag** (snake_case:
//!      lww_map / or_set / g_counter / pn_counter).
//!   7. **CrdtType Display agrees with serde tag**.
//!   8. **ConnectorHealth per-variant `status` tag** (lowercase:
//!      healthy / degraded / unavailable).
//!   9. **ConnectorHealth nested fields** preserved through JSON
//!      round-trip for Degraded and Unavailable.
//!  10. **PascalCase rejected** for all three classifiers (drift
//!      sentinel for any future rename_all swap).

use ciborium::value::Value as CborValue;
use fcp_core::{ConnectorHealth, ConnectorStateModel, CrdtType};

// ─────────────────────────────────────────────────────────────────────────────
// 1. ConnectorStateModel per-variant `type` tag
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn connector_state_model_type_tag_pinned_for_stateless() {
    let value = serde_json::to_value(&ConnectorStateModel::Stateless).expect("serialize");
    assert_eq!(
        value,
        serde_json::json!({"type": "stateless"}),
        "ConnectorStateModel::Stateless MUST serialize as `{{\"type\": \"stateless\"}}`"
    );
}

#[test]
fn connector_state_model_type_tag_pinned_for_singleton_writer() {
    let value = serde_json::to_value(&ConnectorStateModel::SingletonWriter).expect("serialize");
    assert_eq!(
        value,
        serde_json::json!({"type": "singleton_writer"}),
        "SingletonWriter uses underscore not hyphen / camelCase"
    );
}

#[test]
fn connector_state_model_type_tag_pinned_for_crdt_with_inner_type() {
    let value = serde_json::to_value(&ConnectorStateModel::Crdt {
        crdt_type: CrdtType::LwwMap,
    })
    .expect("serialize");
    assert_eq!(
        value,
        serde_json::json!({"type": "crdt", "crdt_type": "lww_map"}),
        "Crdt internally-tagged form MUST flatten crdt_type field next to outer type"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. ConnectorStateModel Display per variant
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn connector_state_model_display_pinned_per_variant() {
    let cases = [
        (ConnectorStateModel::Stateless, "stateless"),
        (ConnectorStateModel::SingletonWriter, "singleton_writer"),
        (
            ConnectorStateModel::Crdt {
                crdt_type: CrdtType::LwwMap,
            },
            "crdt(lww_map)",
        ),
        (
            ConnectorStateModel::Crdt {
                crdt_type: CrdtType::OrSet,
            },
            "crdt(or_set)",
        ),
        (
            ConnectorStateModel::Crdt {
                crdt_type: CrdtType::GCounter,
            },
            "crdt(g_counter)",
        ),
        (
            ConnectorStateModel::Crdt {
                crdt_type: CrdtType::PnCounter,
            },
            "crdt(pn_counter)",
        ),
    ];
    for (variant, expected) in cases {
        assert_eq!(
            variant.to_string(),
            expected,
            "ConnectorStateModel::Display drift on {variant:?}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. ConnectorStateModel JSON round-trip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn connector_state_model_json_roundtrip_preserves_every_variant() {
    let cases = [
        ConnectorStateModel::Stateless,
        ConnectorStateModel::SingletonWriter,
        ConnectorStateModel::Crdt {
            crdt_type: CrdtType::LwwMap,
        },
        ConnectorStateModel::Crdt {
            crdt_type: CrdtType::OrSet,
        },
        ConnectorStateModel::Crdt {
            crdt_type: CrdtType::GCounter,
        },
        ConnectorStateModel::Crdt {
            crdt_type: CrdtType::PnCounter,
        },
    ];
    for variant in cases {
        let json = serde_json::to_string(&variant).expect("serialize");
        let back: ConnectorStateModel = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(variant, back);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Default is Stateless
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn connector_state_model_default_is_stateless() {
    // Operator-visible default posture: connectors are stateless
    // unless explicitly opted into SingletonWriter or Crdt.
    let default_model: ConnectorStateModel = ConnectorStateModel::default();
    assert_eq!(default_model, ConnectorStateModel::Stateless);
    assert!(default_model.is_stateless());
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. ConnectorStateModel predicates truth table
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn connector_state_model_predicates_truth_table() {
    let stateless = ConnectorStateModel::Stateless;
    let singleton = ConnectorStateModel::SingletonWriter;
    let crdt = ConnectorStateModel::Crdt {
        crdt_type: CrdtType::LwwMap,
    };

    assert!(stateless.is_stateless());
    assert!(!stateless.is_singleton_writer());
    assert!(!stateless.is_crdt());
    assert_eq!(stateless.crdt_type(), None);

    assert!(!singleton.is_stateless());
    assert!(singleton.is_singleton_writer());
    assert!(!singleton.is_crdt());
    assert_eq!(singleton.crdt_type(), None);

    assert!(!crdt.is_stateless());
    assert!(!crdt.is_singleton_writer());
    assert!(crdt.is_crdt());
    assert_eq!(crdt.crdt_type(), Some(CrdtType::LwwMap));
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. CrdtType per-variant serde tag
// ─────────────────────────────────────────────────────────────────────────────

const CRDT_TYPE_CASES: &[(CrdtType, &str)] = &[
    (CrdtType::LwwMap, "lww_map"),
    (CrdtType::OrSet, "or_set"),
    (CrdtType::GCounter, "g_counter"),
    (CrdtType::PnCounter, "pn_counter"),
];

#[test]
fn crdt_type_json_tag_pinned_per_variant() {
    for (variant, expected) in CRDT_TYPE_CASES {
        let json = serde_json::to_string(variant).expect("serialize");
        assert_eq!(
            json,
            format!("\"{expected}\""),
            "CrdtType serde JSON tag drift on {variant:?}"
        );
    }
}

#[test]
fn crdt_type_json_and_cbor_roundtrip_per_variant() {
    for (variant, _) in CRDT_TYPE_CASES {
        let json = serde_json::to_string(variant).expect("serialize");
        let back_json: CrdtType = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*variant, back_json);

        let mut buf = Vec::new();
        ciborium::ser::into_writer(variant, &mut buf).expect("CBOR encode");
        let back_cbor: CrdtType = ciborium::de::from_reader(buf.as_slice()).expect("CBOR decode");
        assert_eq!(*variant, back_cbor);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. CrdtType Display agrees with serde tag
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn crdt_type_display_agrees_with_serde_tag_byte_for_byte() {
    for (variant, expected) in CRDT_TYPE_CASES {
        let displayed = variant.to_string();
        let stringy = variant.as_str();
        let json = serde_json::to_string(variant).expect("serialize");
        assert_eq!(displayed, *expected);
        assert_eq!(displayed, stringy);
        assert_eq!(json.trim_matches('"'), displayed);
    }
}

#[test]
fn crdt_type_count_is_four() {
    assert_eq!(
        CRDT_TYPE_CASES.len(),
        4,
        "CrdtType has 4 documented variants"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. ConnectorHealth per-variant `status` tag (lowercase)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn connector_health_status_tag_pinned_for_healthy() {
    let value = serde_json::to_value(&ConnectorHealth::Healthy).expect("serialize");
    assert_eq!(
        value,
        serde_json::json!({"status": "healthy"}),
        "Healthy MUST serialize as `{{\"status\": \"healthy\"}}` (lowercase, no extra fields)"
    );
}

#[test]
fn connector_health_status_tag_pinned_for_degraded() {
    let health = ConnectorHealth::degraded("CPU saturated");
    let value = serde_json::to_value(&health).expect("serialize");
    let obj = value.as_object().expect("object");
    assert_eq!(obj.get("status").and_then(|v| v.as_str()), Some("degraded"));
    assert_eq!(
        obj.get("reason").and_then(|v| v.as_str()),
        Some("CPU saturated")
    );
}

#[test]
fn connector_health_status_tag_pinned_for_unavailable() {
    let health = ConnectorHealth::unavailable("network partition");
    let value = serde_json::to_value(&health).expect("serialize");
    let obj = value.as_object().expect("object");
    assert_eq!(
        obj.get("status").and_then(|v| v.as_str()),
        Some("unavailable")
    );
    assert_eq!(
        obj.get("reason").and_then(|v| v.as_str()),
        Some("network partition")
    );
    assert!(
        obj.get("since").is_some(),
        "Unavailable MUST carry `since` timestamp"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. ConnectorHealth nested fields preserved through JSON round-trip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn connector_health_json_roundtrip_preserves_healthy() {
    let original = ConnectorHealth::Healthy;
    let json = serde_json::to_string(&original).expect("serialize");
    let back: ConnectorHealth = serde_json::from_str(&json).expect("deserialize");
    assert!(matches!(back, ConnectorHealth::Healthy));
}

#[test]
fn connector_health_json_roundtrip_preserves_degraded_reason() {
    let original = ConnectorHealth::degraded("rate limited");
    let json = serde_json::to_string(&original).expect("serialize");
    let back: ConnectorHealth = serde_json::from_str(&json).expect("deserialize");
    match back {
        ConnectorHealth::Degraded { reason } => assert_eq!(reason, "rate limited"),
        other => panic!("expected Degraded, got {other:?}"),
    }
}

#[test]
fn connector_health_json_roundtrip_preserves_unavailable_payload() {
    let original = ConnectorHealth::unavailable("timeout");
    let json = serde_json::to_string(&original).expect("serialize");
    let back: ConnectorHealth = serde_json::from_str(&json).expect("deserialize");
    match back {
        ConnectorHealth::Unavailable { reason, since: _ } => {
            assert_eq!(reason, "timeout");
        }
        other => panic!("expected Unavailable, got {other:?}"),
    }
}

#[test]
fn connector_health_cbor_carries_status_tag_for_healthy() {
    let original = ConnectorHealth::Healthy;
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&original, &mut buf).expect("encode");
    let value: CborValue = ciborium::de::from_reader(buf.as_slice()).expect("decode as Value");
    let map = match value {
        CborValue::Map(m) => m,
        other => panic!("ConnectorHealth MUST encode as CBOR Map, got {other:?}"),
    };
    let status_value = map
        .iter()
        .find_map(|(k, v)| match k {
            CborValue::Text(s) if s == "status" => Some(v),
            _ => None,
        })
        .expect("missing `status` discriminator");
    match status_value {
        CborValue::Text(s) => assert_eq!(s, "healthy"),
        other => panic!("`status` MUST be Text, got {other:?}"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. PascalCase rejected for all three classifiers
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn connector_state_model_rejects_pascal_case_type_tag() {
    let bad = serde_json::json!({"type": "Stateless"});
    let parsed = serde_json::from_value::<ConnectorStateModel>(bad);
    assert!(
        parsed.is_err(),
        "PascalCase `type` tag MUST be rejected — only snake_case is canonical"
    );
}

#[test]
fn connector_state_model_rejects_singleton_camel_case() {
    let bad = serde_json::json!({"type": "singletonWriter"});
    let parsed = serde_json::from_value::<ConnectorStateModel>(bad);
    assert!(parsed.is_err(), "camelCase tag MUST be rejected");
}

#[test]
fn crdt_type_rejects_pascal_case() {
    for bad in [
        r#""LwwMap""#,
        r#""OrSet""#,
        r#""GCounter""#,
        r#""PnCounter""#,
    ] {
        let parsed = serde_json::from_str::<CrdtType>(bad);
        assert!(parsed.is_err(), "{bad} MUST be rejected");
    }
}

#[test]
fn connector_health_rejects_pascal_case_status() {
    let bad = serde_json::json!({"status": "Healthy"});
    let parsed = serde_json::from_value::<ConnectorHealth>(bad);
    assert!(
        parsed.is_err(),
        "PascalCase `status` MUST be rejected — only lowercase is canonical"
    );
}

#[test]
fn connector_health_rejects_unknown_status() {
    let bad = serde_json::json!({"status": "broken"});
    let parsed = serde_json::from_value::<ConnectorHealth>(bad);
    assert!(parsed.is_err(), "unknown status MUST be rejected");
}
