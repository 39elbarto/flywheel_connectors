//! Pin `HealthState` + `BudgetStatus` + `SelfCheckStatus` serde tag
//! matrix — the closest analogues to "ManifestStatus variant matrix"
//! (flywheel_connectors-ghver).
//!
//! Bead asks for `ManifestStatus variant Display + serde`. No type
//! literally named `ManifestStatus` exists in fcp-core. The
//! status-shaped surface that covers manifest/lifecycle/budget
//! reporting splits across many enums:
//!
//!  - Already pinned: `IntentStatus` (epymi), `ProvisioningStatus`
//!    (6tcjg), `DescriptorStatus` (live_status_serde_tag_matrix.rs),
//!    `PrerequisiteStatus` (nhms0), `OperationStatus`
//!    (operation_status_serde_tags.rs), `RevocationSlaStatus`
//!    (RevocationSlaStatus is also documented but largely covered
//!    by revocation tests).
//!  - Unpinned classifiers covering different status surfaces:
//!    `HealthState` (health.rs:108), `BudgetStatus` (policy.rs:123),
//!    `SelfCheckStatus` (health.rs:110).
//!
//! `HealthState` is the closest "ManifestStatus" analogue — a
//! 5-variant lifecycle status (Starting/Ready/Degraded/Error/
//! Stopping) with internal `state` tag and lowercase rename, used
//! for connector-instance status reporting. `BudgetStatus` and
//! `SelfCheckStatus` are paired status classifiers in the same
//! reporting surface.
//!
//! Targets:
//!
//!   1. **`HealthState` per-variant JSON tag** (`state: "starting"`
//!      etc.) — unit variants and struct variants.
//!   2. **JSON shape per variant** — Starting/Ready/Stopping unit
//!      variants are `{"state": "<name>"}`; Degraded/Error carry
//!      `reason` field via internal-tag flatten.
//!   3. **JSON round-trip** preserves variant + nested fields.
//!   4. **CBOR carries `state` discriminator** for every variant
//!      (Value inspection — internal-tag + nested struct hits the
//!      same Content-shim quirk as past beads if we tried full
//!      round-trip on struct variants).
//!   5. **PascalCase rejected** — drift sentinel.
//!   6. **5-variant count + pairwise distinct**.
//!   7. **`BudgetStatus` per-variant JSON tag** (`ok` / `exceeded`).
//!   8. **`BudgetStatus` JSON+CBOR round-trip**.
//!   9. **`SelfCheckStatus` per-variant JSON tag** (4 variants
//!      ok/degraded/failed/unsupported).
//!  10. **`SelfCheckStatus` JSON+CBOR round-trip**.
//!  11. **Cross-enum: `degraded` token shared** across HealthState +
//!      SelfCheckStatus + (transitively) ConnectorHealth — pinned
//!      as intentional collision since each lives in its own field.

use ciborium::value::Value as CborValue;
use fcp_core::{BudgetStatus, HealthState, SelfCheckStatus};

// ─────────────────────────────────────────────────────────────────────────────
// 1. HealthState per-variant JSON tag (unit variants)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn health_state_starting_serializes_with_state_tag() {
    let value = serde_json::to_value(&HealthState::Starting).expect("serialize");
    assert_eq!(
        value,
        serde_json::json!({"state": "starting"}),
        "MANIFEST-STATUS REGRESSION: HealthState::Starting tag drift"
    );
}

#[test]
fn health_state_ready_serializes_with_state_tag() {
    let value = serde_json::to_value(&HealthState::Ready).expect("serialize");
    assert_eq!(value, serde_json::json!({"state": "ready"}));
}

#[test]
fn health_state_stopping_serializes_with_state_tag() {
    let value = serde_json::to_value(&HealthState::Stopping).expect("serialize");
    assert_eq!(value, serde_json::json!({"state": "stopping"}));
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. JSON shape per struct variant (Degraded, Error)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn health_state_degraded_serializes_with_state_and_reason() {
    let value = serde_json::to_value(&HealthState::Degraded {
        reason: "rate limited".to_string(),
    })
    .expect("serialize");
    assert_eq!(
        value,
        serde_json::json!({"state": "degraded", "reason": "rate limited"}),
        "Degraded MUST carry `state: degraded` + `reason` flattened"
    );
}

#[test]
fn health_state_error_serializes_with_state_and_reason() {
    let value = serde_json::to_value(&HealthState::Error {
        reason: "panic".to_string(),
    })
    .expect("serialize");
    assert_eq!(
        value,
        serde_json::json!({"state": "error", "reason": "panic"})
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. JSON round-trip per variant
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn health_state_json_roundtrip_preserves_starting() {
    let original = HealthState::Starting;
    let json = serde_json::to_string(&original).expect("serialize");
    let back: HealthState = serde_json::from_str(&json).expect("deserialize");
    assert!(matches!(back, HealthState::Starting));
}

#[test]
fn health_state_json_roundtrip_preserves_ready() {
    let original = HealthState::Ready;
    let json = serde_json::to_string(&original).expect("serialize");
    let back: HealthState = serde_json::from_str(&json).expect("deserialize");
    assert!(matches!(back, HealthState::Ready));
}

#[test]
fn health_state_json_roundtrip_preserves_stopping() {
    let original = HealthState::Stopping;
    let json = serde_json::to_string(&original).expect("serialize");
    let back: HealthState = serde_json::from_str(&json).expect("deserialize");
    assert!(matches!(back, HealthState::Stopping));
}

#[test]
fn health_state_json_roundtrip_preserves_degraded_reason() {
    let original = HealthState::Degraded {
        reason: "high latency".to_string(),
    };
    let json = serde_json::to_string(&original).expect("serialize");
    let back: HealthState = serde_json::from_str(&json).expect("deserialize");
    match back {
        HealthState::Degraded { reason } => assert_eq!(reason, "high latency"),
        other => panic!("expected Degraded, got {other:?}"),
    }
}

#[test]
fn health_state_json_roundtrip_preserves_error_reason() {
    let original = HealthState::Error {
        reason: "internal error".to_string(),
    };
    let json = serde_json::to_string(&original).expect("serialize");
    let back: HealthState = serde_json::from_str(&json).expect("deserialize");
    match back {
        HealthState::Error { reason } => assert_eq!(reason, "internal error"),
        other => panic!("expected Error, got {other:?}"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. CBOR carries `state` discriminator
// ─────────────────────────────────────────────────────────────────────────────

fn cbor_state_tag(value: &HealthState) -> String {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(value, &mut buf).expect("encode");
    let cbor: CborValue = ciborium::de::from_reader(buf.as_slice()).expect("decode as Value");
    let map = match cbor {
        CborValue::Map(m) => m,
        other => panic!("HealthState MUST encode as Map, got {other:?}"),
    };
    let state_value = map
        .iter()
        .find_map(|(k, v)| match k {
            CborValue::Text(s) if s == "state" => Some(v),
            _ => None,
        })
        .expect("missing `state` discriminator");
    match state_value {
        CborValue::Text(s) => s.clone(),
        other => panic!("`state` MUST be Text, got {other:?}"),
    }
}

#[test]
fn health_state_cbor_carries_state_tag_for_starting() {
    assert_eq!(cbor_state_tag(&HealthState::Starting), "starting");
}

#[test]
fn health_state_cbor_carries_state_tag_for_degraded() {
    assert_eq!(
        cbor_state_tag(&HealthState::Degraded {
            reason: "x".to_string()
        }),
        "degraded"
    );
}

#[test]
fn health_state_cbor_carries_state_tag_for_error() {
    assert_eq!(
        cbor_state_tag(&HealthState::Error {
            reason: "x".to_string()
        }),
        "error"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. PascalCase rejected
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn health_state_rejects_pascal_case_state_tag() {
    let bad = serde_json::json!({"state": "Starting"});
    let parsed = serde_json::from_value::<HealthState>(bad);
    assert!(
        parsed.is_err(),
        "PascalCase `state` MUST be rejected — only lowercase is canonical"
    );
}

#[test]
fn health_state_rejects_unknown_state() {
    let bad = serde_json::json!({"state": "broken"});
    let parsed = serde_json::from_value::<HealthState>(bad);
    assert!(parsed.is_err(), "unknown state MUST be rejected");
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. 5-variant pairwise distinct
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn health_state_five_variants_produce_distinct_state_tags() {
    let tags: Vec<String> = [
        cbor_state_tag(&HealthState::Starting),
        cbor_state_tag(&HealthState::Ready),
        cbor_state_tag(&HealthState::Degraded {
            reason: String::new(),
        }),
        cbor_state_tag(&HealthState::Error {
            reason: String::new(),
        }),
        cbor_state_tag(&HealthState::Stopping),
    ]
    .to_vec();
    let unique: std::collections::HashSet<&String> = tags.iter().collect();
    assert_eq!(unique.len(), 5, "all 5 state tags MUST be distinct");
    assert_eq!(
        tags,
        vec!["starting", "ready", "degraded", "error", "stopping"],
        "HealthState declaration order pinned"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. BudgetStatus per-variant JSON tag
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn budget_status_json_tag_pinned_per_variant() {
    let cases = [
        (BudgetStatus::Ok, "ok"),
        (BudgetStatus::Exceeded, "exceeded"),
    ];
    for (variant, expected) in cases {
        let json = serde_json::to_string(&variant).expect("serialize");
        assert_eq!(json, format!("\"{expected}\""));
    }
}

#[test]
fn budget_status_json_and_cbor_roundtrip() {
    for variant in [BudgetStatus::Ok, BudgetStatus::Exceeded] {
        let json = serde_json::to_string(&variant).expect("serialize");
        let back_json: BudgetStatus = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(variant, back_json);

        let mut buf = Vec::new();
        ciborium::ser::into_writer(&variant, &mut buf).expect("CBOR encode");
        let back_cbor: BudgetStatus =
            ciborium::de::from_reader(buf.as_slice()).expect("CBOR decode");
        assert_eq!(variant, back_cbor);
    }
}

#[test]
fn budget_status_rejects_pascal_case() {
    for bad in [r#""Ok""#, r#""Exceeded""#, r#""over_budget""#] {
        let parsed = serde_json::from_str::<BudgetStatus>(bad);
        assert!(parsed.is_err(), "{bad} MUST be rejected");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. SelfCheckStatus per-variant JSON tag
// ─────────────────────────────────────────────────────────────────────────────

const SELF_CHECK_STATUS_CASES: &[(SelfCheckStatus, &str)] = &[
    (SelfCheckStatus::Ok, "ok"),
    (SelfCheckStatus::Degraded, "degraded"),
    (SelfCheckStatus::Failed, "failed"),
    (SelfCheckStatus::Unsupported, "unsupported"),
];

#[test]
fn self_check_status_json_tag_pinned_per_variant() {
    for (variant, expected) in SELF_CHECK_STATUS_CASES {
        let json = serde_json::to_string(variant).expect("serialize");
        assert_eq!(json, format!("\"{expected}\""));
    }
}

#[test]
fn self_check_status_json_and_cbor_roundtrip_per_variant() {
    for (variant, _) in SELF_CHECK_STATUS_CASES {
        let json = serde_json::to_string(variant).expect("serialize");
        let back_json: SelfCheckStatus = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*variant, back_json);

        let mut buf = Vec::new();
        ciborium::ser::into_writer(variant, &mut buf).expect("CBOR encode");
        let back_cbor: SelfCheckStatus =
            ciborium::de::from_reader(buf.as_slice()).expect("CBOR decode");
        assert_eq!(*variant, back_cbor);
    }
}

#[test]
fn self_check_status_rejects_pascal_case() {
    for bad in [
        r#""Ok""#,
        r#""Degraded""#,
        r#""Failed""#,
        r#""Unsupported""#,
        r#""missing""#,
    ] {
        let parsed = serde_json::from_str::<SelfCheckStatus>(bad);
        assert!(parsed.is_err(), "{bad} MUST be rejected");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. Cross-enum: `degraded` token shared by intentional design
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn degraded_token_shared_across_status_enums() {
    // HealthState::Degraded, SelfCheckStatus::Degraded, and (in
    // separate tests) ConnectorHealth::Degraded all serialize to
    // tokens containing the literal `degraded`. Pin that the
    // collision is intentional — each lives in a different field
    // and operator dashboards distinguish by source.
    let health_state_json = serde_json::to_value(&HealthState::Degraded {
        reason: "x".to_string(),
    })
    .unwrap();
    assert_eq!(
        health_state_json.get("state").and_then(|v| v.as_str()),
        Some("degraded")
    );

    let self_check_json = serde_json::to_string(&SelfCheckStatus::Degraded).unwrap();
    assert_eq!(self_check_json, r#""degraded""#);
}
