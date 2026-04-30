//! Pin `ForkResolution` ↔ `ConnectorStateModel` validity truth table +
//! `ForkResolutionOutcome` + `StateForkDetectionResult` + `resolve_by_lease`
//! ordering — the closest analogue to "PolicyConflictResolution variant
//! Display" (flywheel_connectors-w4b4c).
//!
//! Bead asks for `PolicyConflictResolution` Display + serde tag pinning. No
//! type literally named `PolicyConflictResolution` exists in fcp-core. The
//! closest "conflict resolution" analogue is [`ForkResolution`] at
//! `crates/fcp-core/src/connector_state.rs:1807` — a 3-variant strategy enum
//! used to resolve fork conflicts (competing writes) in connector state. A
//! state fork IS a conflict; choosing a strategy IS the resolution.
//!
//! Existing `recovery_strategy_variant_matrix.rs` covers ForkResolution
//! Display tokens, JSON tag stability, CBOR tag bytes, and noncanonical
//! rejection. This pin adds the orthogonal invariants:
//!   * `ForkResolution::is_valid_for(model)` full truth table —
//!     ChooseByLease only valid for SingletonWriter, CrdtMerge only for
//!     Crdt models, ManualResolution always valid (a critical safety
//!     contract: ManualResolution is the universal fallback),
//!   * `ForkResolutionOutcome` JSON shape with embedded ForkResolution
//!     `strategy` round-trip + nested ForkEvent + Optional `winning_head`,
//!   * `StateForkDetectionResult` externally-tagged enum (NoFork variant
//!     carries `head` + `seq`; ForkDetected carries a tuple ForkEvent),
//!   * `ForkEvent::resolve_by_lease` ordered truth table: `a > b → branch_a`,
//!     `a < b → branch_b`, `a == b → None` (the canonical tie-rule that
//!     escalates to ManualResolution).

use ciborium::Value as CborValue;
use fcp_core::{
    ConnectorId, ConnectorStateModel, CrdtType, ForkEvent, ForkResolution, ForkResolutionOutcome,
    ObjectId, StateForkDetectionResult, ZoneId,
};
use serde_json::json;

fn obj(byte: u8) -> ObjectId {
    ObjectId::from_bytes([byte; 32])
}

fn fork_event() -> ForkEvent {
    ForkEvent::new(
        obj(0x10),
        obj(0xaa),
        obj(0xbb),
        7,
        1_700_000_500,
        ZoneId::work(),
        ConnectorId::from_static("connector:test"),
    )
}

const ALL_RESOLUTIONS: &[ForkResolution] = &[
    ForkResolution::ChooseByLease,
    ForkResolution::ManualResolution,
    ForkResolution::CrdtMerge,
];

#[test]
fn fork_resolution_validity_truth_table_per_state_model() {
    // Models we'll evaluate against:
    let stateless = ConnectorStateModel::Stateless;
    let singleton = ConnectorStateModel::SingletonWriter;
    let crdt_lww = ConnectorStateModel::Crdt {
        crdt_type: CrdtType::LwwMap,
    };
    let crdt_orset = ConnectorStateModel::Crdt {
        crdt_type: CrdtType::OrSet,
    };

    // ChooseByLease is ONLY valid for SingletonWriter.
    assert!(!ForkResolution::ChooseByLease.is_valid_for(&stateless));
    assert!(ForkResolution::ChooseByLease.is_valid_for(&singleton));
    assert!(!ForkResolution::ChooseByLease.is_valid_for(&crdt_lww));
    assert!(!ForkResolution::ChooseByLease.is_valid_for(&crdt_orset));

    // CrdtMerge is ONLY valid for any Crdt variant.
    assert!(!ForkResolution::CrdtMerge.is_valid_for(&stateless));
    assert!(!ForkResolution::CrdtMerge.is_valid_for(&singleton));
    assert!(ForkResolution::CrdtMerge.is_valid_for(&crdt_lww));
    assert!(ForkResolution::CrdtMerge.is_valid_for(&crdt_orset));

    // ManualResolution is the universal fallback — must be valid for ALL
    // models, including new ones added in the future.
    for model in [&stateless, &singleton, &crdt_lww, &crdt_orset] {
        assert!(
            ForkResolution::ManualResolution.is_valid_for(model),
            "ManualResolution must be valid for {model:?}"
        );
    }
}

#[test]
fn fork_resolution_manual_is_universally_valid_across_all_crdt_types() {
    // Walk every CrdtType to confirm ManualResolution still applies.
    let crdt_types = [
        CrdtType::LwwMap,
        CrdtType::OrSet,
        CrdtType::GCounter,
        CrdtType::PnCounter,
    ];
    for crdt_type in crdt_types {
        let model = ConnectorStateModel::Crdt { crdt_type };
        assert!(
            ForkResolution::ManualResolution.is_valid_for(&model),
            "ManualResolution must be valid for Crdt {{ crdt_type: {crdt_type:?} }}"
        );
        assert!(
            ForkResolution::CrdtMerge.is_valid_for(&model),
            "CrdtMerge must be valid for every Crdt variant"
        );
        assert!(
            !ForkResolution::ChooseByLease.is_valid_for(&model),
            "ChooseByLease must NOT be valid for Crdt"
        );
    }
}

#[test]
fn fork_resolution_validity_disjoint_for_singleton_vs_crdt() {
    // Sentinel: ChooseByLease and CrdtMerge are disjoint — no model can
    // accept both. Otherwise the safety contract collapses (a model could
    // silently accept a strategy that doesn't match its merge semantics).
    for resolution_model in [
        ConnectorStateModel::Stateless,
        ConnectorStateModel::SingletonWriter,
        ConnectorStateModel::Crdt {
            crdt_type: CrdtType::LwwMap,
        },
    ] {
        let lease_ok = ForkResolution::ChooseByLease.is_valid_for(&resolution_model);
        let crdt_ok = ForkResolution::CrdtMerge.is_valid_for(&resolution_model);
        assert!(
            !(lease_ok && crdt_ok),
            "ChooseByLease and CrdtMerge cannot both be valid for {resolution_model:?}"
        );
    }
}

#[test]
fn fork_resolution_distinct_variants_have_distinct_display() {
    let mut seen = std::collections::HashSet::new();
    for &r in ALL_RESOLUTIONS {
        let s = r.to_string();
        assert!(seen.insert(s.clone()), "Display collision: `{s}`");
    }
}

#[test]
fn fork_resolution_outcome_json_shape_pins_embedded_strategy() {
    // ForkResolutionOutcome carries:
    //   { fork_event, strategy, winning_head: Option, resolved_at }
    // The embedded `strategy` must serialize via ForkResolution snake_case.
    let outcome = ForkResolutionOutcome {
        fork_event: fork_event(),
        strategy: ForkResolution::ChooseByLease,
        winning_head: Some(obj(0xaa)),
        resolved_at: 1_700_000_600,
        resolved: true,
        failure_reason: None,
        decision_detail: Some("test outcome".to_string()),
    };

    let value = serde_json::to_value(&outcome).unwrap();
    let obj_value = value.as_object().expect("must be object");

    let expected_keys: std::collections::BTreeSet<&str> = [
        "fork_event",
        "strategy",
        "winning_head",
        "resolved_at",
        "resolved",
        "failure_reason",
        "decision_detail",
    ]
    .into_iter()
    .collect();
    let actual: std::collections::BTreeSet<&str> = obj_value.keys().map(String::as_str).collect();
    assert_eq!(actual, expected_keys, "outcome shape drift: {obj_value:?}");

    assert_eq!(obj_value.get("strategy"), Some(&json!("choose_by_lease")));
    assert_eq!(obj_value.get("resolved_at"), Some(&json!(1_700_000_600)));
}

#[test]
fn fork_resolution_outcome_json_roundtrip_for_each_strategy() {
    for &strategy in ALL_RESOLUTIONS {
        let outcome = ForkResolutionOutcome {
            fork_event: fork_event(),
            strategy,
            winning_head: None,
            resolved_at: 1_700_000_700,
            resolved: false,
            failure_reason: Some("tie requires manual review".to_string()),
            decision_detail: None,
        };
        let bytes = serde_json::to_vec(&outcome).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v.get("strategy").unwrap(), &json!(strategy.to_string()));
        // Round-trip back into ForkResolutionOutcome and confirm strategy survives.
        // (ForkResolutionOutcome doesn't derive PartialEq because ForkEvent
        // payload comparisons go through field equality.)
        let back: ForkResolutionOutcome = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.strategy, strategy);
        assert_eq!(back.resolved_at, 1_700_000_700);
        assert!(back.winning_head.is_none());
    }
}

#[test]
fn fork_resolution_outcome_cbor_roundtrip_preserves_strategy() {
    let outcome = ForkResolutionOutcome {
        fork_event: fork_event(),
        strategy: ForkResolution::CrdtMerge,
        winning_head: Some(obj(0xbb)),
        resolved_at: 1_700_000_800,
        resolved: true,
        failure_reason: None,
        decision_detail: Some("crdt merge".to_string()),
    };
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&outcome, &mut bytes).unwrap();
    let back: ForkResolutionOutcome = ciborium::de::from_reader(&bytes[..]).unwrap();
    assert_eq!(back.strategy, ForkResolution::CrdtMerge);
    assert_eq!(back.resolved_at, 1_700_000_800);
    assert_eq!(back.winning_head, Some(obj(0xbb)));
}

#[test]
fn state_fork_detection_result_no_fork_externally_tagged_with_head_seq() {
    // StateForkDetectionResult is externally tagged (default for non-renamed
    // enums). NoFork carries struct-style payload `{ head, seq }`.
    let result = StateForkDetectionResult::NoFork {
        head: obj(0x42),
        seq: 12,
    };
    let v = serde_json::to_value(&result).unwrap();
    let obj_value = v.as_object().expect("externally tagged → outer object");

    assert_eq!(
        obj_value.len(),
        1,
        "external tag must produce single-key wrapper"
    );
    let inner = obj_value
        .get("NoFork")
        .expect("NoFork variant key")
        .as_object()
        .expect("NoFork payload object");
    assert!(inner.contains_key("head"));
    assert_eq!(inner.get("seq"), Some(&json!(12)));

    let back: StateForkDetectionResult = serde_json::from_value(v).unwrap();
    assert!(!back.is_fork());
}

#[test]
fn state_fork_detection_result_fork_detected_carries_tuple_event() {
    let result = StateForkDetectionResult::ForkDetected(fork_event());
    let v = serde_json::to_value(&result).unwrap();
    let obj_value = v.as_object().expect("must be outer object");

    assert_eq!(obj_value.len(), 1);
    assert!(obj_value.contains_key("ForkDetected"));

    // Round-trip preserves event.
    let back: StateForkDetectionResult = serde_json::from_value(v).unwrap();
    assert!(back.is_fork());
    assert!(back.fork_event().is_some());
    let event = back.fork_event().unwrap();
    assert_eq!(event.fork_seq, 7);
}

#[test]
fn state_fork_detection_result_cbor_value_inspection_pins_external_tag() {
    let result = StateForkDetectionResult::NoFork {
        head: obj(0x33),
        seq: 5,
    };
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&result, &mut bytes).unwrap();
    let value: CborValue = ciborium::de::from_reader(&bytes[..]).unwrap();
    let map = match value {
        CborValue::Map(m) => m,
        other => panic!("expected outer Map, got {other:?}"),
    };
    assert_eq!(
        map.len(),
        1,
        "externally-tagged enum must serialize as single-key CBOR map"
    );
    let (key, _) = &map[0];
    match key {
        CborValue::Text(text) => assert_eq!(text, "NoFork"),
        other => panic!("expected Text key, got {other:?}"),
    }
}

#[test]
fn resolve_by_lease_truth_table_picks_higher_seq_branch() {
    let event = fork_event();
    let branch_a = event.branch_a;
    let branch_b = event.branch_b;

    // a > b → branch_a wins.
    assert_eq!(event.resolve_by_lease(10, 5), Some(branch_a));
    // a < b → branch_b wins.
    assert_eq!(event.resolve_by_lease(3, 9), Some(branch_b));
    // a == b → None (escalate to ManualResolution).
    assert!(event.resolve_by_lease(7, 7).is_none());
    // Boundary: 0 vs 0 → None.
    assert!(event.resolve_by_lease(0, 0).is_none());
    // Boundary: u64::MAX vs u64::MAX-1 → branch_a.
    assert_eq!(
        event.resolve_by_lease(u64::MAX, u64::MAX - 1),
        Some(branch_a)
    );
    // Boundary: u64::MAX-1 vs u64::MAX → branch_b.
    assert_eq!(
        event.resolve_by_lease(u64::MAX - 1, u64::MAX),
        Some(branch_b)
    );
}

#[test]
fn fork_event_serde_full_field_roundtrip() {
    let event = fork_event();
    let bytes = serde_json::to_vec(&event).unwrap();
    let back: ForkEvent = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(back, event);

    let mut cbor_bytes = Vec::new();
    ciborium::ser::into_writer(&event, &mut cbor_bytes).unwrap();
    let back_cbor: ForkEvent = ciborium::de::from_reader(&cbor_bytes[..]).unwrap();
    assert_eq!(back_cbor, event);
}
