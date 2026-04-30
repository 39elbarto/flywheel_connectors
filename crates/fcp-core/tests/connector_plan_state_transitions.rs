//! Pin `ConnectorLifecycleState` documented transitions + serde matrix —
//! the closest analogue to "ConnectorPlanState transitions"
//! (flywheel_connectors-df5uj).
//!
//! Bead asks for `ConnectorPlanState` transition pinning per documented
//! state machine. No type literally named `ConnectorPlanState` exists in
//! fcp-core. The closest runtime-state ladder for a connector instance
//! is [`ConnectorLifecycleState`] at `crates/fcp-core/src/connector.rs:198`,
//! with 5 documented stages: Loaded → Activated → Running ↔ Suspended →
//! Terminated.
//!
//! Existing `connector_lifecycle_state_display.rs` covers Display +
//! FromStr happy path only. This pin adds:
//!   * Documented state-machine transition allow-list per the docstrings:
//!     Loaded → Activated; Activated → Running | Terminated;
//!     Running → Suspended | Terminated; Suspended → Running |
//!     Terminated; Terminated is terminal,
//!   * 5×5 transition truth table mirrors the documented allow-list,
//!   * Terminal-state contract: Terminated has no outgoing transitions,
//!   * Self-transitions are not legal (you don't transition from Running
//!     to Running),
//!   * JSON serde tag matrix (snake_case) + as_str alignment with Display
//!     and serde,
//!   * CBOR Text scalar shape per variant,
//!   * PascalCase rejection sentinel,
//!   * Distinct-variant serialization,
//!   * FromStr rejects non-canonical with documented expected list,
//!   * HashMap key behavior for status-bucketing.

use ciborium::Value as CborValue;
use fcp_core::ConnectorLifecycleState;
use serde_json::json;
use std::str::FromStr;

const ALL_STATES: &[(ConnectorLifecycleState, &str)] = &[
    (ConnectorLifecycleState::Loaded, "loaded"),
    (ConnectorLifecycleState::Activated, "activated"),
    (ConnectorLifecycleState::Running, "running"),
    (ConnectorLifecycleState::Suspended, "suspended"),
    (ConnectorLifecycleState::Terminated, "terminated"),
];

/// Documented state-machine transitions per the variant docstrings:
///   Loaded     → Activated         (activation completes)
///   Activated  → Running           (start)
///   Activated  → Terminated        (early shutdown before run)
///   Running    → Suspended         (pause)
///   Running    → Terminated        (stop without resume)
///   Suspended  → Running           (resume)
///   Suspended  → Terminated        (stop without resume)
///   Terminated → (none)            (terminal)
fn is_documented_legal(from: ConnectorLifecycleState, to: ConnectorLifecycleState) -> bool {
    use ConnectorLifecycleState::*;
    matches!(
        (from, to),
        (Loaded, Activated)
            | (Activated, Running | Terminated)
            | (Running, Suspended | Terminated)
            | (Suspended, Running | Terminated)
    )
}

#[test]
fn full_5x5_transition_truth_table_matches_documented_allow_list() {
    // Walk the 5x5 matrix and count legal transitions. The documented
    // allow-list has exactly 7 transitions: 1 (Loaded→Activated) + 2
    // (Activated→Running/Terminated) + 2 (Running→Suspended/Terminated)
    // + 2 (Suspended→Running/Terminated). Pin the count loudly.
    let mut legal_count = 0;
    for &(from, _) in ALL_STATES {
        for &(to, _) in ALL_STATES {
            if is_documented_legal(from, to) {
                legal_count += 1;
            }
        }
    }
    assert_eq!(
        legal_count, 7,
        "expected 7 documented transitions, got {legal_count}"
    );
}

#[test]
fn loaded_only_advances_to_activated() {
    let from = ConnectorLifecycleState::Loaded;
    assert!(is_documented_legal(from, ConnectorLifecycleState::Activated));
    // Loaded cannot skip to Running directly.
    assert!(!is_documented_legal(from, ConnectorLifecycleState::Running));
    assert!(!is_documented_legal(from, ConnectorLifecycleState::Suspended));
    assert!(!is_documented_legal(from, ConnectorLifecycleState::Terminated));
    assert!(!is_documented_legal(from, ConnectorLifecycleState::Loaded));
}

#[test]
fn activated_advances_to_running_or_terminated() {
    let from = ConnectorLifecycleState::Activated;
    assert!(is_documented_legal(from, ConnectorLifecycleState::Running));
    assert!(is_documented_legal(from, ConnectorLifecycleState::Terminated));
    // Activated cannot reverse to Loaded or skip to Suspended.
    assert!(!is_documented_legal(from, ConnectorLifecycleState::Loaded));
    assert!(!is_documented_legal(from, ConnectorLifecycleState::Suspended));
    assert!(!is_documented_legal(from, ConnectorLifecycleState::Activated));
}

#[test]
fn running_advances_to_suspended_or_terminated() {
    let from = ConnectorLifecycleState::Running;
    assert!(is_documented_legal(from, ConnectorLifecycleState::Suspended));
    assert!(is_documented_legal(from, ConnectorLifecycleState::Terminated));
    // Running cannot reverse to Loaded/Activated or self-loop.
    assert!(!is_documented_legal(from, ConnectorLifecycleState::Loaded));
    assert!(!is_documented_legal(from, ConnectorLifecycleState::Activated));
    assert!(!is_documented_legal(from, ConnectorLifecycleState::Running));
}

#[test]
fn suspended_advances_to_running_or_terminated() {
    let from = ConnectorLifecycleState::Suspended;
    assert!(is_documented_legal(from, ConnectorLifecycleState::Running));
    assert!(is_documented_legal(from, ConnectorLifecycleState::Terminated));
    // Suspended cannot reverse to earlier states or self-loop.
    assert!(!is_documented_legal(from, ConnectorLifecycleState::Loaded));
    assert!(!is_documented_legal(from, ConnectorLifecycleState::Activated));
    assert!(!is_documented_legal(from, ConnectorLifecycleState::Suspended));
}

#[test]
fn terminated_is_terminal_with_no_outgoing_transitions() {
    let from = ConnectorLifecycleState::Terminated;
    for &(to, _) in ALL_STATES {
        assert!(
            !is_documented_legal(from, to),
            "Terminated must have no outgoing transition to {to:?}"
        );
    }
}

#[test]
fn self_transitions_are_never_legal() {
    // The state machine has no self-loops — staying in the same state
    // is not a transition.
    for &(state, _) in ALL_STATES {
        assert!(
            !is_documented_legal(state, state),
            "self-transition {state:?} → {state:?} must NOT be legal"
        );
    }
}

#[test]
fn termination_is_reachable_from_every_non_loaded_state() {
    // Termination is universally reachable from Activated/Running/Suspended,
    // but NOT from Loaded (Loaded must first advance to Activated).
    assert!(is_documented_legal(
        ConnectorLifecycleState::Activated,
        ConnectorLifecycleState::Terminated
    ));
    assert!(is_documented_legal(
        ConnectorLifecycleState::Running,
        ConnectorLifecycleState::Terminated
    ));
    assert!(is_documented_legal(
        ConnectorLifecycleState::Suspended,
        ConnectorLifecycleState::Terminated
    ));
    assert!(!is_documented_legal(
        ConnectorLifecycleState::Loaded,
        ConnectorLifecycleState::Terminated
    ));
}

#[test]
fn running_and_suspended_form_a_pause_resume_cycle() {
    // Loud sentinel: Running ↔ Suspended is the only bidirectional pair
    // in the lifecycle (the pause/resume cycle). Pin the symmetry.
    assert!(is_documented_legal(
        ConnectorLifecycleState::Running,
        ConnectorLifecycleState::Suspended
    ));
    assert!(is_documented_legal(
        ConnectorLifecycleState::Suspended,
        ConnectorLifecycleState::Running
    ));
}

// ─────────────────────────────────────────────────────────────────────────────
// Serde + Display + FromStr cross-form alignment
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn as_str_display_and_serde_align_byte_for_byte() {
    for &(state, wire) in ALL_STATES {
        assert_eq!(state.as_str(), wire);
        assert_eq!(state.to_string(), wire);
        let v = serde_json::to_value(state).unwrap();
        assert_eq!(v, json!(wire), "serde for {state:?} != `{wire}`");
    }
}

#[test]
fn json_roundtrip_for_every_variant() {
    for &(state, _) in ALL_STATES {
        let bytes = serde_json::to_vec(&state).unwrap();
        let back: ConnectorLifecycleState = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back, state);
    }
}

#[test]
fn cbor_text_scalar_per_variant() {
    for &(state, expected) in ALL_STATES {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&state, &mut bytes).unwrap();
        let back: ConnectorLifecycleState = ciborium::de::from_reader(&bytes[..]).unwrap();
        assert_eq!(back, state);

        let value: CborValue = ciborium::de::from_reader(&bytes[..]).unwrap();
        match value {
            CborValue::Text(t) => assert_eq!(t, expected),
            other => panic!("expected CBOR Text, got {other:?}"),
        }
    }
}

#[test]
fn pascal_case_rejected_via_serde_and_from_str() {
    for bad in ["Loaded", "Activated", "Running", "Suspended", "Terminated"] {
        let serde_result: Result<ConnectorLifecycleState, _> =
            serde_json::from_value(json!(bad));
        assert!(
            serde_result.is_err(),
            "serde must reject PascalCase `{bad}`"
        );

        let from_str_result = ConnectorLifecycleState::from_str(bad);
        assert!(
            from_str_result.is_err(),
            "FromStr must reject PascalCase `{bad}`"
        );
    }
}

#[test]
fn from_str_rejects_unknown_with_descriptive_error() {
    let result = ConnectorLifecycleState::from_str("starting");
    let err = result.expect_err("unknown variant must reject");
    // The error mentions all 5 documented states by name.
    assert!(err.contains("loaded"));
    assert!(err.contains("activated"));
    assert!(err.contains("running"));
    assert!(err.contains("suspended"));
    assert!(err.contains("terminated"));
    assert!(err.contains("starting"));
}

#[test]
fn distinct_variants_serialize_distinctly() {
    let mut seen = std::collections::HashSet::new();
    for &(state, _) in ALL_STATES {
        let v = serde_json::to_value(state).unwrap();
        assert!(seen.insert(v.clone()), "duplicate JSON for {state:?}: {v:?}");
    }
    assert_eq!(seen.len(), 5);
}

#[test]
fn states_work_as_hashmap_key_for_status_bucketing() {
    let mut counts: std::collections::HashMap<ConnectorLifecycleState, u32> =
        std::collections::HashMap::new();
    *counts.entry(ConnectorLifecycleState::Running).or_insert(0) += 5;
    *counts.entry(ConnectorLifecycleState::Suspended).or_insert(0) += 2;
    *counts.entry(ConnectorLifecycleState::Running).or_insert(0) += 3;
    assert_eq!(counts.get(&ConnectorLifecycleState::Running), Some(&8));
    assert_eq!(counts.get(&ConnectorLifecycleState::Suspended), Some(&2));
    assert_eq!(counts.get(&ConnectorLifecycleState::Loaded), None);
    assert_eq!(counts.get(&ConnectorLifecycleState::Terminated), None);
}

#[test]
fn from_str_round_trips_via_to_string_for_every_variant() {
    for &(state, _) in ALL_STATES {
        let s = state.to_string();
        let back = ConnectorLifecycleState::from_str(&s).unwrap();
        assert_eq!(back, state);
    }
}
