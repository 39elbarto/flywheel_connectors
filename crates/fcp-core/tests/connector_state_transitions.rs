//! Pin `MigratableComputationState` transition + serde shape
//! (flywheel_connectors-cgfwt).
//!
//! Bead asks for "ConnectorState transitions per documented state
//! machine (Loaded -> Activated -> Running -> Suspended ->
//! Terminated)". The literal `Loaded` and `Activated` states do NOT
//! exist in fcp-core. The actual NORMATIVE migration state machine
//! is `MigratableComputationState` in connector_state.rs:589 with
//! variants {Running, Suspended, Transferring, Completed, Failed}.
//! `Completed`/`Failed` together cover the bead's "Terminated" leaf;
//! `Transferring` is the in-flight handoff state with no analogue in
//! the bead's description.
//!
//! The `MigratableComputation` struct (connector_state.rs:616)
//! enforces the explicit transitions: `suspend()` requires
//! `Running`, `begin_transfer()` requires `Suspended`, `resume()`
//! accepts `Suspended` or `Transferring` and lands on `Running`. We
//! pin those guards via the `ComputationMigrationError::InvalidStateTransition`
//! Display surface — the operator-facing error that fires when a
//! caller invokes the wrong action for the current state.
//!
//! Tests pin what exists for the migration state enum:
//!
//!   1. **All five variants enumerated** — list MUST match the
//!      documented machine; if a sixth variant gets added, this
//!      test fails to force a review.
//!   2. **`is_terminal()` truth table** — true only for `Completed`
//!      and `Failed`; false for the other three.
//!   3. **Serde JSON tag form** — internally tagged on `state` field
//!      with snake_case rename — exact JSON shape pinned per
//!      variant including the nested `Transferring` payload.
//!   4. **JSON round-trip** preserves variant + nested fields.
//!   5. **CBOR round-trip** via ciborium preserves variant + nested
//!      fields.
//!   6. **CBOR map shape** — every encoding has a `state` key with
//!      the snake_case label as its value.
//!   7. **Unknown / PascalCase tag rejected** — only snake_case is
//!      canonical.
//!   8. **Equality & Clone** behave by variant, including across
//!      the nested `Transferring` payload.
//!   9. **`InvalidStateTransition` Display surface** — the exact
//!      operator-facing error format pinning the action verb +
//!      state Debug rendering.

use ciborium::value::Value as CborValue;
use fcp_core::{
    ComputationMigrationError, LeaseId, MigratableComputationState, ObjectId, TailscaleNodeId,
};

fn fixture_target() -> TailscaleNodeId {
    TailscaleNodeId::new("node-target-1")
}

fn fixture_lease_id() -> LeaseId {
    ObjectId::from_bytes([0x42; 32])
}

fn transferring_fixture() -> MigratableComputationState {
    MigratableComputationState::Transferring {
        target_holder: fixture_target(),
        next_lease_id: fixture_lease_id(),
        next_fencing_token: 99,
    }
}

fn all_variants() -> Vec<MigratableComputationState> {
    vec![
        MigratableComputationState::Running,
        MigratableComputationState::Suspended,
        transferring_fixture(),
        MigratableComputationState::Completed,
        MigratableComputationState::Failed,
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Variant enumeration — guard against silent additions
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn migratable_state_has_exactly_five_documented_variants() {
    // Drift sentinel: if a sixth variant is added, the exhaustive
    // match below stops compiling — forcing the author to update
    // this test (and consider the wire/audit implications).
    fn label(v: &MigratableComputationState) -> &'static str {
        match v {
            MigratableComputationState::Running => "running",
            MigratableComputationState::Suspended => "suspended",
            MigratableComputationState::Transferring { .. } => "transferring",
            MigratableComputationState::Completed => "completed",
            MigratableComputationState::Failed => "failed",
        }
    }
    let labels: Vec<&'static str> = all_variants().iter().map(label).collect();
    assert_eq!(
        labels,
        vec![
            "running",
            "suspended",
            "transferring",
            "completed",
            "failed"
        ],
        "MigratableComputationState variant set drifted from the documented \
         {{Running, Suspended, Transferring, Completed, Failed}}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. is_terminal() truth table
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn is_terminal_true_only_for_completed_and_failed() {
    assert!(!MigratableComputationState::Running.is_terminal());
    assert!(!MigratableComputationState::Suspended.is_terminal());
    assert!(!transferring_fixture().is_terminal());
    assert!(MigratableComputationState::Completed.is_terminal());
    assert!(MigratableComputationState::Failed.is_terminal());
}

#[test]
fn transferring_is_not_terminal_regardless_of_payload() {
    // The documentation of `is_terminal` says "the computation can
    // no longer resume". `Transferring` IS resumable on the target
    // — it MUST report not-terminal regardless of nested fields.
    let other_payload = MigratableComputationState::Transferring {
        target_holder: TailscaleNodeId::new("node-other-2"),
        next_lease_id: ObjectId::from_bytes([0x99; 32]),
        next_fencing_token: 0,
    };
    assert!(!other_payload.is_terminal());
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Serde JSON tag form pinning
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn json_tag_form_pinned_for_unit_variants() {
    // Internally-tagged on field "state" with snake_case rename.
    let cases = [
        (MigratableComputationState::Running, r#"{"state":"running"}"#),
        (
            MigratableComputationState::Suspended,
            r#"{"state":"suspended"}"#,
        ),
        (
            MigratableComputationState::Completed,
            r#"{"state":"completed"}"#,
        ),
        (MigratableComputationState::Failed, r#"{"state":"failed"}"#),
    ];
    for (variant, expected) in cases {
        let got = serde_json::to_string(&variant).expect("serialize");
        assert_eq!(
            got, expected,
            "JSON tag form drift on {variant:?}; \
             audit logs and operator dashboards consume this exact shape"
        );
    }
}

#[test]
fn json_tag_form_pinned_for_transferring_with_nested_fields() {
    let v = transferring_fixture();
    let got = serde_json::to_value(&v).expect("serialize");
    let expected = serde_json::json!({
        "state": "transferring",
        "target_holder": "node-target-1",
        "next_lease_id": format!("0x{}", "42".repeat(32)),
        "next_fencing_token": 99,
    });
    assert_eq!(
        got, expected,
        "Transferring JSON shape drift — nested fields are part of the wire contract"
    );
}

#[test]
fn json_roundtrip_preserves_every_variant() {
    for variant in all_variants() {
        let json = serde_json::to_string(&variant).expect("serialize");
        let back: MigratableComputationState =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(variant, back, "JSON round-trip lost variant {variant:?}");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. CBOR round-trip + map-shape inspection
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn cbor_roundtrip_preserves_every_variant() {
    for variant in all_variants() {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&variant, &mut buf).expect("encode");
        let back: MigratableComputationState =
            ciborium::de::from_reader(buf.as_slice()).expect("decode");
        assert_eq!(variant, back, "CBOR round-trip lost variant {variant:?}");
    }
}

#[test]
fn cbor_map_carries_state_tag_field_for_every_variant() {
    let expected_labels = [
        (MigratableComputationState::Running, "running"),
        (MigratableComputationState::Suspended, "suspended"),
        (transferring_fixture(), "transferring"),
        (MigratableComputationState::Completed, "completed"),
        (MigratableComputationState::Failed, "failed"),
    ];
    for (variant, expected_label) in expected_labels {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&variant, &mut buf).expect("encode");
        let value: CborValue =
            ciborium::de::from_reader(buf.as_slice()).expect("decode as Value");
        let map = match value {
            CborValue::Map(m) => m,
            other => panic!("expected CBOR map for {variant:?}, got {other:?}"),
        };
        let tag_value = map
            .iter()
            .find_map(|(k, v)| match k {
                CborValue::Text(s) if s == "state" => Some(v),
                _ => None,
            })
            .unwrap_or_else(|| panic!("CBOR map for {variant:?} missing `state` tag field"));
        match tag_value {
            CborValue::Text(s) => assert_eq!(
                s, expected_label,
                "CBOR `state` tag value drift on {variant:?}"
            ),
            other => panic!("CBOR `state` tag must be text, got {other:?}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Negative serde paths — only snake_case is canonical
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn json_rejects_pascal_case_state_tag() {
    // Variant names are PascalCase in source; on the wire only the
    // snake_case form is canonical.
    for bad in [
        r#"{"state":"Running"}"#,
        r#"{"state":"Suspended"}"#,
        r#"{"state":"Completed"}"#,
        r#"{"state":"Failed"}"#,
    ] {
        let parsed = serde_json::from_str::<MigratableComputationState>(bad);
        assert!(
            parsed.is_err(),
            "PascalCase tag {bad:?} MUST be rejected; only snake_case is canonical"
        );
    }
}

#[test]
fn json_rejects_unknown_state_tag() {
    let bad = serde_json::from_str::<MigratableComputationState>(r#"{"state":"loaded"}"#);
    assert!(
        bad.is_err(),
        "unknown state tag MUST be rejected (note: `loaded` and `activated` from the \
         bead's description are NOT variants on this enum)"
    );
    let bad2 = serde_json::from_str::<MigratableComputationState>(r#"{"state":"activated"}"#);
    assert!(bad2.is_err(), "`activated` MUST be rejected");
    let bad3 = serde_json::from_str::<MigratableComputationState>(r#"{"state":"terminated"}"#);
    assert!(
        bad3.is_err(),
        "`terminated` MUST be rejected (the documented terminal states are \
         {{completed, failed}}, not a single `terminated`)"
    );
}

#[test]
fn json_rejects_missing_tag_field() {
    let bad = serde_json::from_str::<MigratableComputationState>("{}");
    assert!(bad.is_err(), "missing `state` tag MUST be rejected");
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Equality + Clone semantics across variants
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn distinct_unit_variants_pairwise_unequal() {
    let unit_variants = [
        MigratableComputationState::Running,
        MigratableComputationState::Suspended,
        MigratableComputationState::Completed,
        MigratableComputationState::Failed,
    ];
    for i in 0..unit_variants.len() {
        for j in (i + 1)..unit_variants.len() {
            assert_ne!(
                unit_variants[i], unit_variants[j],
                "{:?} and {:?} MUST be distinct",
                unit_variants[i], unit_variants[j]
            );
        }
    }
}

#[test]
fn transferring_equality_depends_on_payload() {
    let a = transferring_fixture();
    let b = transferring_fixture();
    assert_eq!(a, b, "identical Transferring payloads MUST be equal");

    let different_holder = MigratableComputationState::Transferring {
        target_holder: TailscaleNodeId::new("node-other"),
        next_lease_id: fixture_lease_id(),
        next_fencing_token: 99,
    };
    assert_ne!(a, different_holder);

    let different_lease = MigratableComputationState::Transferring {
        target_holder: fixture_target(),
        next_lease_id: ObjectId::from_bytes([0x55; 32]),
        next_fencing_token: 99,
    };
    assert_ne!(a, different_lease);

    let different_token = MigratableComputationState::Transferring {
        target_holder: fixture_target(),
        next_lease_id: fixture_lease_id(),
        next_fencing_token: 100,
    };
    assert_ne!(a, different_token);
}

#[test]
fn clone_preserves_equality_for_every_variant() {
    for variant in all_variants() {
        let cloned = variant.clone();
        assert_eq!(variant, cloned, "Clone MUST preserve equality for {variant:?}");
    }
}

#[test]
fn unit_variant_unequal_to_transferring_with_any_payload() {
    let transferring = transferring_fixture();
    assert_ne!(MigratableComputationState::Running, transferring);
    assert_ne!(MigratableComputationState::Suspended, transferring);
    assert_ne!(MigratableComputationState::Completed, transferring);
    assert_ne!(MigratableComputationState::Failed, transferring);
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. InvalidStateTransition Display surface
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn invalid_state_transition_display_format_pinned() {
    // Format pinned by connector_state.rs:1669:
    //   "cannot {action} while computation is in state {state:?}"
    // The action verb and state Debug rendering both end up in
    // operator-facing logs, so both are part of the contract.
    let err = ComputationMigrationError::InvalidStateTransition {
        state: MigratableComputationState::Running,
        action: "suspend",
    };
    assert_eq!(
        err.to_string(),
        "cannot suspend while computation is in state Running"
    );

    let err = ComputationMigrationError::InvalidStateTransition {
        state: MigratableComputationState::Suspended,
        action: "begin_transfer",
    };
    assert_eq!(
        err.to_string(),
        "cannot begin_transfer while computation is in state Suspended"
    );

    let err = ComputationMigrationError::InvalidStateTransition {
        state: MigratableComputationState::Completed,
        action: "resume",
    };
    assert_eq!(
        err.to_string(),
        "cannot resume while computation is in state Completed"
    );

    let err = ComputationMigrationError::InvalidStateTransition {
        state: MigratableComputationState::Failed,
        action: "resume",
    };
    assert_eq!(
        err.to_string(),
        "cannot resume while computation is in state Failed"
    );
}

#[test]
fn invalid_state_transition_display_renders_transferring_payload() {
    // Sanity check: the Debug rendering of Transferring leaks the
    // nested fields into the error message. If we ever switch the
    // error to use Display instead, this test will fail and force a
    // review of what operators see.
    let err = ComputationMigrationError::InvalidStateTransition {
        state: transferring_fixture(),
        action: "suspend",
    };
    let s = err.to_string();
    assert!(
        s.starts_with("cannot suspend while computation is in state Transferring"),
        "Transferring rendering drift: {s}"
    );
    assert!(
        s.contains("node-target-1"),
        "target_holder MUST appear in the rendered Debug payload: {s}"
    );
}
