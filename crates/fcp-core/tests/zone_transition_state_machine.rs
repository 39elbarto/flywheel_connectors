//! Pin `EnrollmentStatus` 5-variant Display + serde + predicate truth tables —
//! the closest analogue to "ZoneTransition state machine"
//! (flywheel_connectors-nn11p).
//!
//! Bead asks for `ZoneTransition` state machine + serde pinning. No type
//! literally named `ZoneTransition` exists in fcp-core. The closest
//! analogue with state-machine semantics over zone membership is
//! [`EnrollmentStatus`] at `crates/fcp-core/src/enrollment.rs:920`. A
//! device's enrollment IS its admission-into-zone transition; the 5
//! variants (Pending / Approved / Rejected / Revoked / Expired) represent
//! the state-machine vocabulary.
//!
//! `LifecycleState` is already pinned by `registry_sync_state_machine.rs`,
//! and `CheckpointAdvanceState` by `checkpoint_golden_vectors.rs`.
//! `EnrollmentStatus`'s wire form, Display, predicate truth tables, and
//! implied terminal-vs-transitive partition are residual unpinned territory.
//! Existing `enrollment_golden_vectors.rs` only generates CBOR vector
//! fixtures; it does not pin Display per variant or the predicate truth
//! tables exhaustively or the JSON shape.
//!
//! Coverage:
//!   * 5-variant snake_case serde rename matrix,
//!   * Display matches serde wire form for every variant,
//!   * `is_enrolled` exhaustive truth table (only Approved → true),
//!   * `is_renewable` exhaustive truth table (Approved + Expired only),
//!   * Terminal-vs-transitive partition: `is_renewable` implies "may
//!     re-enter the lifecycle"; Rejected and Revoked are documented
//!     terminals (no renewal path),
//!   * JSON + CBOR roundtrip per variant,
//!   * PascalCase rejection sentinel,
//!   * Use as HashMap key (Hash + Eq) for status-grouping in registries.

use ciborium::Value as CborValue;
use fcp_core::EnrollmentStatus;
use serde_json::json;

const ALL_STATUSES: &[(EnrollmentStatus, &str)] = &[
    (EnrollmentStatus::Pending, "pending"),
    (EnrollmentStatus::Approved, "approved"),
    (EnrollmentStatus::Rejected, "rejected"),
    (EnrollmentStatus::Revoked, "revoked"),
    (EnrollmentStatus::Expired, "expired"),
];

#[test]
fn enrollment_status_serde_uses_snake_case_for_every_variant() {
    for &(variant, wire) in ALL_STATUSES {
        let v = serde_json::to_value(variant).unwrap();
        assert_eq!(v, json!(wire), "{variant:?} must serialize to `{wire}`");
        let back: EnrollmentStatus = serde_json::from_value(v).unwrap();
        assert_eq!(back, variant);
    }
}

#[test]
fn enrollment_status_display_matches_serde_wire_form() {
    // Display must equal the serde form byte-for-byte. Otherwise log
    // scrapers and wire payloads diverge.
    for &(variant, wire) in ALL_STATUSES {
        assert_eq!(
            variant.to_string(),
            wire,
            "Display for {variant:?} != `{wire}`"
        );
    }
}

#[test]
fn is_enrolled_truth_table_only_approved_qualifies() {
    // Approved is the SOLE state in which the device is currently enrolled;
    // any other state means the device is NOT actively a zone member.
    for &(variant, _) in ALL_STATUSES {
        let expected = variant == EnrollmentStatus::Approved;
        assert_eq!(variant.is_enrolled(), expected, "is_enrolled({variant:?})");
    }
}

#[test]
fn is_renewable_truth_table_includes_approved_and_expired_only() {
    // is_renewable answers: can this state path-back into a fresh enrollment?
    // Approved + Expired qualify (re-approval / renewal flow).
    // Pending, Rejected, Revoked do NOT — they require a fresh request
    // (Pending), or are terminal (Rejected/Revoked).
    let renewable_set = [EnrollmentStatus::Approved, EnrollmentStatus::Expired];
    for &(variant, _) in ALL_STATUSES {
        let expected = renewable_set.contains(&variant);
        assert_eq!(
            variant.is_renewable(),
            expected,
            "is_renewable({variant:?}) — expected {expected}"
        );
    }
}

#[test]
fn rejected_and_revoked_are_terminal_neither_enrolled_nor_renewable() {
    // Loud sentinel for the documented terminal-state contract: Rejected
    // and Revoked must neither count as enrolled NOR be renewable. Any
    // future helper that flips one of these without the other invalidates
    // the audit invariants downstream.
    for terminal in [EnrollmentStatus::Rejected, EnrollmentStatus::Revoked] {
        assert!(!terminal.is_enrolled(), "{terminal:?} must not be enrolled");
        assert!(
            !terminal.is_renewable(),
            "{terminal:?} must not be renewable"
        );
    }
}

#[test]
fn approved_is_the_only_state_that_is_both_enrolled_and_renewable() {
    // Approved is the unique fixed-point of (is_enrolled ∧ is_renewable).
    // Pin this so refactoring either predicate doesn't accidentally
    // promote another state into the "actively serving" intersection.
    for &(variant, _) in ALL_STATUSES {
        let both = variant.is_enrolled() && variant.is_renewable();
        let expected = variant == EnrollmentStatus::Approved;
        assert_eq!(
            both, expected,
            "{variant:?}: both = {both}, expected {expected}"
        );
    }
}

#[test]
fn enrollment_status_cbor_roundtrip_for_every_variant() {
    for &(variant, expected) in ALL_STATUSES {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&variant, &mut bytes).unwrap();
        let back: EnrollmentStatus = ciborium::de::from_reader(&bytes[..]).unwrap();
        assert_eq!(back, variant);

        // CBOR shape: Text scalar (rename_all snake_case unit-variant).
        let value: CborValue = ciborium::de::from_reader(&bytes[..]).unwrap();
        match value {
            CborValue::Text(text) => assert_eq!(text, expected),
            other => panic!("EnrollmentStatus must encode as CBOR Text, got {other:?}"),
        }
    }
}

#[test]
fn enrollment_status_rejects_pascal_case() {
    // Loud sentinel: dropping rename_all = "snake_case" would let
    // PascalCase through and silently break wire compatibility.
    for bad in ["Approved", "Pending", "REJECTED", "InProgress"] {
        let result: Result<EnrollmentStatus, _> = serde_json::from_value(json!(bad));
        assert!(
            result.is_err(),
            "EnrollmentStatus must reject `{bad}`, got {result:?}"
        );
    }
}

#[test]
fn enrollment_status_distinct_variants_serialize_distinctly() {
    let mut seen = std::collections::HashSet::new();
    for &(variant, _) in ALL_STATUSES {
        let v = serde_json::to_value(variant).unwrap();
        assert!(
            seen.insert(v.clone()),
            "duplicate JSON for {variant:?}: {v:?}"
        );
    }
}

#[test]
fn enrollment_status_works_as_hashmap_key() {
    // EnrollmentStatus is used to bucket devices by status in registries.
    // Pin Hash + Eq via direct HashMap usage — same status into same
    // bucket; distinct statuses into distinct buckets.
    let mut counts: std::collections::HashMap<EnrollmentStatus, u32> =
        std::collections::HashMap::new();
    *counts.entry(EnrollmentStatus::Pending).or_insert(0) += 1;
    *counts.entry(EnrollmentStatus::Pending).or_insert(0) += 1;
    *counts.entry(EnrollmentStatus::Approved).or_insert(0) += 1;
    *counts.entry(EnrollmentStatus::Expired).or_insert(0) += 1;
    *counts.entry(EnrollmentStatus::Approved).or_insert(0) += 1;

    assert_eq!(counts.get(&EnrollmentStatus::Pending), Some(&2));
    assert_eq!(counts.get(&EnrollmentStatus::Approved), Some(&2));
    assert_eq!(counts.get(&EnrollmentStatus::Expired), Some(&1));
    assert_eq!(counts.get(&EnrollmentStatus::Rejected), None);
    assert_eq!(counts.get(&EnrollmentStatus::Revoked), None);
}

#[test]
fn enrollment_status_implied_terminality_partition_is_consistent() {
    // Terminality = "this state cannot transition forward to enrolled".
    // For our 5-variant lifecycle:
    //   Pending  → can become Approved (transient)
    //   Approved → already enrolled, can renew (transient)
    //   Expired  → renewable (transient)
    //   Rejected → terminal
    //   Revoked  → terminal
    //
    // Pin the partition as (is_renewable || is_enrolled) → transient,
    // !(is_renewable || is_enrolled) → terminal-or-pending. The Pending
    // state is the lone false-false case (it's neither enrolled nor
    // renewable, but is still pre-terminal). This grouping pins the
    // state-machine vocabulary.
    let mut transient = std::collections::HashSet::new();
    let mut terminal_or_pending = std::collections::HashSet::new();
    for &(variant, _) in ALL_STATUSES {
        if variant.is_enrolled() || variant.is_renewable() {
            transient.insert(variant);
        } else {
            terminal_or_pending.insert(variant);
        }
    }
    assert_eq!(
        transient,
        std::collections::HashSet::from([EnrollmentStatus::Approved, EnrollmentStatus::Expired,]),
        "transient set"
    );
    assert_eq!(
        terminal_or_pending,
        std::collections::HashSet::from([
            EnrollmentStatus::Pending,
            EnrollmentStatus::Rejected,
            EnrollmentStatus::Revoked,
        ]),
        "terminal-or-pending set"
    );
}

#[test]
fn enrollment_status_json_decode_accepts_all_canonical_wire_forms() {
    // Round-trip via JSON for every variant (independent of the per-variant
    // serialize test — this asserts the decode side is symmetric).
    for &(variant, wire) in ALL_STATUSES {
        let json_str = format!("\"{wire}\"");
        let back: EnrollmentStatus = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back, variant);
    }
}
