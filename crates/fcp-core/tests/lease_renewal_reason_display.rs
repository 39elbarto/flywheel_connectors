//! Pin `LeaseValidationError` + `LeasePurpose` variant Display — the closest
//! analogue to "LeaseRenewalReason variant Display"
//! (flywheel_connectors-wdmd7).
//!
//! Bead asks for `LeaseRenewalReason` Display + serde pinning. No type
//! literally named `LeaseRenewalReason` exists in fcp-core. The closest
//! analogue with "reason"-shaped variants is [`LeaseValidationError`] at
//! `crates/fcp-core/src/lease.rs:609`, whose 7 variants enumerate the
//! reasons a lease (including a renewal) is rejected:
//!   * `Expired` — renewal of a lease whose wall-clock TTL has passed,
//!   * `Superseded { held_seq, current_seq }` — renewal attempted under a
//!     stale `lease_seq` (the canonical "stale renewal" reason),
//!   * `SubjectMismatch`, `ZoneMismatch`, `PurposeMismatch`,
//!     `CoordinatorMismatch`, `InsufficientQuorum`.
//! [`LeasePurpose`] at `crates/fcp-core/src/lease.rs:53` is the input that
//! feeds `PurposeMismatch`, with its own snake_case Display + serde rename.
//!
//! This test pins:
//!   * Every `LeaseValidationError` Display match-arm phrase verbatim,
//!   * Payload preservation in the rendered string for every variant carrying
//!     a `u64` / id field,
//!   * Distinct discriminants → distinct Display strings,
//!   * `LeasePurpose` 6-variant snake_case Display + serde rename + Display
//!     matches serde wire form,
//!   * Round-trip every `LeasePurpose` variant through JSON + CBOR.

use ciborium::Value as CborValue;
use fcp_core::{LeasePurpose, LeaseValidationError, ObjectId, TailscaleNodeId, ZoneId};
use serde_json::json;

fn obj(byte: u8) -> ObjectId {
    ObjectId::from_bytes([byte; 32])
}

fn node(name: &str) -> TailscaleNodeId {
    TailscaleNodeId::new(name)
}

const ALL_PURPOSES: &[(LeasePurpose, &str)] = &[
    (LeasePurpose::OperationExecution, "operation_execution"),
    (LeasePurpose::ConnectorStateWrite, "connector_state_write"),
    (LeasePurpose::ComputationMigration, "computation_migration"),
    (LeasePurpose::CoordinatorElection, "coordinator_election"),
    (LeasePurpose::Migration, "migration"),
    (LeasePurpose::ResourceAccess, "resource_access"),
];

#[test]
fn lease_validation_error_expired_display_pins_phrasing() {
    let err = LeaseValidationError::Expired {
        expired_at: 1_700_000_000,
        now: 1_700_000_500,
    };
    let msg = err.to_string();
    assert_eq!(
        msg,
        "lease expired at 1700000000, current time is 1700000500"
    );
}

#[test]
fn lease_validation_error_superseded_display_pins_stale_renewal_phrasing() {
    // This is the canonical "stale renewal" case — a renewal arrived holding
    // an older `lease_seq` than the system has already advanced past.
    let err = LeaseValidationError::Superseded {
        held_seq: 7,
        current_seq: 12,
    };
    let msg = err.to_string();
    assert_eq!(msg, "lease superseded: held seq 7, current seq 12");
    assert!(msg.contains("7"), "must mention held seq: {msg}");
    assert!(msg.contains("12"), "must mention current seq: {msg}");
}

#[test]
fn lease_validation_error_subject_mismatch_display_pins_phrasing() {
    let expected = obj(0x11);
    let got = obj(0x22);
    let err = LeaseValidationError::SubjectMismatch {
        expected: expected.clone(),
        got: got.clone(),
    };
    let msg = err.to_string();
    assert_eq!(
        msg,
        format!("subject mismatch: expected {expected}, got {got}")
    );
    assert!(msg.contains(&expected.to_string()));
    assert!(msg.contains(&got.to_string()));
}

#[test]
fn lease_validation_error_zone_mismatch_display_pins_phrasing() {
    let err = LeaseValidationError::ZoneMismatch {
        expected: ZoneId::work(),
        got: ZoneId::private(),
    };
    let msg = err.to_string();
    assert_eq!(msg, "zone mismatch: expected z:work, got z:private");
}

#[test]
fn lease_validation_error_purpose_mismatch_display_pins_phrasing() {
    let err = LeaseValidationError::PurposeMismatch {
        expected: LeasePurpose::OperationExecution,
        got: LeasePurpose::ConnectorStateWrite,
    };
    let msg = err.to_string();
    assert_eq!(
        msg,
        "purpose mismatch: expected operation_execution, got connector_state_write"
    );
}

#[test]
fn lease_validation_error_coordinator_mismatch_display_pins_phrasing() {
    let err = LeaseValidationError::CoordinatorMismatch {
        expected: node("coord-primary"),
        got: node("coord-secondary"),
    };
    let msg = err.to_string();
    assert_eq!(
        msg,
        "coordinator mismatch: expected coord-primary, got coord-secondary"
    );
}

#[test]
fn lease_validation_error_insufficient_quorum_display_pins_phrasing() {
    let err = LeaseValidationError::InsufficientQuorum {
        required: 5,
        got: 3,
    };
    let msg = err.to_string();
    assert_eq!(msg, "insufficient quorum: required 5 signatures, got 3");
}

#[test]
fn all_lease_validation_error_variants_have_distinct_display() {
    // Build one of each variant with same-shaped placeholder payload and
    // confirm none collide. Avoids a future variant being accidentally
    // assigned a duplicate Display phrase.
    let variants = [
        LeaseValidationError::Expired {
            expired_at: 0,
            now: 0,
        },
        LeaseValidationError::SubjectMismatch {
            expected: obj(0xa),
            got: obj(0xb),
        },
        LeaseValidationError::ZoneMismatch {
            expected: ZoneId::work(),
            got: ZoneId::private(),
        },
        LeaseValidationError::PurposeMismatch {
            expected: LeasePurpose::OperationExecution,
            got: LeasePurpose::ConnectorStateWrite,
        },
        LeaseValidationError::Superseded {
            held_seq: 1,
            current_seq: 2,
        },
        LeaseValidationError::CoordinatorMismatch {
            expected: node("a"),
            got: node("b"),
        },
        LeaseValidationError::InsufficientQuorum {
            required: 1,
            got: 0,
        },
    ];
    let strings: std::collections::HashSet<_> = variants.iter().map(ToString::to_string).collect();
    assert_eq!(
        strings.len(),
        variants.len(),
        "Display collision across variants: {strings:?}"
    );
}

#[test]
fn lease_validation_error_implements_std_error() {
    fn assert_error<E: std::error::Error>(_: &E) {}
    let err = LeaseValidationError::Expired {
        expired_at: 0,
        now: 0,
    };
    assert_error(&err);
}

#[test]
fn lease_purpose_display_matches_snake_case_for_every_variant() {
    for &(variant, expected) in ALL_PURPOSES {
        assert_eq!(
            variant.to_string(),
            expected,
            "Display for {variant:?} != `{expected}`"
        );
    }
}

#[test]
fn lease_purpose_serde_matches_display_for_every_variant() {
    // serde rename_all = "snake_case" must agree with Display verbatim;
    // otherwise log scrapers and wire payloads will disagree.
    for &(variant, expected) in ALL_PURPOSES {
        let value = serde_json::to_value(variant).unwrap();
        assert_eq!(
            value,
            json!(expected),
            "serde for {variant:?} != `{expected}`"
        );
        assert_eq!(
            variant.to_string(),
            expected,
            "Display drifted from serde for {variant:?}"
        );
        let back: LeasePurpose = serde_json::from_value(value).unwrap();
        assert_eq!(back, variant);
    }
}

#[test]
fn lease_purpose_cbor_roundtrip_for_every_variant() {
    for &(variant, expected) in ALL_PURPOSES {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&variant, &mut bytes).unwrap();
        let back: LeasePurpose = ciborium::de::from_reader(&bytes[..]).unwrap();
        assert_eq!(back, variant);

        // The CBOR form must be a TEXT scalar (not a tagged map) since the
        // enum is rename_all'd to a unit-string form.
        let value: CborValue = ciborium::de::from_reader(&bytes[..]).unwrap();
        match value {
            CborValue::Text(text) => assert_eq!(text, expected),
            other => panic!("LeasePurpose must encode as CBOR Text, got {other:?}"),
        }
    }
}

#[test]
fn lease_purpose_rejects_pascalcase_input() {
    // Loud sentinel: dropping rename_all = "snake_case" would let PascalCase
    // through and silently break wire compatibility with on-disk leases.
    let result: Result<LeasePurpose, _> = serde_json::from_value(json!("OperationExecution"));
    assert!(result.is_err(), "must reject PascalCase, got {result:?}");
    let result: Result<LeasePurpose, _> = serde_json::from_value(json!("Migration"));
    assert!(result.is_err(), "must reject PascalCase, got {result:?}");
}

#[test]
fn lease_purpose_distinct_variants_serialize_distinctly() {
    let mut seen = std::collections::HashSet::new();
    for &(variant, _) in ALL_PURPOSES {
        let v = serde_json::to_value(variant).unwrap();
        assert!(
            seen.insert(v.clone()),
            "duplicate serialization for {variant:?}: {v:?}"
        );
    }
}
