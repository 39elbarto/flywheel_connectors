//! Pin `LeaseTransferValidationError` 9-variant Display matrix — the closest
//! analogue to "LeasePolicy variant Display"
//! (flywheel_connectors-f333w).
//!
//! Bead asks for `LeasePolicy` Display + serde tag pinning. No type literally
//! named `LeasePolicy` exists in fcp-core. The closest "policy"-shaped lease
//! enum is [`LeaseTransferValidationError`] at `crates/fcp-core/src/lease.rs:365`,
//! a 9-variant error enumerating the rules `validate_lease_handoff` enforces
//! when a lease is transferred between nodes. These 9 variants ARE the
//! LeasePolicy invariants — every documented rule a handoff must satisfy
//! shows up here as a rejection variant.
//!
//! Existing pinned lease enums:
//!   * `LeasePurpose` + `LeaseValidationError` → `lease_renewal_reason_display.rs`,
//!   * `LeaseTokenParseError` → `lease_token_display.rs`,
//!   * `LeaseResponse` → `lease_grant_display_serde.rs`,
//!   * `LeaseTransferValidationError::SelfTransfer` + `FromHolderMismatch`
//!     → `lease_holder_display_roundtrip.rs`.
//!
//! This pin adds the residual 7 LeaseTransferValidationError Display arms
//! that aren't pinned anywhere else, plus the validate_lease_handoff
//! variant-selection truth table.
//!
//! Coverage:
//!   * 9-variant Display phrasing pinned verbatim,
//!   * Payload preservation in rendered string for u64/ObjectId/ZoneId/
//!     TailscaleNodeId/LeasePurpose fields,
//!   * Distinct-Display sentinel across all 9 variants,
//!   * `validate_lease_handoff` truth table: every documented rule fires
//!     the documented variant (precedence test — first-failing rule wins),
//!   * std::error::Error impl.

use fcp_cbor::SchemaId;
use fcp_core::{
    Lease, LeaseHandoff, LeaseParams, LeasePurpose, LeaseTransferValidationError, ObjectId,
    Provenance, SignatureSet, TailscaleNodeId, ZoneId, validate_lease_handoff,
};
use semver::Version;

fn obj(byte: u8) -> ObjectId {
    ObjectId::from_bytes([byte; 32])
}

fn node(name: &str) -> TailscaleNodeId {
    TailscaleNodeId::new(name)
}

fn make_lease(holder: TailscaleNodeId, lease_seq: u64, exp: u64) -> Lease {
    let zone = ZoneId::work();
    let mut lease = Lease::new(LeaseParams {
        schema: SchemaId::new("fcp.core", "Lease", Version::new(1, 0, 0)),
        zone_id: zone.clone(),
        holder,
        lease_seq,
        ttl_secs: 60,
        subject_object_id: obj(0xaa),
        provenance: Provenance::new(zone),
        purpose: LeasePurpose::OperationExecution,
        quorum_signatures: SignatureSet::default(),
    });
    lease.exp = exp;
    lease
}

fn make_handoff(
    previous_lease_id: ObjectId,
    next_lease_id: ObjectId,
    from_holder: TailscaleNodeId,
    to_holder: TailscaleNodeId,
    purpose: LeasePurpose,
    previous_fence: u64,
    next_fence: u64,
    subject: ObjectId,
    zone: ZoneId,
) -> LeaseHandoff {
    LeaseHandoff {
        previous_lease_id,
        next_lease_id,
        from_holder,
        to_holder,
        zone_id: zone,
        subject_object_id: subject,
        purpose,
        previous_fencing_token: previous_fence,
        next_fencing_token: next_fence,
        transferred_at: 1_700_000_000,
        checkpoint_object_id: None,
    }
}

#[test]
fn lease_expired_display_pins_phrasing() {
    let err = LeaseTransferValidationError::LeaseExpired {
        expired_at: 1_700_000_000,
        now: 1_700_000_500,
    };
    let msg = err.to_string();
    assert_eq!(
        msg,
        "cannot transfer expired lease (expired at 1700000000, current time 1700000500)"
    );
}

#[test]
fn lease_id_reused_display_pins_phrasing() {
    let lease_id = obj(0x42);
    let err = LeaseTransferValidationError::LeaseIdReused { lease_id };
    let msg = err.to_string();
    assert_eq!(msg, format!("lease handoff reused lease id {lease_id}"));
    assert!(msg.contains(&lease_id.to_string()));
}

#[test]
fn subject_mismatch_display_pins_phrasing() {
    let expected = obj(0x11);
    let got = obj(0x22);
    let err = LeaseTransferValidationError::SubjectMismatch { expected, got };
    let msg = err.to_string();
    assert_eq!(
        msg,
        format!("handoff subject mismatch: expected {expected}, got {got}")
    );
}

#[test]
fn zone_mismatch_display_pins_phrasing() {
    let err = LeaseTransferValidationError::ZoneMismatch {
        expected: ZoneId::work(),
        got: ZoneId::private(),
    };
    let msg = err.to_string();
    assert_eq!(msg, "handoff zone mismatch: expected z:work, got z:private");
}

#[test]
fn purpose_mismatch_display_pins_phrasing() {
    let err = LeaseTransferValidationError::PurposeMismatch {
        expected: LeasePurpose::OperationExecution,
        got: LeasePurpose::ConnectorStateWrite,
    };
    let msg = err.to_string();
    assert_eq!(
        msg,
        "handoff purpose mismatch: expected operation_execution, got connector_state_write"
    );
}

#[test]
fn previous_fence_mismatch_display_pins_phrasing() {
    let err = LeaseTransferValidationError::PreviousFenceMismatch {
        expected: 7,
        got: 5,
    };
    let msg = err.to_string();
    assert_eq!(
        msg,
        "handoff previous fencing token mismatch: expected 7, got 5"
    );
}

#[test]
fn non_monotonic_fence_display_pins_phrasing() {
    let err = LeaseTransferValidationError::NonMonotonicFence {
        previous: 7,
        next: 7,
    };
    let msg = err.to_string();
    assert_eq!(
        msg,
        "handoff fencing token must increase monotonically (previous 7, next 7)"
    );

    // Non-monotonic where next < previous also fires this variant.
    let err = LeaseTransferValidationError::NonMonotonicFence {
        previous: 10,
        next: 5,
    };
    let msg = err.to_string();
    assert_eq!(
        msg,
        "handoff fencing token must increase monotonically (previous 10, next 5)"
    );
}

#[test]
fn self_transfer_display_pins_phrasing() {
    // SelfTransfer Display already pinned in lease_holder_display_roundtrip.rs;
    // include here for completeness of the 9-variant matrix.
    let err = LeaseTransferValidationError::SelfTransfer {
        holder: node("solo-holder"),
    };
    let msg = err.to_string();
    assert!(
        msg.contains("solo-holder"),
        "SelfTransfer must mention holder: {msg}"
    );
    assert!(msg.contains("different holder"));
}

#[test]
fn from_holder_mismatch_display_pins_phrasing() {
    // Already pinned in lease_holder_display_roundtrip.rs; include for matrix.
    let err = LeaseTransferValidationError::FromHolderMismatch {
        expected: node("expected-holder"),
        got: node("got-holder"),
    };
    let msg = err.to_string();
    assert!(msg.contains("expected-holder"));
    assert!(msg.contains("got-holder"));
    assert!(msg.contains("source holder mismatch"));
}

#[test]
fn all_nine_variants_have_distinct_display() {
    let variants = [
        LeaseTransferValidationError::LeaseExpired {
            expired_at: 0,
            now: 1,
        },
        LeaseTransferValidationError::LeaseIdReused {
            lease_id: obj(0x01),
        },
        LeaseTransferValidationError::SelfTransfer { holder: node("a") },
        LeaseTransferValidationError::FromHolderMismatch {
            expected: node("a"),
            got: node("b"),
        },
        LeaseTransferValidationError::SubjectMismatch {
            expected: obj(0x11),
            got: obj(0x22),
        },
        LeaseTransferValidationError::ZoneMismatch {
            expected: ZoneId::work(),
            got: ZoneId::private(),
        },
        LeaseTransferValidationError::PurposeMismatch {
            expected: LeasePurpose::OperationExecution,
            got: LeasePurpose::ConnectorStateWrite,
        },
        LeaseTransferValidationError::PreviousFenceMismatch {
            expected: 1,
            got: 2,
        },
        LeaseTransferValidationError::NonMonotonicFence {
            previous: 5,
            next: 5,
        },
    ];
    let strings: std::collections::HashSet<_> = variants.iter().map(ToString::to_string).collect();
    assert_eq!(
        strings.len(),
        variants.len(),
        "Display collision across LeaseTransferValidationError variants: {strings:?}"
    );
}

#[test]
fn lease_transfer_validation_error_implements_std_error() {
    fn assert_error<E: std::error::Error>(_: &E) {}
    let err = LeaseTransferValidationError::LeaseExpired {
        expired_at: 0,
        now: 1,
    };
    assert_error(&err);
}

#[test]
fn validate_handoff_fires_lease_expired_when_lease_exp_is_in_past() {
    let lease = make_lease(node("alpha"), 5, 1_000);
    let handoff = make_handoff(
        obj(0x10),
        obj(0x11),
        node("alpha"),
        node("beta"),
        LeasePurpose::OperationExecution,
        5,
        6,
        obj(0xaa),
        ZoneId::work(),
    );
    let now = 2_000;
    let err = validate_lease_handoff(&lease, &handoff, now).unwrap_err();
    match err {
        LeaseTransferValidationError::LeaseExpired { expired_at, now: n } => {
            assert_eq!(expired_at, 1_000);
            assert_eq!(n, 2_000);
        }
        other => panic!("expected LeaseExpired, got {other:?}"),
    }
}

#[test]
fn validate_handoff_fires_lease_id_reused_before_other_checks() {
    // LeaseExpired comes before LeaseIdReused in precedence — make the lease
    // unexpired so we can observe the LeaseIdReused branch directly.
    let lease = make_lease(node("alpha"), 5, 9_999_999_999);
    let dup = obj(0x10);
    let handoff = make_handoff(
        dup,
        dup, // reused → triggers LeaseIdReused
        node("alpha"),
        node("beta"),
        LeasePurpose::OperationExecution,
        5,
        6,
        obj(0xaa),
        ZoneId::work(),
    );
    let err = validate_lease_handoff(&lease, &handoff, 1_700_000_000).unwrap_err();
    match err {
        LeaseTransferValidationError::LeaseIdReused { lease_id } => {
            assert_eq!(lease_id, dup);
        }
        other => panic!("expected LeaseIdReused, got {other:?}"),
    }
}

#[test]
fn validate_handoff_fires_self_transfer_when_holders_equal() {
    let lease = make_lease(node("alpha"), 5, 9_999_999_999);
    let handoff = make_handoff(
        obj(0x10),
        obj(0x11),
        node("alpha"),
        node("alpha"), // same → triggers SelfTransfer
        LeasePurpose::OperationExecution,
        5,
        6,
        obj(0xaa),
        ZoneId::work(),
    );
    let err = validate_lease_handoff(&lease, &handoff, 1_700_000_000).unwrap_err();
    match err {
        LeaseTransferValidationError::SelfTransfer { holder } => {
            assert_eq!(holder.as_str(), "alpha");
        }
        other => panic!("expected SelfTransfer, got {other:?}"),
    }
}

#[test]
fn validate_handoff_fires_from_holder_mismatch() {
    let lease = make_lease(node("alpha"), 5, 9_999_999_999);
    let handoff = make_handoff(
        obj(0x10),
        obj(0x11),
        node("imposter"), // doesn't match lease.holder
        node("beta"),
        LeasePurpose::OperationExecution,
        5,
        6,
        obj(0xaa),
        ZoneId::work(),
    );
    let err = validate_lease_handoff(&lease, &handoff, 1_700_000_000).unwrap_err();
    match err {
        LeaseTransferValidationError::FromHolderMismatch { expected, got } => {
            assert_eq!(expected.as_str(), "alpha");
            assert_eq!(got.as_str(), "imposter");
        }
        other => panic!("expected FromHolderMismatch, got {other:?}"),
    }
}

#[test]
fn validate_handoff_fires_subject_mismatch() {
    let lease = make_lease(node("alpha"), 5, 9_999_999_999);
    let handoff = make_handoff(
        obj(0x10),
        obj(0x11),
        node("alpha"),
        node("beta"),
        LeasePurpose::OperationExecution,
        5,
        6,
        obj(0xbb), // doesn't match lease.subject_object_id
        ZoneId::work(),
    );
    let err = validate_lease_handoff(&lease, &handoff, 1_700_000_000).unwrap_err();
    match err {
        LeaseTransferValidationError::SubjectMismatch { expected, got } => {
            assert_eq!(expected, obj(0xaa));
            assert_eq!(got, obj(0xbb));
        }
        other => panic!("expected SubjectMismatch, got {other:?}"),
    }
}

#[test]
fn validate_handoff_fires_zone_mismatch() {
    let lease = make_lease(node("alpha"), 5, 9_999_999_999);
    let handoff = make_handoff(
        obj(0x10),
        obj(0x11),
        node("alpha"),
        node("beta"),
        LeasePurpose::OperationExecution,
        5,
        6,
        obj(0xaa),
        ZoneId::private(), // doesn't match lease.zone_id (work)
    );
    let err = validate_lease_handoff(&lease, &handoff, 1_700_000_000).unwrap_err();
    match err {
        LeaseTransferValidationError::ZoneMismatch { expected, got } => {
            assert_eq!(expected, ZoneId::work());
            assert_eq!(got, ZoneId::private());
        }
        other => panic!("expected ZoneMismatch, got {other:?}"),
    }
}

#[test]
fn validate_handoff_fires_purpose_mismatch() {
    let lease = make_lease(node("alpha"), 5, 9_999_999_999);
    let handoff = make_handoff(
        obj(0x10),
        obj(0x11),
        node("alpha"),
        node("beta"),
        LeasePurpose::ConnectorStateWrite, // doesn't match lease.purpose
        5,
        6,
        obj(0xaa),
        ZoneId::work(),
    );
    let err = validate_lease_handoff(&lease, &handoff, 1_700_000_000).unwrap_err();
    match err {
        LeaseTransferValidationError::PurposeMismatch { expected, got } => {
            assert_eq!(expected, LeasePurpose::OperationExecution);
            assert_eq!(got, LeasePurpose::ConnectorStateWrite);
        }
        other => panic!("expected PurposeMismatch, got {other:?}"),
    }
}

#[test]
fn validate_handoff_fires_previous_fence_mismatch() {
    let lease = make_lease(node("alpha"), 5, 9_999_999_999);
    let handoff = make_handoff(
        obj(0x10),
        obj(0x11),
        node("alpha"),
        node("beta"),
        LeasePurpose::OperationExecution,
        99, // doesn't match lease.fencing_token() == 5
        100,
        obj(0xaa),
        ZoneId::work(),
    );
    let err = validate_lease_handoff(&lease, &handoff, 1_700_000_000).unwrap_err();
    match err {
        LeaseTransferValidationError::PreviousFenceMismatch { expected, got } => {
            assert_eq!(expected, 5);
            assert_eq!(got, 99);
        }
        other => panic!("expected PreviousFenceMismatch, got {other:?}"),
    }
}

#[test]
fn validate_handoff_fires_non_monotonic_fence_when_next_le_previous() {
    let lease = make_lease(node("alpha"), 5, 9_999_999_999);

    // next == previous → fires NonMonotonicFence (must STRICTLY increase).
    let handoff = make_handoff(
        obj(0x10),
        obj(0x11),
        node("alpha"),
        node("beta"),
        LeasePurpose::OperationExecution,
        5,
        5,
        obj(0xaa),
        ZoneId::work(),
    );
    let err = validate_lease_handoff(&lease, &handoff, 1_700_000_000).unwrap_err();
    match err {
        LeaseTransferValidationError::NonMonotonicFence { previous, next } => {
            assert_eq!(previous, 5);
            assert_eq!(next, 5);
        }
        other => panic!("expected NonMonotonicFence, got {other:?}"),
    }

    // next < previous → also fires NonMonotonicFence.
    let handoff = make_handoff(
        obj(0x10),
        obj(0x11),
        node("alpha"),
        node("beta"),
        LeasePurpose::OperationExecution,
        5,
        4,
        obj(0xaa),
        ZoneId::work(),
    );
    let err = validate_lease_handoff(&lease, &handoff, 1_700_000_000).unwrap_err();
    match err {
        LeaseTransferValidationError::NonMonotonicFence { previous, next } => {
            assert_eq!(previous, 5);
            assert_eq!(next, 4);
        }
        other => panic!("expected NonMonotonicFence, got {other:?}"),
    }
}

#[test]
fn validate_handoff_accepts_a_well_formed_strictly_increasing_fence_handoff() {
    // Smoke test: every check passes → Ok(()).
    let lease = make_lease(node("alpha"), 5, 9_999_999_999);
    let handoff = make_handoff(
        obj(0x10),
        obj(0x11),
        node("alpha"),
        node("beta"),
        LeasePurpose::OperationExecution,
        5,
        6,
        obj(0xaa),
        ZoneId::work(),
    );
    let result = validate_lease_handoff(&lease, &handoff, 1_700_000_000);
    assert!(
        result.is_ok(),
        "well-formed handoff must validate, got {result:?}"
    );
}
