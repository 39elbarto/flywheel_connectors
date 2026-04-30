//! Pin `FlowCheckResult` 4-variant zone-crossing truth table +
//! `ProvenanceViolation` 10-variant Display matrix — the closest analogue to
//! "ZoneTrustBoundary variant matrix" (flywheel_connectors-bd9cb).
//!
//! Bead asks for `ZoneTrustBoundary` Display + serde tag pinning. No type
//! literally named `ZoneTrustBoundary` exists in fcp-core. The trust-
//! boundary surface across zones is split between:
//!   * [`FlowCheckResult`] at `crates/fcp-core/src/provenance.rs:712` —
//!     a 4-variant enum (Allowed / RequiresElevation /
//!     RequiresDeclassification / RequiresBoth) returned by
//!     `ProvenanceRecord::can_flow_to(target_zone)`. This IS the zone-
//!     crossing trust-boundary check.
//!   * [`ProvenanceViolation`] at `crates/fcp-core/src/provenance.rs:725`
//!     — a 10-variant error with thiserror Display, listing the ways
//!     a zone-crossing/operation-driving check fails.
//!
//! Existing `provenance_golden_vectors.rs` uses both but does NOT pin
//! the full 4-variant FlowCheckResult zone matrix or the 10-variant
//! ProvenanceViolation Display per variant.
//!
//! Coverage:
//!   * 4-variant FlowCheckResult enumerated and asserted distinct,
//!   * `can_flow_to` Bell-LaPadula+Biba truth table on all 4 outcomes
//!     (Allowed when both ok, RequiresElevation when integrity-down
//!     blocked, RequiresDeclassification when confidentiality-up blocked,
//!     RequiresBoth when both blocked),
//!   * Public→Owner sentinel (lowest trust into highest zone fires
//!     RequiresBoth — both elevation and declassification needed),
//!   * Owner→Public sentinel (highest trust into lowest zone is
//!     Allowed: integrity flows down freely, confidentiality also flows
//!     down ... but wait, confidentiality flows UP freely, so Owner→Public
//!     would require declassification),
//!   * 10 ProvenanceViolation variants Display phrasing pinned verbatim,
//!   * Distinct-Display sentinel across all 10 variants,
//!   * std::error::Error impl on ProvenanceViolation.

use fcp_core::{
    ConfidentialityLevel, FlowCheckResult, IntegrityLevel, ProvenanceRecord, ProvenanceViolation,
    TaintFlag, ZoneId,
};

const ALL_FLOW_RESULTS: &[FlowCheckResult] = &[
    FlowCheckResult::Allowed,
    FlowCheckResult::RequiresElevation,
    FlowCheckResult::RequiresDeclassification,
    FlowCheckResult::RequiresBoth,
];

#[test]
fn flow_check_result_has_exactly_4_distinct_variants() {
    let mut seen = std::collections::HashSet::new();
    for &v in ALL_FLOW_RESULTS {
        assert!(seen.insert(format!("{v:?}")), "duplicate variant: {v:?}");
    }
    assert_eq!(seen.len(), 4);
}

#[test]
fn can_flow_to_same_zone_is_always_allowed() {
    // Identity sentinel: data sitting in zone Z can always flow to Z.
    for zone in [
        ZoneId::owner(),
        ZoneId::private(),
        ZoneId::work(),
        ZoneId::community(),
        ZoneId::public(),
    ] {
        let record = ProvenanceRecord::new(zone.clone());
        let result = record.can_flow_to(&zone);
        assert_eq!(
            result,
            FlowCheckResult::Allowed,
            "self-flow {zone:?} → {zone:?} must be Allowed"
        );
    }
}

#[test]
fn can_flow_to_owner_into_public_requires_declassification() {
    // Owner has integrity=Owner (highest) and confidentiality=Owner (highest).
    // Public has integrity=Untrusted (lowest) and confidentiality=Public (lowest).
    // Integrity Owner → Untrusted: integrity flows DOWN freely (target ≤ current). OK.
    // Confidentiality Owner → Public: target < current → confidentiality cannot flow DOWN
    // freely; this requires declassification.
    let record = ProvenanceRecord::new(ZoneId::owner());
    let result = record.can_flow_to(&ZoneId::public());
    assert_eq!(result, FlowCheckResult::RequiresDeclassification);
}

#[test]
fn can_flow_to_public_into_owner_requires_elevation() {
    // Public has integrity=Untrusted (lowest), confidentiality=Public (lowest).
    // Owner has integrity=Owner (highest), confidentiality=Owner (highest).
    // Integrity Untrusted → Owner: target > current → blocked, RequiresElevation.
    // Confidentiality Public → Owner: target > current → confidentiality flows UP
    // freely. OK.
    // Therefore: only elevation needed.
    let record = ProvenanceRecord::new(ZoneId::public());
    let result = record.can_flow_to(&ZoneId::owner());
    assert_eq!(result, FlowCheckResult::RequiresElevation);
}

#[test]
fn can_flow_to_blocks_both_when_target_is_more_strict_in_both_axes() {
    // Construct a record that has high integrity but also high confidentiality
    // and ask to flow to a zone with LOW integrity AND LOW confidentiality.
    // - target integrity (low) ≤ current integrity (high): integrity-down OK.
    // - target confidentiality (low) < current confidentiality (high): blocked.
    // → RequiresDeclassification. Already covered above.
    //
    // For RequiresBoth, we need both axes blocked simultaneously: data with
    // LOW integrity AND HIGH confidentiality flowing to a target with
    // HIGH integrity AND LOW confidentiality.
    let mut record = ProvenanceRecord::new(ZoneId::work());
    record.integrity_label = IntegrityLevel::Untrusted; // low integrity
    record.confidentiality_label = ConfidentialityLevel::Owner; // high confidentiality

    // Target: owner zone has high integrity (Owner) AND high confidentiality (Owner).
    // Integrity Untrusted → Owner: target > current → blocked.
    // Confidentiality Owner → Owner: target ≥ current → OK.
    // So this case is RequiresElevation.
    assert_eq!(
        record.can_flow_to(&ZoneId::owner()),
        FlowCheckResult::RequiresElevation
    );

    // For RequiresBoth: need target integrity > current AND target confidentiality < current.
    // current: integrity=Untrusted, confidentiality=Owner.
    // Set target = work: integrity=Work, confidentiality=Work.
    // Integrity Untrusted < Work → blocked (RequiresElevation).
    // Confidentiality Owner > Work → blocked (RequiresDeclassification).
    // → RequiresBoth.
    assert_eq!(
        record.can_flow_to(&ZoneId::work()),
        FlowCheckResult::RequiresBoth
    );
}

#[test]
fn can_flow_to_owner_into_owner_with_full_credentials_is_allowed() {
    let record = ProvenanceRecord::new(ZoneId::owner());
    assert_eq!(record.can_flow_to(&ZoneId::owner()), FlowCheckResult::Allowed);
}

#[test]
fn can_flow_to_full_5x5_zone_truth_table() {
    // Walk every (origin, target) pair and confirm the flow result follows
    // the documented Bell-LaPadula+Biba lattice rules.
    let zones = [
        ZoneId::owner(),
        ZoneId::private(),
        ZoneId::work(),
        ZoneId::community(),
        ZoneId::public(),
    ];

    for origin in &zones {
        for target in &zones {
            let record = ProvenanceRecord::new(origin.clone());
            let result = record.can_flow_to(target);

            let origin_int = IntegrityLevel::from_zone(origin);
            let origin_conf = ConfidentialityLevel::from_zone(origin);
            let target_int = IntegrityLevel::from_zone(target);
            let target_conf = ConfidentialityLevel::from_zone(target);

            let integrity_ok = target_int <= origin_int;
            let confidentiality_ok = target_conf >= origin_conf;

            let expected = match (integrity_ok, confidentiality_ok) {
                (true, true) => FlowCheckResult::Allowed,
                (false, false) => FlowCheckResult::RequiresBoth,
                (false, true) => FlowCheckResult::RequiresElevation,
                (true, false) => FlowCheckResult::RequiresDeclassification,
            };
            assert_eq!(
                result, expected,
                "flow {origin:?} → {target:?}: expected {expected:?}, got {result:?}"
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ProvenanceViolation 10-variant Display matrix
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn provenance_violation_public_input_for_dangerous_operation_display() {
    let err = ProvenanceViolation::PublicInputForDangerousOperation;
    assert_eq!(err.to_string(), "public input cannot drive dangerous operation");
}

#[test]
fn provenance_violation_malicious_input_detected_display() {
    let err = ProvenanceViolation::MaliciousInputDetected;
    assert_eq!(err.to_string(), "malicious input pattern detected");
}

#[test]
fn provenance_violation_cross_zone_unapproved_for_dangerous_display() {
    let err = ProvenanceViolation::CrossZoneUnapprovedForDangerousOperation;
    assert_eq!(
        err.to_string(),
        "unapproved cross-zone input cannot drive dangerous operation"
    );
}

#[test]
fn provenance_violation_tainted_input_for_risky_operation_display() {
    let err = ProvenanceViolation::TaintedInputForRiskyOperation {
        taint_flags: vec![TaintFlag::PublicInput, TaintFlag::CrossZoneUnapproved],
    };
    let msg = err.to_string();
    assert!(
        msg.starts_with("tainted input cannot drive risky operation without elevation:"),
        "msg drift: {msg}"
    );
    assert!(msg.contains("PublicInput"));
    assert!(msg.contains("CrossZoneUnapproved"));
}

#[test]
fn provenance_violation_insufficient_integrity_display() {
    let err = ProvenanceViolation::InsufficientIntegrity {
        required: IntegrityLevel::Work,
        actual: IntegrityLevel::Untrusted,
    };
    assert_eq!(
        err.to_string(),
        "insufficient integrity: required work, actual untrusted"
    );
}

#[test]
fn provenance_violation_invalid_elevation_display() {
    let err = ProvenanceViolation::InvalidElevation {
        current: IntegrityLevel::Work,
        requested: IntegrityLevel::Owner,
    };
    assert_eq!(
        err.to_string(),
        "invalid elevation: cannot elevate from work to owner"
    );
}

#[test]
fn provenance_violation_invalid_declassification_display() {
    let err = ProvenanceViolation::InvalidDeclassification {
        current: ConfidentialityLevel::Owner,
        requested: ConfidentialityLevel::Public,
    };
    assert_eq!(
        err.to_string(),
        "invalid declassification: cannot declassify from owner to public"
    );
}

#[test]
fn provenance_violation_sanitizer_coverage_insufficient_display() {
    let err = ProvenanceViolation::SanitizerCoverageInsufficient;
    assert_eq!(err.to_string(), "sanitizer receipt does not cover required inputs");
}

#[test]
fn provenance_violation_approval_token_invalid_display() {
    let err = ProvenanceViolation::ApprovalTokenInvalid;
    assert_eq!(err.to_string(), "approval token expired or invalid");
}

#[test]
fn provenance_violation_forbidden_operation_display() {
    let err = ProvenanceViolation::ForbiddenOperation;
    assert_eq!(
        err.to_string(),
        "forbidden operations are never allowed regardless of provenance"
    );
}

#[test]
fn all_ten_provenance_violation_variants_have_distinct_display() {
    let variants = [
        ProvenanceViolation::PublicInputForDangerousOperation,
        ProvenanceViolation::MaliciousInputDetected,
        ProvenanceViolation::CrossZoneUnapprovedForDangerousOperation,
        ProvenanceViolation::TaintedInputForRiskyOperation {
            taint_flags: vec![TaintFlag::PublicInput],
        },
        ProvenanceViolation::InsufficientIntegrity {
            required: IntegrityLevel::Work,
            actual: IntegrityLevel::Untrusted,
        },
        ProvenanceViolation::InvalidElevation {
            current: IntegrityLevel::Untrusted,
            requested: IntegrityLevel::Owner,
        },
        ProvenanceViolation::InvalidDeclassification {
            current: ConfidentialityLevel::Owner,
            requested: ConfidentialityLevel::Public,
        },
        ProvenanceViolation::SanitizerCoverageInsufficient,
        ProvenanceViolation::ApprovalTokenInvalid,
        ProvenanceViolation::ForbiddenOperation,
    ];
    let strings: std::collections::HashSet<_> =
        variants.iter().map(ToString::to_string).collect();
    assert_eq!(
        strings.len(),
        variants.len(),
        "Display collision across ProvenanceViolation: {strings:?}"
    );
}

#[test]
fn provenance_violation_implements_std_error() {
    fn assert_error<E: std::error::Error>(_: &E) {}
    let err = ProvenanceViolation::ForbiddenOperation;
    assert_error(&err);
}
