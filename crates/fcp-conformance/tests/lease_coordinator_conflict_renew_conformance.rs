//! `LeaseCoordinator` `detect_conflicts` + `should_renew` conformance.
//!
//! Two LeaseCoordinator helpers that complement br-9nee8 (acquire /
//! renew / release):
//!
//! 1. **`detect_conflicts`** surfaces overlapping active leases for
//!    split-brain triage. Returns `None` when ≤1 active leases for a
//!    subject/purpose, `Some(LeaseConflict)` with all holders listed
//!    when 2+ are active. Severity is `Critical` when
//!    `escalate_dangerous_conflicts` is enabled (default), else
//!    `Warning`. The resolution string names the highest-fencing-token
//!    winner so triagers can route the resolution.
//! 2. **`should_renew`** tells the holder when to refresh: returns
//!    `false` for expired leases, `true` when remaining-TTL falls
//!    at or below `renew_threshold_bps` (basis points × 10⁻⁴ of the
//!    reference TTL), and `false` when ample time remains.

use fcp_prelude::{ObjectId, TailscaleNodeId, ZoneId};
use fcp_mesh::{
    ConflictSeverity, HeldLease, LeaseCoordinator, LeaseCoordinatorConfig, LeasePurpose,
    ObservedLeaseAuthority,
};

fn obj() -> ObjectId {
    ObjectId::from_unscoped_bytes(b"subject")
}

fn purpose() -> LeasePurpose {
    LeasePurpose::OperationExecution
}

fn observation(holder: &str, fencing_token: u64, expires_at: u64) -> ObservedLeaseAuthority {
    ObservedLeaseAuthority::new(
        TailscaleNodeId::new(holder),
        HeldLease {
            subject_id: obj(),
            purpose: purpose(),
            expires_at,
            fencing_token,
        },
    )
}

#[test]
fn detect_conflicts_returns_none_for_zero_active_leases() {
    let coord = LeaseCoordinator::with_defaults();
    let conflict = coord.detect_conflicts(&ZoneId::work(), &obj(), &purpose(), &[], 1_000);
    assert!(
        conflict.is_none(),
        "detect_conflicts on empty observations MUST return None"
    );
}

#[test]
fn detect_conflicts_returns_none_for_single_active_lease() {
    let coord = LeaseCoordinator::with_defaults();
    let observed = vec![observation("alice", 1, 2_000)];
    let conflict = coord.detect_conflicts(&ZoneId::work(), &obj(), &purpose(), &observed, 1_000);
    assert!(conflict.is_none(), "single active lease is not a conflict");
}

#[test]
fn detect_conflicts_returns_some_with_all_holders_for_two_active_leases() {
    let coord = LeaseCoordinator::with_defaults();
    let observed = vec![observation("alice", 5, 2_000), observation("bob", 7, 2_000)];

    let conflict = coord
        .detect_conflicts(&ZoneId::work(), &obj(), &purpose(), &observed, 1_000)
        .expect("two active leases MUST surface a LeaseConflict");

    assert_eq!(
        conflict.holders.len(),
        2,
        "all holders MUST appear in the conflict report so triage can decide"
    );
    let holder_ids: Vec<&str> = conflict
        .holders
        .iter()
        .map(|h| h.node_id.as_str())
        .collect();
    assert!(holder_ids.contains(&"node-alice") || holder_ids.contains(&"alice"));
    assert!(holder_ids.contains(&"node-bob") || holder_ids.contains(&"bob"));
}

#[test]
fn detect_conflicts_resolution_names_highest_fencing_token_holder() {
    let coord = LeaseCoordinator::with_defaults();
    let observed = vec![
        observation("alice", 5, 2_000),
        observation("bob", 99, 2_000), // higher token -> winner
        observation("charlie", 50, 2_000),
    ];

    let conflict = coord
        .detect_conflicts(&ZoneId::work(), &obj(), &purpose(), &observed, 1_000)
        .expect("conflict reported");
    assert!(
        conflict.resolution.contains("bob"),
        "resolution MUST name the highest-token holder so triage knows where the lease should land; got {:?}",
        conflict.resolution
    );
    assert!(
        conflict.resolution.contains("99"),
        "resolution MUST surface the winning fencing token; got {:?}",
        conflict.resolution
    );
}

#[test]
fn detect_conflicts_excludes_expired_leases() {
    let coord = LeaseCoordinator::with_defaults();
    // Alice's lease expired at 4_000; Bob is the only ACTIVE one at now=5_000.
    let observed = vec![
        observation("alice", 99, 4_000),
        observation("bob", 7, 6_000),
    ];

    let conflict = coord.detect_conflicts(&ZoneId::work(), &obj(), &purpose(), &observed, 5_000);
    assert!(
        conflict.is_none(),
        "expired leases MUST NOT count toward conflict detection — only one ACTIVE lease here"
    );
}

#[test]
fn detect_conflicts_severity_critical_with_escalation_enabled() {
    let coord = LeaseCoordinator::new(LeaseCoordinatorConfig {
        escalate_dangerous_conflicts: true,
        ..LeaseCoordinatorConfig::default()
    });
    let observed = vec![observation("alice", 5, 2_000), observation("bob", 7, 2_000)];

    let conflict = coord
        .detect_conflicts(&ZoneId::work(), &obj(), &purpose(), &observed, 1_000)
        .expect("conflict");
    assert_eq!(
        conflict.severity,
        ConflictSeverity::Critical,
        "escalate_dangerous_conflicts=true MUST yield Critical severity"
    );
}

#[test]
fn detect_conflicts_severity_warning_with_escalation_disabled() {
    let coord = LeaseCoordinator::new(LeaseCoordinatorConfig {
        escalate_dangerous_conflicts: false,
        ..LeaseCoordinatorConfig::default()
    });
    let observed = vec![observation("alice", 5, 2_000), observation("bob", 7, 2_000)];

    let conflict = coord
        .detect_conflicts(&ZoneId::work(), &obj(), &purpose(), &observed, 1_000)
        .expect("conflict");
    assert_eq!(
        conflict.severity,
        ConflictSeverity::Warning,
        "escalate_dangerous_conflicts=false MUST yield Warning severity"
    );
}

#[test]
fn should_renew_returns_false_for_expired_lease() {
    let coord = LeaseCoordinator::with_defaults();
    let lease = HeldLease {
        subject_id: obj(),
        purpose: purpose(),
        expires_at: 100,
        fencing_token: 1,
    };
    assert!(
        !coord.should_renew(&lease, 200),
        "expired lease MUST NOT trigger renew (it can't be renewed anyway)"
    );
}

#[test]
fn should_renew_returns_true_when_remaining_below_threshold() {
    // Default config: default_ttl_secs=300, renew_threshold_bps=2000
    // (renew at 20% remaining). At now=900 with expires_at=950:
    // remaining=50, reference=300, remaining_bps = 50/300 * 10_000 ≈
    // 1666 <= 2000 -> renew.
    let coord = LeaseCoordinator::with_defaults();
    let lease = HeldLease {
        subject_id: obj(),
        purpose: purpose(),
        expires_at: 950,
        fencing_token: 1,
    };
    assert!(
        coord.should_renew(&lease, 900),
        "remaining (50s) below 20% threshold of 300s default TTL MUST trigger renew"
    );
}

#[test]
fn should_renew_returns_false_when_ample_time_remains() {
    // expires_at=1500, now=900: remaining=600, reference=300,
    // remaining_bps = 600/300 * 10_000 = 20_000 > 2_000 -> no renew
    // (the lease has more time left than the entire reference TTL).
    let coord = LeaseCoordinator::with_defaults();
    let lease = HeldLease {
        subject_id: obj(),
        purpose: purpose(),
        expires_at: 1_500,
        fencing_token: 1,
    };
    assert!(
        !coord.should_renew(&lease, 900),
        "ample remaining time (600s vs 300s reference TTL) MUST NOT trigger renew"
    );
}

#[test]
fn should_renew_with_zero_reference_ttl_always_returns_true_for_active_lease() {
    // Edge case: a default_ttl_secs of 0 produces reference_ttl=0,
    // which the implementation treats as "always renew" (otherwise
    // we'd divide by zero).
    let coord = LeaseCoordinator::new(LeaseCoordinatorConfig {
        default_ttl_secs: 0,
        ..LeaseCoordinatorConfig::default()
    });
    let lease = HeldLease {
        subject_id: obj(),
        purpose: purpose(),
        expires_at: 1_000_000,
        fencing_token: 1,
    };
    assert!(
        coord.should_renew(&lease, 100),
        "zero reference_ttl MUST short-circuit to renew=true (avoids div-by-zero, treats config as 'always renew')"
    );
}

#[test]
fn should_renew_does_not_panic_on_far_future_expires_at() {
    // Documented panic-safety guard: an adversarial peer reporting
    // expires_at = u64::MAX must NOT panic in the remaining * 10_000
    // arithmetic. The implementation uses u128 intermediates.
    let coord = LeaseCoordinator::with_defaults();
    let lease = HeldLease {
        subject_id: obj(),
        purpose: purpose(),
        expires_at: u64::MAX,
        fencing_token: 1,
    };
    // The result is a function call that must complete without
    // panicking; we don't assert on a specific bool value.
    let _ = coord.should_renew(&lease, 100);
}

#[test]
fn should_renew_returns_false_at_exact_expiry_boundary() {
    // expires_at == now: lease.is_active(now) returns false (the
    // lease is no longer ACTIVE strictly past its expiry). So
    // should_renew returns false on the exact boundary too.
    let coord = LeaseCoordinator::with_defaults();
    let lease = HeldLease {
        subject_id: obj(),
        purpose: purpose(),
        expires_at: 1_000,
        fencing_token: 1,
    };
    assert!(
        !coord.should_renew(&lease, 1_000),
        "lease at exact expiry boundary is not active -> should_renew false"
    );
}
