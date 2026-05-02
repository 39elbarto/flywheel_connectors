//! `LeaseCoordinator` acquire/renew/release causality conformance.
//!
//! `fcp_mesh::coordinator::LeaseCoordinator` is the per-subject lease
//! authority across mesh nodes — the routing-decision causality
//! engine that decides which node may execute singleton-writer
//! operations on a given object. Zero conformance coverage today.
//!
//! Critical causality invariants pinned (NORMATIVE):
//!
//! 1. **Empty state -> Granted.** A lease acquire on a subject with
//!    no observed active leases grants immediately, with a fresh
//!    fencing token and an `expires_at` derived from the requested
//!    TTL.
//! 2. **Active-lease causality.** When X holds an active lease,
//!    a subsequent acquire by Y returns `Denied` with `current_holder
//!    = X` — the routing-layer signal callers depend on to re-route.
//! 3. **Expiration causality.** Once `now_secs >= expires_at`, a new
//!    acquire on the same subject succeeds because the prior lease is
//!    no longer active.
//! 4. **Fencing-token monotonicity.** Each new acquire by ANY peer
//!    receives a token strictly greater than the previously observed
//!    maximum. This is the property that makes split-brain
//!    deterministically resolvable.
//! 5. **Renew by holder extends expiry**; renew of an expired lease
//!    is denied with `reason` mentioning that no active lease matches.
//! 6. **Release by holder succeeds**; release by non-holder returns
//!    `NotHeld`.

use fcp_prelude::{ObjectId, TailscaleNodeId, ZoneId};
use fcp_mesh::{
    AcquireOutcome, HeldLease, LeaseCoordinator, LeasePurpose, ObservedLeaseAuthority,
    ReleaseOutcome, RenewOutcome,
};

fn coordinator() -> LeaseCoordinator {
    LeaseCoordinator::with_defaults()
}

fn alice() -> TailscaleNodeId {
    TailscaleNodeId::new("node-alice")
}

fn bob() -> TailscaleNodeId {
    TailscaleNodeId::new("node-bob")
}

fn obj() -> ObjectId {
    ObjectId::from_unscoped_bytes(b"subject-under-lease")
}

fn purpose() -> LeasePurpose {
    LeasePurpose::OperationExecution
}

fn observation(
    holder: &TailscaleNodeId,
    fencing_token: u64,
    expires_at: u64,
) -> ObservedLeaseAuthority {
    ObservedLeaseAuthority::new(
        holder.clone(),
        HeldLease {
            subject_id: obj(),
            purpose: purpose(),
            expires_at,
            fencing_token,
        },
    )
}

#[test]
fn acquire_on_empty_state_grants_lease_with_fresh_token() {
    let mut coord = coordinator();
    let now = 1_000_u64;
    let eligible = vec![alice(), bob()];

    let (outcome, _timeline) = coord.acquire(
        &alice(),
        &ZoneId::work(),
        &obj(),
        &purpose(),
        &[],
        &eligible,
        now,
        Some(60),
    );

    match outcome {
        AcquireOutcome::Granted {
            fencing_token,
            expires_at,
        } => {
            assert!(
                fencing_token > 0,
                "fresh fencing_token must be positive (token=0 is reserved)"
            );
            assert_eq!(expires_at, now + 60, "expires_at must be now_secs + ttl");
        }
        other => panic!("expected Granted on empty state, got {other:?}"),
    }
}

#[test]
fn acquire_when_other_holds_active_lease_returns_denied_with_holder_named() {
    let mut coord = coordinator();
    let now = 1_000_u64;
    let eligible = vec![alice(), bob()];
    // Alice holds an active lease (expires in the future).
    let observed = vec![observation(&alice(), 7, now + 60)];

    let (outcome, _) = coord.acquire(
        &bob(),
        &ZoneId::work(),
        &obj(),
        &purpose(),
        &observed,
        &eligible,
        now,
        Some(60),
    );

    match outcome {
        AcquireOutcome::Denied {
            current_holder,
            current_fencing_token,
            expires_at,
            reason: _,
        } => {
            assert_eq!(
                current_holder.as_str(),
                "node-alice",
                "Denied.current_holder MUST name Alice so Bob's caller can re-route"
            );
            assert_eq!(current_fencing_token, 7);
            assert_eq!(expires_at, now + 60);
        }
        other => panic!("expected Denied, got {other:?}"),
    }
}

#[test]
fn expired_lease_yields_grant_to_new_acquirer() {
    let mut coord = coordinator();
    let now = 5_000_u64;
    let eligible = vec![alice(), bob()];
    // Alice's lease expired at t=4_000; "now" is t=5_000.
    let observed = vec![observation(&alice(), 3, 4_000)];

    let (outcome, _) = coord.acquire(
        &bob(),
        &ZoneId::work(),
        &obj(),
        &purpose(),
        &observed,
        &eligible,
        now,
        Some(60),
    );

    match outcome {
        AcquireOutcome::Granted {
            fencing_token,
            expires_at,
        } => {
            assert!(
                fencing_token > 3,
                "post-expiry acquire MUST receive a token greater than the prior holder's \
                 (fencing-token monotonicity). got token={fencing_token}, prior=3"
            );
            assert_eq!(expires_at, now + 60);
        }
        other => panic!(
            "expected Granted after prior lease expired (now={now} > expires_at=4000); \
             got {other:?}"
        ),
    }
}

#[test]
fn fencing_tokens_are_strictly_monotonic_across_consecutive_acquires() {
    // Even when each acquire is on an empty subject (after prior
    // release), the fencing token must continue increasing — that's
    // what makes split-brain deterministically resolvable.
    let mut coord = coordinator();
    let now = 1_000_u64;
    let eligible = vec![alice(), bob()];
    let mut prior_token = 0_u64;

    for _ in 0..5 {
        let (outcome, _) = coord.acquire(
            &alice(),
            &ZoneId::work(),
            &obj(),
            &purpose(),
            &[],
            &eligible,
            now,
            Some(60),
        );
        match outcome {
            AcquireOutcome::Granted { fencing_token, .. } => {
                assert!(
                    fencing_token > prior_token,
                    "fencing_token must strictly increase: got {fencing_token}, prior={prior_token}"
                );
                prior_token = fencing_token;
            }
            other => panic!("expected Granted, got {other:?}"),
        }
    }
}

#[test]
fn renew_by_current_holder_extends_expiry() {
    let coord = coordinator();
    let now = 1_000_u64;
    let observed = vec![observation(&alice(), 7, now + 30)];

    let (outcome, _) = coord.renew(&alice(), &obj(), &purpose(), 7, &observed, now, Some(120));

    match outcome {
        RenewOutcome::Renewed { expires_at } => {
            assert!(
                expires_at >= now + 120,
                "renew with ttl=120 must produce expires_at >= now+120; got {expires_at}, now={now}"
            );
        }
        other => panic!("expected Renewed, got {other:?}"),
    }
}

#[test]
fn renew_after_expiry_is_denied_with_no_active_lease() {
    let coord = coordinator();
    let now = 5_000_u64;
    // Alice's lease expired at t=4_000; "now" is t=5_000 — there is
    // no longer an ACTIVE matching lease, so renew must deny.
    let observed = vec![observation(&alice(), 7, 4_000)];

    let (outcome, _) = coord.renew(&alice(), &obj(), &purpose(), 7, &observed, now, Some(60));

    match outcome {
        RenewOutcome::Denied { reason } => {
            assert!(
                reason.contains("no active lease"),
                "denied reason must surface 'no active lease' for triage; got {reason:?}"
            );
        }
        other => panic!("expected Denied (lease expired), got {other:?}"),
    }
}

#[test]
fn renew_with_wrong_fencing_token_is_denied() {
    let coord = coordinator();
    let now = 1_000_u64;
    // Alice holds token=7; she tries to renew claiming token=99.
    let observed = vec![observation(&alice(), 7, now + 60)];

    let (outcome, _) = coord.renew(&alice(), &obj(), &purpose(), 99, &observed, now, Some(60));

    assert!(
        matches!(outcome, RenewOutcome::Denied { .. }),
        "renew with non-matching fencing token MUST be denied; got {outcome:?}"
    );
}

#[test]
fn release_by_current_holder_succeeds() {
    let coord = coordinator();
    let now = 1_000_u64;
    let observed = vec![observation(&alice(), 7, now + 60)];

    let (outcome, _) = coord.release(&alice(), &obj(), &purpose(), 7, &observed, now);

    assert!(
        matches!(outcome, ReleaseOutcome::Released),
        "release by current holder must succeed; got {outcome:?}"
    );
}

#[test]
fn release_by_non_holder_returns_not_held() {
    let coord = coordinator();
    let now = 1_000_u64;
    // Alice holds the lease; Bob tries to release.
    let observed = vec![observation(&alice(), 7, now + 60)];

    let (outcome, _) = coord.release(&bob(), &obj(), &purpose(), 7, &observed, now);

    match outcome {
        ReleaseOutcome::NotHeld { reason: _ } => {
            // Reason text is informative; we only require the variant.
        }
        other => panic!("expected NotHeld for non-holder release, got {other:?}"),
    }
}

#[test]
fn release_with_wrong_token_returns_not_held() {
    let coord = coordinator();
    let now = 1_000_u64;
    let observed = vec![observation(&alice(), 7, now + 60)];

    // Alice tries to release with the WRONG token.
    let (outcome, _) = coord.release(&alice(), &obj(), &purpose(), 99, &observed, now);

    assert!(
        matches!(outcome, ReleaseOutcome::NotHeld { .. }),
        "release with wrong fencing_token MUST return NotHeld; got {outcome:?}"
    );
}
