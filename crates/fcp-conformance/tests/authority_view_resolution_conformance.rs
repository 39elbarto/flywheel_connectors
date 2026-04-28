//! `AuthorityView::from_observed` deterministic resolution conformance.
//!
//! `fcp_mesh::AuthorityView::from_observed` is the routing-decision
//! resolver: given a set of observed leases for one subject/purpose,
//! it computes a deterministic snapshot of who holds authority. The
//! tiebreaker ordering (`compare_observed_leases`) is:
//!
//! 1. Higher `fencing_token` wins.
//! 2. Tie on token → later `expires_at` wins.
//! 3. Tie on (token, expires_at) → lexicographically smaller `holder`
//!    wins.
//!
//! These tests pin that ordering, the ACTIVE-vs-EXPIRED filter, and
//! the per-record status tagging (Active / Superseded / Expired) so a
//! regression in any branch fails conformance immediately.

use fcp_core::{ObjectId, TailscaleNodeId, ZoneId};
use fcp_mesh::{AuthorityStatus, AuthorityView, HeldLease, LeasePurpose, ObservedLeaseAuthority};

fn obj() -> ObjectId {
    ObjectId::from_unscoped_bytes(b"subject-under-authority")
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

fn build_view(
    eligible: &[TailscaleNodeId],
    observed: &[ObservedLeaseAuthority],
    now_secs: u64,
) -> AuthorityView {
    AuthorityView::from_observed(
        &ZoneId::work(),
        &obj(),
        purpose(),
        eligible,
        observed,
        now_secs,
        now_secs * 1000,
    )
}

#[test]
fn empty_observations_yield_no_active_holder() {
    let eligible = vec![TailscaleNodeId::new("node-a")];
    let view = build_view(&eligible, &[], 1_000);
    assert!(
        view.active_holder.is_none(),
        "no observations -> no active holder; got {:?}",
        view.active_holder
    );
    assert!(view.active_fencing_token.is_none());
    assert!(
        view.records.is_empty(),
        "no observations -> no records; got {} records",
        view.records.len()
    );
}

#[test]
fn higher_fencing_token_wins_among_active_leases() {
    // Two active leases — alice with token=3, bob with token=7.
    // Bob must win.
    let eligible = vec![
        TailscaleNodeId::new("node-a"),
        TailscaleNodeId::new("node-b"),
    ];
    let observed = vec![
        observation("node-a", 3, 2_000),
        observation("node-b", 7, 2_000),
    ];
    let view = build_view(&eligible, &observed, 1_000);

    assert_eq!(
        view.active_holder.as_ref().map(|n| n.as_str()),
        Some("node-b"),
        "higher fencing_token MUST win among active leases"
    );
    assert_eq!(view.active_fencing_token, Some(7));
}

#[test]
fn tied_fencing_tokens_broken_by_later_expires_at() {
    // Same token (7), different expires_at — later expiry wins
    // because the tiebreaker prefers the more-recently-renewed
    // lease.
    let eligible = vec![
        TailscaleNodeId::new("node-a"),
        TailscaleNodeId::new("node-b"),
    ];
    let observed = vec![
        observation("node-a", 7, 1_500),
        observation("node-b", 7, 3_000),
    ];
    let view = build_view(&eligible, &observed, 1_000);

    assert_eq!(
        view.active_holder.as_ref().map(|n| n.as_str()),
        Some("node-b"),
        "tied fencing_token MUST be broken by later expires_at"
    );
}

#[test]
fn tied_token_and_expiry_broken_lexicographically_by_holder() {
    // Same (token, expires_at) — the lex-smaller holder wins. This
    // is the deterministic final tiebreaker that prevents
    // observation-order-dependent split-brain.
    let eligible = vec![
        TailscaleNodeId::new("node-a"),
        TailscaleNodeId::new("node-b"),
    ];
    let observed = vec![
        observation("node-b", 7, 2_000),
        observation("node-a", 7, 2_000),
    ];
    let view = build_view(&eligible, &observed, 1_000);

    assert_eq!(
        view.active_holder.as_ref().map(|n| n.as_str()),
        Some("node-a"),
        "tied (token, expires_at) MUST be broken by lex-smaller holder; \
         observation order MUST NOT determine the winner"
    );
}

#[test]
fn expired_lease_with_higher_token_does_not_take_authority() {
    // Alice has token=99 but her lease is EXPIRED at now=5_000.
    // Bob has token=2 but his lease is ACTIVE.
    // Bob must be the active holder; the expired alice must NOT
    // win even though her token is higher — the active filter is
    // applied BEFORE the token comparison.
    let eligible = vec![
        TailscaleNodeId::new("node-a"),
        TailscaleNodeId::new("node-b"),
    ];
    let observed = vec![
        observation("node-a", 99, 4_000), // expired (past now=5_000)
        observation("node-b", 2, 6_000),  // active
    ];
    let view = build_view(&eligible, &observed, 5_000);

    assert_eq!(
        view.active_holder.as_ref().map(|n| n.as_str()),
        Some("node-b"),
        "active filter must precede token comparison; expired-but-higher-token \
         must NOT take authority"
    );
    assert_eq!(view.active_fencing_token, Some(2));
}

#[test]
fn all_expired_leases_yield_no_active_holder() {
    let eligible = vec![
        TailscaleNodeId::new("node-a"),
        TailscaleNodeId::new("node-b"),
    ];
    let observed = vec![
        observation("node-a", 5, 2_000),
        observation("node-b", 7, 3_000),
    ];
    // Now is past both expirations.
    let view = build_view(&eligible, &observed, 10_000);

    assert!(
        view.active_holder.is_none(),
        "all-expired observations -> no active holder; got {:?}",
        view.active_holder
    );
    assert!(view.active_fencing_token.is_none());
}

#[test]
fn winner_record_status_is_active_loser_is_superseded() {
    // The winning record must carry AuthorityStatus::Active; the
    // losing-but-still-not-expired records carry Superseded.
    let eligible = vec![
        TailscaleNodeId::new("node-a"),
        TailscaleNodeId::new("node-b"),
    ];
    let observed = vec![
        observation("node-a", 3, 2_000), // loser
        observation("node-b", 7, 2_000), // winner
    ];
    let view = build_view(&eligible, &observed, 1_000);

    let winner = view
        .records
        .iter()
        .find(|r| r.holder.as_str() == "node-b")
        .expect("winner record present");
    assert_eq!(
        winner.status,
        AuthorityStatus::Active,
        "winning record must be tagged Active"
    );

    let loser = view
        .records
        .iter()
        .find(|r| r.holder.as_str() == "node-a")
        .expect("loser record present");
    assert_eq!(
        loser.status,
        AuthorityStatus::Superseded,
        "non-winning active record must be tagged Superseded"
    );
}

#[test]
fn expired_record_is_tagged_expired_regardless_of_token_rank() {
    // Even a high-token lease that has expired must appear with
    // status=Expired in the record list — preserving auditability
    // of the timeline.
    let eligible = vec![
        TailscaleNodeId::new("node-a"),
        TailscaleNodeId::new("node-b"),
    ];
    let observed = vec![
        observation("node-a", 99, 4_000), // expired (token rank irrelevant)
        observation("node-b", 2, 6_000),  // active winner
    ];
    let view = build_view(&eligible, &observed, 5_000);

    let expired = view
        .records
        .iter()
        .find(|r| r.holder.as_str() == "node-a")
        .expect("expired record present in audit trail");
    assert_eq!(
        expired.status,
        AuthorityStatus::Expired,
        "expired record must be tagged Expired regardless of token rank"
    );
}

#[test]
fn from_observed_is_deterministic_under_observation_reordering() {
    // The tiebreakers must produce the SAME view regardless of the
    // input order. This is what prevents two peers that observed the
    // same set of leases (but received them in different orders)
    // from arriving at different authority decisions.
    let eligible = vec![
        TailscaleNodeId::new("node-a"),
        TailscaleNodeId::new("node-b"),
        TailscaleNodeId::new("node-c"),
    ];
    let order_1 = vec![
        observation("node-a", 5, 2_000),
        observation("node-b", 7, 2_000),
        observation("node-c", 7, 2_000),
    ];
    let mut order_2 = order_1.clone();
    order_2.reverse();

    let v1 = build_view(&eligible, &order_1, 1_000);
    let v2 = build_view(&eligible, &order_2, 1_000);

    assert_eq!(
        v1.active_holder, v2.active_holder,
        "active_holder MUST be invariant under observation reordering"
    );
    assert_eq!(v1.active_fencing_token, v2.active_fencing_token);
    assert_eq!(
        v1.failover_order, v2.failover_order,
        "failover_order is HRW over eligible_nodes — independent of observation order"
    );
}

#[test]
fn failover_order_covers_all_eligible_nodes() {
    let eligible = vec![
        TailscaleNodeId::new("node-a"),
        TailscaleNodeId::new("node-b"),
        TailscaleNodeId::new("node-c"),
    ];
    let view = build_view(&eligible, &[], 1_000);
    assert_eq!(
        view.failover_order.len(),
        eligible.len(),
        "failover_order MUST rank every eligible node so a routing layer can fall back through them in order"
    );
    let mut sorted = view
        .failover_order
        .iter()
        .map(|n| n.as_str().to_string())
        .collect::<Vec<_>>();
    sorted.sort();
    assert_eq!(
        sorted,
        vec!["node-a", "node-b", "node-c"],
        "failover_order must cover the same set of eligible nodes (no extras, no drops)"
    );
}
