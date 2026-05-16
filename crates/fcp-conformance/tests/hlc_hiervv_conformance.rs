//! Conformance coverage for HLC audit ordering and `HierVV` freshness frontiers.

use fcp_audit::{HybridLogicalClock, HybridLogicalTimestamp};
use fcp_mesh::{
    HierarchicalVersionVector, RevocationFreshnessAction, RevocationFreshnessFrontier,
    VersionVectorOrder,
};

#[test]
fn audit_cross_zone_order_survives_one_second_clock_skew() {
    let mut zone_a = HybridLogicalClock::new("zone-a-node");
    let mut zone_b = HybridLogicalClock::new("zone-b-node");
    let mut zone_c = HybridLogicalClock::new("zone-c-node");

    let a0 = zone_a.tick(10_000);
    let b0 = zone_b.merge(&a0, 9_000);
    let c0 = zone_c.merge(&b0, 9_500);
    let a1 = zone_a.merge(&c0, 9_100);

    assert!(b0 > a0.with_node_id("zone-b-node"));
    assert!(c0 > b0.with_node_id("zone-c-node"));
    assert!(a1 > c0.with_node_id("zone-a-node"));
}

#[test]
fn revocation_freshness_uses_hiervv_dominance_not_wall_clock_order() {
    let mut source = HierarchicalVersionVector::new();
    source.set("z:work", 10);

    let mut ahead_clock_receiver = HierarchicalVersionVector::new();
    ahead_clock_receiver.set("z:work:team-a", 7);
    ahead_clock_receiver.set("z:work:team-b", 9);

    assert_eq!(
        source.compare(&ahead_clock_receiver),
        VersionVectorOrder::Dominates,
        "freshness must be based on vector dominance, not receiver wall-clock skew"
    );
    assert!(source.dominates(&ahead_clock_receiver));
}

#[test]
fn revocation_frontier_accepts_dominating_push_instead_of_clock_stale_order() {
    let mut receiver = RevocationFreshnessFrontier::new();
    receiver.observe("z:work:team-a", 7);
    receiver.observe("z:work:team-b", 9);

    let decision = receiver.observe("z:work", 10);

    assert_eq!(decision.order, VersionVectorOrder::Dominates);
    assert_eq!(decision.action, RevocationFreshnessAction::Accept);
    assert_eq!(receiver.counter_for("z:work:team-a"), 10);
    assert_eq!(receiver.counter_for("z:work:team-b"), 10);
}

#[test]
fn hlc_timestamp_order_tie_breaks_by_logical_counter() {
    let older = HybridLogicalTimestamp::new(42, 1, "node-a");
    let newer = HybridLogicalTimestamp::new(42, 2, "node-a");

    assert!(newer > older);
}
