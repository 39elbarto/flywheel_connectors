use fcp_mesh::{
    HierarchicalVersionVector, RevocationFreshnessAction, RevocationFreshnessFrontier,
    VersionVectorOrder,
};

#[test]
fn hier_vv_dominates_child_scopes_from_parent_counter() {
    let mut parent = HierarchicalVersionVector::new();
    parent.set("z:work", 7);

    let mut child = HierarchicalVersionVector::new();
    child.set("z:work:team-a", 3);
    child.set("z:work:team-b", 7);

    assert_eq!(parent.counter_for("z:work:team-a"), 7);
    assert_eq!(parent.compare(&child), VersionVectorOrder::Dominates);
    assert!(parent.dominates(&child));
}

#[test]
fn hier_vv_detects_concurrent_independent_zone_frontiers() {
    let mut left = HierarchicalVersionVector::new();
    left.set("z:work:team-a", 4);
    left.set("z:work:team-b", 1);

    let mut right = HierarchicalVersionVector::new();
    right.set("z:work:team-a", 2);
    right.set("z:work:team-b", 5);

    assert_eq!(left.compare(&right), VersionVectorOrder::Concurrent);
    assert!(!left.dominates(&right));
    assert!(!right.dominates(&left));
}

#[test]
fn hier_vv_merge_keeps_freshest_counter_per_scope() {
    let mut left = HierarchicalVersionVector::new();
    left.set("z:work:team-a", 4);
    left.set("z:work:team-b", 1);

    let mut right = HierarchicalVersionVector::new();
    right.set("z:work:team-a", 2);
    right.set("z:work:team-b", 5);

    left.merge(&right);

    assert_eq!(left.counter_for("z:work:team-a"), 4);
    assert_eq!(left.counter_for("z:work:team-b"), 5);
    assert!(left.dominates(&right));
}

#[test]
fn hier_vv_compresses_uniform_large_zone_subtree() {
    let mut vector = HierarchicalVersionVector::new();
    vector.set("z:tenant:prod", 42);

    for index in 0..1024 {
        assert_eq!(
            vector.counter_for(&format!("z:tenant:prod:zone-{index:04}")),
            42
        );
    }

    assert_eq!(vector.len(), 1);
    assert!(
        vector.canonical_len().expect("canonical encode") <= 2_048,
        "uniform 1024-zone subtree should remain compact"
    );
}

#[test]
fn revocation_frontier_accepts_parent_update_over_child_scopes() {
    let mut frontier = RevocationFreshnessFrontier::new();
    frontier.observe("z:work:team-a", 7);
    frontier.observe("z:work:team-b", 9);

    let decision = frontier.observe("z:work", 10);

    assert_eq!(decision.action, RevocationFreshnessAction::Accept);
    assert_eq!(decision.order, VersionVectorOrder::Dominates);
    assert_eq!(frontier.counter_for("z:work:team-a"), 10);
    assert_eq!(frontier.counter_for("z:work:team-b"), 10);
}

#[test]
fn revocation_frontier_rejects_dominated_update_without_downgrade() {
    let mut frontier = RevocationFreshnessFrontier::new();
    frontier.observe("z:work", 10);

    let decision = frontier.observe("z:work:team-a", 9);

    assert_eq!(decision.action, RevocationFreshnessAction::RejectStale);
    assert_eq!(decision.order, VersionVectorOrder::DominatedBy);
    assert_eq!(frontier.counter_for("z:work:team-a"), 10);
}
