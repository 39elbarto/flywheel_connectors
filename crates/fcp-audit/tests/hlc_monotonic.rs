use fcp_audit::{HybridLogicalClock, HybridLogicalTimestamp};

#[test]
fn hlc_monotonic_under_clock_skew() {
    let mut clock = HybridLogicalClock::new("node-a");

    let first = clock.tick(1_000);
    let second = clock.tick(900);
    let third = clock.tick(900);

    assert!(second > first);
    assert!(third > second);
    assert_eq!(second.physical_ms, 1_000);
    assert_eq!(second.logical, 1);
    assert_eq!(third.logical, 2);
}

#[test]
fn hlc_merge_preserves_remote_causality_when_local_clock_lags() {
    let mut clock = HybridLogicalClock::new("node-b");
    let remote = HybridLogicalTimestamp::new(5_000, 7, "node-a");

    let merged = clock.merge(&remote, 4_000);

    assert!(merged > remote.with_node_id("node-b"));
    assert_eq!(merged.physical_ms, 5_000);
    assert_eq!(merged.logical, 8);
    assert_eq!(merged.node_id, "node-b");
}

#[test]
fn hlc_merge_uses_physical_time_when_it_is_newest() {
    let mut clock = HybridLogicalClock::new("node-c");
    let remote = HybridLogicalTimestamp::new(5_000, 7, "node-a");

    let merged = clock.merge(&remote, 6_000);

    assert_eq!(merged, HybridLogicalTimestamp::new(6_000, 0, "node-c"));
}
