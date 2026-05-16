//! Conformance coverage for HLC audit ordering and `HierVV` freshness frontiers.

use std::hint::black_box;
use std::time::Instant;

use fcp_audit::{HybridLogicalClock, HybridLogicalTimestamp};
use fcp_mesh::{
    HierarchicalVersionVector, RevocationFreshnessAction, RevocationFreshnessFrontier,
    VersionVectorOrder,
};

const HLC_TICK_P99_BUDGET_NANOS: u128 = 2_000;
const HIERVV_MERGE_P99_BUDGET_NANOS: u128 = 50_000;
const PERF_SAMPLE_COUNT: usize = 128;
const HLC_BATCH_SIZE: u128 = 256;

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

#[test]
fn hlc_tick_p99_stays_under_two_microseconds() {
    let mut clock = HybridLogicalClock::new("zone-a-node");

    for physical_ms in 1..=1024 {
        black_box(clock.tick(physical_ms));
    }

    let mut samples = Vec::with_capacity(PERF_SAMPLE_COUNT);
    for sample in 0..PERF_SAMPLE_COUNT {
        let base_physical_ms = 10_000_u64 + u64::try_from(sample).unwrap() * 1_000;
        let started_at = Instant::now();
        for offset in 0..HLC_BATCH_SIZE {
            black_box(clock.tick(base_physical_ms + u64::try_from(offset).unwrap()));
        }
        samples.push(started_at.elapsed().as_nanos() / HLC_BATCH_SIZE);
    }

    let p99_nanos = p99(&mut samples);
    assert!(
        p99_nanos <= HLC_TICK_P99_BUDGET_NANOS,
        "HLC tick p99 {p99_nanos}ns exceeded {HLC_TICK_P99_BUDGET_NANOS}ns budget"
    );
}

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "strict HierVV p99 budget is asserted in release-mode proof lanes"
)]
fn hiervv_merge_1024_zone_p99_stays_under_fifty_microseconds() {
    let right = explicit_1024_zone_vector(10);
    let mut samples = Vec::with_capacity(PERF_SAMPLE_COUNT);
    let lefts = (0..PERF_SAMPLE_COUNT)
        .map(|_| explicit_1024_zone_vector(7))
        .collect::<Vec<_>>();

    for mut left in lefts {
        let started_at = Instant::now();
        left.merge(black_box(&right));
        let elapsed_nanos = started_at.elapsed().as_nanos();
        assert_eq!(black_box(left.counter_for("z:tenant:prod:zone-1023")), 10);
        samples.push(elapsed_nanos);
    }

    let p99_nanos = p99(&mut samples);
    assert!(
        p99_nanos <= HIERVV_MERGE_P99_BUDGET_NANOS,
        "HierVV 1024-zone merge p99 {p99_nanos}ns exceeded {HIERVV_MERGE_P99_BUDGET_NANOS}ns budget"
    );
}

fn explicit_1024_zone_vector(counter: u64) -> HierarchicalVersionVector {
    let mut vector = HierarchicalVersionVector::new();
    for zone in 0..1024 {
        vector.set(format!("z:tenant:prod:zone-{zone:04}"), counter);
    }
    vector
}

fn p99(samples: &mut [u128]) -> u128 {
    samples.sort_unstable();
    let rank = (samples.len() * 99).div_ceil(100).saturating_sub(1);
    samples[rank]
}
