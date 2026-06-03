use fcp_audit::{
    AuditEntry, AuditEntryBuilder, ReservoirCompactionError, compact_entries, event_types,
};
use serde_json::json;

fn entry(seq: u64) -> AuditEntry {
    AuditEntryBuilder::new()
        .event_type(event_types::CAPABILITY_INVOKE)
        .actor("agent:reservoir-test")
        .zone_id("z:work")
        .seq(seq)
        .occurred_at(1_700_000_000 + seq)
        .correlation_id(format!("corr-{seq}"))
        .connector_id("fcp.test")
        .operation_id("test.invoke")
        .meta("token_hash", json!(format!("token-{seq}")))
        .build_with_computed_id()
        .expect("fixture entry should build")
}

fn entries(count: usize) -> Vec<AuditEntry> {
    (0..count)
        .map(|seq| entry(u64::try_from(seq).expect("fixture sequence fits u64")))
        .collect()
}

fn retained_sequences(compaction: &fcp_audit::ReservoirCompaction) -> Vec<u64> {
    compaction.entries.iter().map(|entry| entry.seq).collect()
}

#[test]
fn small_stream_is_retained_exactly() {
    let source = entries(5);

    let compaction = compact_entries(source.clone(), 10, 42).expect("capacity is valid");

    assert_eq!(compaction.entries, source);
    assert_eq!(compaction.report.total_observed, 5);
    assert_eq!(compaction.report.retained_count, 5);
    assert_eq!(compaction.report.dropped_count, 0);
    assert_eq!(compaction.report.observed_seq_min, Some(0));
    assert_eq!(compaction.report.observed_seq_max, Some(4));
}

#[test]
fn capacity_bounds_large_stream_and_reports_drops() {
    let compaction = compact_entries(entries(100), 7, 7).expect("capacity is valid");

    assert_eq!(compaction.entries.len(), 7);
    assert_eq!(compaction.report.capacity, 7);
    assert_eq!(compaction.report.total_observed, 100);
    assert_eq!(compaction.report.retained_count, 7);
    assert_eq!(compaction.report.dropped_count, 93);
}

#[test]
fn same_seed_is_reproducible() {
    let first = compact_entries(entries(200), 12, 99).expect("capacity is valid");
    let second = compact_entries(entries(200), 12, 99).expect("capacity is valid");

    assert_eq!(retained_sequences(&first), retained_sequences(&second));
    assert_eq!(first.report.sample_digest, second.report.sample_digest);
}

#[test]
fn different_seed_can_choose_different_sample() {
    let first = compact_entries(entries(200), 12, 1).expect("capacity is valid");
    let second = compact_entries(entries(200), 12, 2).expect("capacity is valid");

    assert_ne!(retained_sequences(&first), retained_sequences(&second));
    assert_ne!(first.report.sample_digest, second.report.sample_digest);
}

#[test]
fn retained_entries_are_sorted_by_sequence_for_replay() {
    let reversed = entries(12).into_iter().rev().collect::<Vec<_>>();

    let compaction = compact_entries(reversed, 20, 3).expect("capacity is valid");

    assert_eq!(retained_sequences(&compaction), (0..12).collect::<Vec<_>>());
    assert_eq!(compaction.report.retained_seq_min, Some(0));
    assert_eq!(compaction.report.retained_seq_max, Some(11));
}

#[test]
fn zero_capacity_is_rejected() {
    let error = compact_entries(entries(1), 0, 0).expect_err("zero capacity should fail");

    assert_eq!(error, ReservoirCompactionError::ZeroCapacity);
}

#[test]
fn seed_sweep_keeps_sample_approximately_uniform() {
    const POPULATION: usize = 64;
    const CAPACITY: usize = 8;
    const SWEEPS: usize = 2_048;

    let mut included = [0_u32; POPULATION];
    for seed in 0..SWEEPS {
        let compaction = compact_entries(
            entries(POPULATION),
            CAPACITY,
            u64::try_from(seed).expect("fixture seed fits u64"),
        )
        .expect("capacity is valid");
        for seq in retained_sequences(&compaction) {
            let index = usize::try_from(seq).expect("fixture sequence fits usize");
            included[index] = included[index].saturating_add(1);
        }
    }

    let expected = u32::try_from((SWEEPS * CAPACITY) / POPULATION).expect("expected fits u32");
    let lower_bound = expected / 2;
    let upper_bound = expected + (expected / 2);

    for (seq, count) in included.into_iter().enumerate() {
        assert!(
            (lower_bound..=upper_bound).contains(&count),
            "sequence {seq} appeared {count} times; expected around {expected}"
        );
    }
}
