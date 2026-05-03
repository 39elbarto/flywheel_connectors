//! Criterion coverage for audit chain append construction and verification.

use std::hint::black_box;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use fcp_audit::{AuditEntry, AuditEntryBuilder, ChainHead, Severity, event_types, verify_chain};
use serde_json::json;

const BENCH_ZONE: &str = "z:bench:audit";

fn bench_entry(seq: u64, prev: Option<&str>, with_metadata: bool) -> AuditEntry {
    let mut builder = AuditEntryBuilder::new()
        .event_type(event_types::CAPABILITY_INVOKE)
        .severity(Severity::Info)
        .actor("agent:bench")
        .zone_id(BENCH_ZONE)
        .seq(seq)
        .occurred_at(1_700_000_000_u64.saturating_add(seq))
        .connector_id("fcp.bench")
        .operation_id("bench.invoke");

    if let Some(prev) = prev {
        builder = builder.prev(prev);
    }
    if with_metadata {
        builder = builder
            .correlation_id(format!("bench-{seq}"))
            .meta("request_bytes", json!(512))
            .meta("response_bytes", json!(2048))
            .meta("duration_us", json!(seq % 10_000));
    }

    builder.build_with_computed_id().unwrap()
}

fn bench_chain(len: u64, with_metadata: bool) -> Vec<AuditEntry> {
    let mut entries = Vec::with_capacity(usize::try_from(len).unwrap());
    let mut prev = None;

    for seq in 0..len {
        let entry = bench_entry(seq, prev.as_deref(), with_metadata);
        prev = Some(entry.id.clone());
        entries.push(entry);
    }

    entries
}

fn bench_head(entries: &[AuditEntry]) -> ChainHead {
    let head = entries.last().unwrap();
    ChainHead {
        zone_id: BENCH_ZONE.to_string(),
        head_entry: head.id.clone(),
        head_seq: head.seq,
        coverage: 1.0,
        epoch_id: "bench-epoch".to_string(),
        signature_count: 0,
        signatures: Vec::new(),
    }
}

fn bench_append_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("audit_chain_append_construction");

    for with_metadata in [false, true] {
        let name = if with_metadata {
            "computed_id_with_metadata"
        } else {
            "computed_id_minimal"
        };
        let mut seq = 0_u64;
        let mut prev = None;

        group.bench_function(name, |b| {
            b.iter(|| {
                let entry = bench_entry(seq, prev.as_deref(), with_metadata);
                prev = Some(entry.id.clone());
                seq = seq.saturating_add(1);
                black_box(entry);
            });
        });
    }

    group.finish();
}

fn bench_verify_chain(c: &mut Criterion) {
    let mut group = c.benchmark_group("audit_chain_verify");

    for len in [1_u64, 64, 1_024] {
        let entries = bench_chain(len, true);
        let head = bench_head(&entries);

        group.throughput(Throughput::Elements(len));
        group.bench_with_input(BenchmarkId::from_parameter(len), &len, |b, _| {
            b.iter(|| {
                black_box(verify_chain(
                    black_box(&entries),
                    Some(black_box(&head)),
                    Some(BENCH_ZONE),
                ));
            });
        });
    }

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(2));
    targets = bench_append_construction, bench_verify_chain
}
criterion_main!(benches);
