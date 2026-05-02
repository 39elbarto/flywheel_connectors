use std::hint::black_box;

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use fcp_prelude::{ObjectId, ObjectPlacementPolicy, ZoneId};
use fcp_store::{CoverageEvaluation, RepairController, RepairControllerConfig, RepairRequest};

fn bench_zone() -> ZoneId {
    "z:bench".parse().unwrap()
}

#[allow(clippy::missing_const_for_fn)]
fn bench_policy() -> ObjectPlacementPolicy {
    ObjectPlacementPolicy {
        min_nodes: 1,
        max_node_fraction_bps: 10_000,
        preferred_devices: vec![],
        excluded_devices: vec![],
        target_coverage_bps: 10_000,
        min_source_diversity: 0,
    }
}

fn bench_object_id(index: usize) -> ObjectId {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&u64::try_from(index).unwrap().to_le_bytes());
    ObjectId::from_bytes(bytes)
}

fn bench_coverage(object_id: ObjectId) -> CoverageEvaluation {
    CoverageEvaluation {
        object_id,
        distinct_nodes: 1,
        max_node_fraction_bps: 10_000,
        coverage_bps: 5_000,
        is_available: false,
        total_symbols: 5,
        source_symbols: 10,
    }
}

fn bench_config() -> RepairControllerConfig {
    RepairControllerConfig {
        max_repairs_per_minute: u32::MAX,
        ..Default::default()
    }
}

fn build_requests(count: usize) -> Vec<RepairRequest> {
    let zone_id = bench_zone();
    let policy = bench_policy();
    (0..count)
        .map(|index| {
            let object_id = bench_object_id(index);
            RepairRequest {
                object_id,
                zone_id: zone_id.clone(),
                coverage: bench_coverage(object_id),
                policy: policy.clone(),
                priority: u32::try_from((index.wrapping_mul(37)) % 10_000).unwrap(),
            }
        })
        .collect()
}

fn populate_controller(requests: &[RepairRequest]) -> RepairController {
    let controller = RepairController::new(bench_config());
    for request in requests {
        controller.queue_repair(request.clone());
    }
    controller
}

fn bench_repair_queue_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("repair_queue_insert");

    for count in [100_usize, 1_000, 10_000] {
        group.throughput(Throughput::Elements(count as u64));
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, &count| {
            b.iter_batched(
                || build_requests(count),
                |requests| {
                    let controller = RepairController::new(bench_config());
                    for request in requests {
                        controller.queue_repair(request);
                    }
                    black_box(controller.queue_depth())
                },
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

fn bench_repair_queue_pop(c: &mut Criterion) {
    let mut group = c.benchmark_group("repair_queue_pop");

    for count in [100_usize, 1_000, 10_000] {
        group.throughput(Throughput::Elements(count as u64));
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, &count| {
            b.iter_batched(
                || {
                    let requests = build_requests(count);
                    populate_controller(&requests)
                },
                |controller| {
                    let mut popped = 0_usize;
                    while controller.next_repair().is_some() {
                        popped += 1;
                    }
                    black_box(popped)
                },
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

criterion_group!(benches, bench_repair_queue_insert, bench_repair_queue_pop);
criterion_main!(benches);
