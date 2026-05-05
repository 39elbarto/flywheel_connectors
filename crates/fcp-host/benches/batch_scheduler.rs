//! Criterion benchmark for adaptive batch-scheduler planning and replay output.
//!
//! The workload intentionally models a pathological massive-agent burst: a
//! small set of long operations arrives before a large set of short independent
//! operations. FIFO preserves submission order; adaptive mode promotes short
//! work while bounding the extra wait imposed on long work.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use fcp_host::{
    BatchExecutor, BatchInvokeRequest, BatchOperation, BatchOperationPriority, BatchOptions,
    BatchScheduleHint, BatchSchedulerMode, BatchSchedulerOptions,
};

const LONG_OPERATION_MS: u64 = 10_000;
const SHORT_OPERATION_MS: u64 = 1;
const FAIRNESS_BUCKETS: usize = 64;

fn scheduled_operation(
    id: String,
    estimated_duration_ms: u64,
    fairness_key: String,
) -> BatchOperation {
    BatchOperation {
        id,
        tool: "fcp.bench.batch_scheduler.noop".to_string(),
        input: serde_json::json!({}),
        depends_on: Vec::new(),
        zone: None,
        scheduler: BatchScheduleHint {
            priority: BatchOperationPriority::Normal,
            estimated_duration_ms: Some(estimated_duration_ms),
            fairness_key: Some(fairness_key),
        },
    }
}

fn skewed_swarm_request(total_operations: usize, mode: BatchSchedulerMode) -> BatchInvokeRequest {
    assert!(
        total_operations >= 1_000,
        "batch scheduler benchmark needs enough samples for p99/p999"
    );
    let long_operations = total_operations / 100;
    let short_operations = total_operations - long_operations;
    let mut operations = Vec::with_capacity(total_operations);

    for index in 0..long_operations {
        operations.push(scheduled_operation(
            format!("long_{index:05}"),
            LONG_OPERATION_MS,
            "tenant-long".to_string(),
        ));
    }
    for index in 0..short_operations {
        operations.push(scheduled_operation(
            format!("short_{index:05}"),
            SHORT_OPERATION_MS,
            format!("tenant-short-{}", index % FAIRNESS_BUCKETS),
        ));
    }

    BatchInvokeRequest {
        operations,
        options: BatchOptions {
            scheduler: BatchSchedulerOptions {
                mode,
                max_consecutive_per_fairness_key: 2,
            },
            ..Default::default()
        },
    }
}

fn assert_tail_queueing_gain(executor: &BatchExecutor, request: &BatchInvokeRequest) {
    let (_plan, report) = executor
        .plan_with_schedule_report(request)
        .expect("adaptive scheduler benchmark request should plan");
    let summary = report
        .queueing_summary
        .expect("scheduler report should include queueing summary");
    let morselization = report
        .morselization
        .expect("scheduler report should include max-parallelism morsels");

    assert!(
        summary.p99_wait_improvement_ms > 0,
        "adaptive scheduler should improve p99 queueing on skewed workload: {summary:?}"
    );
    assert!(
        summary.p999_wait_improvement_ms > 0,
        "adaptive scheduler should improve p999 queueing on skewed workload: {summary:?}"
    );
    assert!(
        summary.max_wait_increase_ms <= i64::try_from(request.operations.len()).unwrap_or(i64::MAX),
        "long-operation wait increase should stay bounded by the short burst: {summary:?}"
    );
    assert!(
        morselization.largest_morsel_operations
            <= usize::try_from(request.options.max_parallelism)
                .unwrap_or(usize::MAX)
                .max(1),
        "morsel report should honor max_parallelism: {morselization:?}"
    );
}

fn batch_scheduler(c: &mut Criterion) {
    let executor = BatchExecutor::new();
    let mut group = c.benchmark_group("batch_scheduler_replay");

    for total_operations in [1_000_usize, 10_000] {
        let fifo_request = skewed_swarm_request(total_operations, BatchSchedulerMode::Fifo);
        let adaptive_request = skewed_swarm_request(total_operations, BatchSchedulerMode::Adaptive);
        assert_tail_queueing_gain(&executor, &adaptive_request);

        group.bench_with_input(
            BenchmarkId::new("fifo_plan_with_report", total_operations),
            &fifo_request,
            |bench, request| {
                bench.iter(|| {
                    let (plan, report) = executor
                        .plan_with_schedule_report(black_box(request))
                        .expect("FIFO benchmark request should plan");
                    black_box((
                        plan.total_operations,
                        report.queueing_summary,
                        report.morselization,
                    ));
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("adaptive_plan_with_report", total_operations),
            &adaptive_request,
            |bench, request| {
                bench.iter(|| {
                    let (plan, report) = executor
                        .plan_with_schedule_report(black_box(request))
                        .expect("adaptive benchmark request should plan");
                    black_box((
                        plan.total_operations,
                        report.queueing_summary,
                        report.morselization,
                    ));
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, batch_scheduler);
criterion_main!(benches);
