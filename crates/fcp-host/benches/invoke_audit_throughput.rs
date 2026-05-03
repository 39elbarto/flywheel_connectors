//! InvokeAuditChain throughput benchmark (br-uwlj5 + br-ir8cz).
//!
//! Measures append throughput at concurrency 1 / 8 / 32 / 128 / 512 across
//! single-zone (lock contention dominant) and multi-zone (per-zone
//! sharding wins) scenarios. Establishes the baseline for the uwlj5
//! per-zone sharding fix.
//!
//! The pre-uwlj5 design held a single global `Mutex<HashMap<...>>`
//! over the whole append, including canonical-CBOR encode + BLAKE3
//! hash. This bench's "single-zone" group surfaces the residual
//! contention while the "multi-zone" group surfaces the load-bearing
//! parallelism win. The production append path keeps the optimistic
//! CAS fast path, then falls back to one serialized commit when
//! stale-head retries show hot same-zone writer pressure.
//!
//! Run with `cargo bench -p fcp-host --bench invoke_audit_throughput`.

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use fcp_host::{InvokeAuditChain, InvokeAuditContext, InvokePhase};

fn ctx(zone: &str, op_id_prefix: &str, i: usize) -> InvokeAuditContext {
    InvokeAuditContext {
        zone_id: zone.into(),
        actor: "agent:bench".into(),
        connector_id: "github".into(),
        operation: "list_repos".into(),
        operation_id: format!("{op_id_prefix}-{i}"),
        correlation_id: None,
        occurred_at: 1_700_000_000,
    }
}

/// Single-thread baseline — measures the cost of one append in
/// isolation (canonical-CBOR encode + BLAKE3 hash + Vec push). Used
/// as the divisor for "speedup vs sequential" computations across
/// the concurrency sweep.
fn bench_single_thread_append(c: &mut Criterion) {
    let mut group = c.benchmark_group("invoke_audit_single_thread");
    group.sample_size(20);
    group.measurement_time(Duration::from_secs(3));
    group.warm_up_time(Duration::from_secs(1));
    group.throughput(Throughput::Elements(1));

    group.bench_function("append_one_event", |b| {
        let chain = InvokeAuditChain::new();
        let mut i = 0_usize;
        b.iter(|| {
            chain
                .append(&ctx("z:bench", "op", i), InvokePhase::PreflightAllow)
                .expect("append must not fail");
            i += 1;
        });
    });

    group.finish();
}

/// Multi-zone parallelism — N threads, each appending APPENDS_PER
/// events to its OWN zone. Pre-uwlj5 single-Mutex design serialised
/// these on the global lock; per-zone sharding lets them run in
/// parallel. Speedup over single-thread is the load-bearing metric.
fn bench_multi_zone_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("invoke_audit_multi_zone");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(5));
    group.warm_up_time(Duration::from_secs(1));

    for &concurrency in &[1usize, 8, 32, 128] {
        const APPENDS_PER_THREAD: usize = 64;
        group.throughput(Throughput::Elements(
            (concurrency * APPENDS_PER_THREAD) as u64,
        ));
        group.bench_function(format!("c={concurrency}"), |b| {
            b.iter_custom(|iters| {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    let chain = Arc::new(InvokeAuditChain::new());
                    let start = std::time::Instant::now();
                    let mut handles = Vec::with_capacity(concurrency);
                    for t in 0..concurrency {
                        let chain = Arc::clone(&chain);
                        handles.push(thread::spawn(move || {
                            let zone = format!("z:bench-{t}");
                            for i in 0..APPENDS_PER_THREAD {
                                chain
                                    .append(&ctx(&zone, "op", i), InvokePhase::PreflightAllow)
                                    .expect("append");
                            }
                        }));
                    }
                    for h in handles {
                        h.join().expect("worker");
                    }
                    total += start.elapsed();
                }
                total
            });
        });
    }

    group.finish();
}

/// Single-zone contention — N threads, each appending events to the
/// SAME zone. The per-zone Mutex still serialises commits. The
/// optimistic-CAS path keeps canonical-CBOR + BLAKE3 lock-free for
/// light contention, and the serialized fallback prevents repeated
/// stale-head recomputation from exhausting the retry budget under a
/// hot-zone storm. Measures the production contention floor.
fn bench_same_zone_contention(c: &mut Criterion) {
    let mut group = c.benchmark_group("invoke_audit_same_zone");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(5));
    group.warm_up_time(Duration::from_secs(1));

    for &concurrency in &[1usize, 8, 32, 128, 512] {
        let appends_per_thread = if concurrency >= 512 { 16 } else { 64 };
        group.throughput(Throughput::Elements(
            (concurrency * appends_per_thread) as u64,
        ));
        group.bench_function(format!("c={concurrency}"), |b| {
            b.iter_custom(|iters| {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    let chain = Arc::new(InvokeAuditChain::new());
                    let start = std::time::Instant::now();
                    let mut handles = Vec::with_capacity(concurrency);
                    for t in 0..concurrency {
                        let chain = Arc::clone(&chain);
                        handles.push(thread::spawn(move || {
                            for i in 0..appends_per_thread {
                                chain
                                    .append(
                                        &ctx("z:contended", &format!("t-{t}"), i),
                                        InvokePhase::PreflightAllow,
                                    )
                                    .expect("append");
                            }
                        }));
                    }
                    for h in handles {
                        h.join().expect("worker");
                    }
                    total += start.elapsed();
                }
                total
            });
        });
    }

    group.finish();
}

/// Per-phase append latency — pin that all four phases (allow,
/// deny, dispatch result, dispatch error) cost approximately the
/// same. Diverging cost would surface a phase-specific allocation
/// regression.
fn bench_per_phase_latency(c: &mut Criterion) {
    let mut group = c.benchmark_group("invoke_audit_per_phase");
    group.sample_size(20);
    group.measurement_time(Duration::from_secs(3));
    group.warm_up_time(Duration::from_secs(1));
    group.throughput(Throughput::Elements(1));

    group.bench_function("allow", |b| {
        let chain = InvokeAuditChain::new();
        let mut i = 0_usize;
        b.iter(|| {
            chain
                .append(&ctx("z:bench", "op", i), InvokePhase::PreflightAllow)
                .unwrap();
            i += 1;
        });
    });

    group.bench_function("deny", |b| {
        let chain = InvokeAuditChain::new();
        let mut i = 0_usize;
        b.iter(|| {
            chain
                .append(
                    &ctx("z:bench", "op", i),
                    InvokePhase::PreflightDeny {
                        reason: "capability not granted".into(),
                    },
                )
                .unwrap();
            i += 1;
        });
    });

    group.bench_function("dispatch_result", |b| {
        let chain = InvokeAuditChain::new();
        let mut i = 0_usize;
        b.iter(|| {
            chain
                .append(
                    &ctx("z:bench", "op", i),
                    InvokePhase::DispatchResult {
                        receipt_id: Some("rcpt-x".into()),
                        success: true,
                        duration_ms: 42,
                    },
                )
                .unwrap();
            i += 1;
        });
    });

    group.bench_function("dispatch_error", |b| {
        let chain = InvokeAuditChain::new();
        let mut i = 0_usize;
        b.iter(|| {
            chain
                .append(
                    &ctx("z:bench", "op", i),
                    InvokePhase::DispatchError {
                        error: "subprocess crashed".into(),
                        duration_ms: 17,
                    },
                )
                .unwrap();
            i += 1;
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_single_thread_append,
    bench_multi_zone_throughput,
    bench_same_zone_contention,
    bench_per_phase_latency,
);
criterion_main!(benches);
