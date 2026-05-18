use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use fcp_migrate::{
    Bandwidth, DirtyTracker, DirtyTrackerError, DirtyTrackerMode, PRECOPY_ROUND_OTLP_SPAN,
    PageFaultSource, PageFetch, PostCopyDecision, PostCopyFallbackDecision, PostCopyForwarder,
    PreCopyController, PreCopyDecision, PreCopyOutcome, Workload,
};
use proptest::prelude::*;
use serde_json::Value;

const MIB: u64 = 1024 * 1024;
const PAGE_COUNT: u64 = 8192;
const PAGE_SIZE_BYTES: u64 = 4096;
const CONCURRENT_WRITER_CAPACITY: usize = 16;
const WRITES_PER_WORKER: usize = 256;

#[test]
fn synthetic_dirty_rate_exceeds_80pct_triggers_stop_and_checkpoint() {
    let controller = PreCopyController::new(Bandwidth::from_mib_per_second(100), 80, 5);
    let workload = Workload::synthetic_mib(256, 85);

    let outcome = controller.run_precopy(&workload);

    assert!(outcome.is_stop_and_checkpoint());
    assert_eq!(outcome.report().rounds, 5);
    assert_eq!(
        outcome.report().logs.last().map(|log| log.decision),
        Some(PreCopyDecision::StopAndCheckpoint)
    );
    assert!(outcome.report().dirty_rate_pct_of_bandwidth >= 85);
}

#[test]
fn precopy_round_logs_serialize_operator_jsonl_contract() {
    let controller = PreCopyController::new(Bandwidth::from_mib_per_second(100), 80, 5);
    let workload = Workload::synthetic_mib(256, 85);

    let outcome = controller.run_precopy(&workload);
    let jsonl = outcome
        .report()
        .jsonl_round_logs("2026-05-18T00:00:00Z", "op_migrate_test")
        .expect("pre-copy round logs should serialize");
    let lines: Vec<&str> = jsonl.lines().collect();

    assert_eq!(lines.len(), 5);
    let last: Value = serde_json::from_str(lines.last().expect("last log line")).unwrap();
    assert_eq!(last["timestamp"], "2026-05-18T00:00:00Z");
    assert_eq!(last["op_id"], "op_migrate_test");
    assert_eq!(last["round_idx"], 5);
    assert_eq!(last["dirty_pages_this_round"], 21_760);
    assert_eq!(last["bandwidth_estimate_mbps"], 100);
    assert_eq!(last["dirty_rate_mbps"], 85);
    assert_eq!(last["decision"], "StopAndCheckpoint");
}

#[test]
fn precopy_round_logs_expose_named_otlp_span() {
    let controller = PreCopyController::new(Bandwidth::from_mib_per_second(100), 80, 5);
    let outcome = controller.run_precopy(&Workload::synthetic_mib(256, 85));
    let last = outcome.report().logs.last().expect("last pre-copy round");

    let _span = last.otlp_span("op_migrate_test");
    assert_eq!(PRECOPY_ROUND_OTLP_SPAN, "fcp.criu.precopy_round");
    assert_eq!(last.bandwidth_estimate_mbps(), 100);
    assert_eq!(last.dirty_rate_mbps(), 85);
    assert!(last.fallback_triggered());
}

#[test]
fn low_dirty_rate_converges_in_bounded_rounds() {
    let controller = PreCopyController::new(Bandwidth::from_mib_per_second(100), 80, 5);
    let workload = Workload::synthetic_mib(256, 10);

    let outcome = controller.run_precopy(&workload);

    assert!(outcome.is_converged(), "{outcome:?}");
    assert!(outcome.report().rounds <= 3, "{outcome:?}");
    assert_eq!(outcome.report().final_dirty_bytes, 0);
}

proptest! {
    #![proptest_config(ProptestConfig {
        failure_persistence: None,
        .. ProptestConfig::default()
    })]

    #[test]
    fn dirty_bitmap_accuracy_under_concurrent_writes(seed in any::<u64>()) {
        let tracker = Arc::new(DirtyTracker::with_mode(
            DirtyTrackerMode::PageWalkerFallback,
            PAGE_COUNT,
            PAGE_SIZE_BYTES,
        ));
        tracker.clear();
        let expected = expected_dirty_pages(seed);
        let mut handles = Vec::with_capacity(CONCURRENT_WRITER_CAPACITY);
        for worker_idx in 0_u64..16 {
            let tracker = Arc::clone(&tracker);
            handles.push(std::thread::spawn(move || {
                let mut state = seed ^ worker_idx.rotate_left(13);
                for _ in 0..WRITES_PER_WORKER {
                    let page_idx = next_page(&mut state);
                    tracker.record_write_range(page_idx.saturating_mul(PAGE_SIZE_BYTES), PAGE_SIZE_BYTES);
                }
            }));
        }
        for handle in handles {
            handle.join().expect("writer thread should not panic");
        }
        let actual: BTreeSet<u64> = tracker.dirty_pages().into_iter().collect();
        prop_assert_eq!(actual, expected);
    }
}

#[test]
fn postcopy_page_fault_timeout_falls_back_to_full_re_execute() {
    let forwarder =
        PostCopyForwarder::new(Duration::from_millis(100)).with_source(0x1000, "node-a");
    let source = StaticPageSource {
        latency: Duration::from_millis(101),
        bytes: vec![0_u8; 4096],
    };

    let outcome = forwarder.resolve_fault(0x1000, &source);

    assert_eq!(outcome.decision(), PostCopyDecision::Timeout);
    assert_eq!(
        outcome,
        fcp_migrate::PostCopyOutcome::Timeout {
            page_addr: 0x1000,
            source_peer: "node-a".to_owned(),
            timeout_ms: 100,
            fallback: PostCopyFallbackDecision::FullReExecute,
        }
    );
}

#[test]
fn postcopy_page_fault_trace_event_carries_forwarding_contract_fields() {
    let forwarder =
        PostCopyForwarder::new(Duration::from_millis(100)).with_source(0x1000, "node-a");
    let source = StaticPageSource {
        latency: Duration::from_micros(75),
        bytes: vec![0_u8; 4096],
    };

    let outcome = forwarder.resolve_fault(0x1000, &source);
    let trace = outcome.trace_event();

    assert_eq!(trace.page_addr, 0x1000);
    assert_eq!(trace.source_peer.as_deref(), Some("node-a"));
    assert_eq!(trace.latency_us, Some(75));
    assert_eq!(trace.timeout_ms, None);
    assert_eq!(trace.decision, PostCopyDecision::Forwarded);
    assert_eq!(trace.fallback, None);
}

#[test]
fn postcopy_page_fault_trace_event_carries_timeout_fallback() {
    let forwarder =
        PostCopyForwarder::new(Duration::from_millis(100)).with_source(0x1000, "node-a");
    let source = StaticPageSource {
        latency: Duration::from_millis(101),
        bytes: vec![0_u8; 4096],
    };

    let outcome = forwarder.resolve_fault(0x1000, &source);
    let trace = outcome.trace_event();

    assert_eq!(trace.page_addr, 0x1000);
    assert_eq!(trace.source_peer.as_deref(), Some("node-a"));
    assert_eq!(trace.latency_us, None);
    assert_eq!(trace.timeout_ms, Some(100));
    assert_eq!(trace.decision, PostCopyDecision::Timeout);
    assert_eq!(
        trace.fallback,
        Some(PostCopyFallbackDecision::FullReExecute)
    );
}

#[test]
fn kernel_lacks_soft_dirty_falls_back_to_walker() {
    let tracker = DirtyTracker::from_soft_dirty_probe(
        4,
        PAGE_SIZE_BYTES,
        Err(DirtyTrackerError::SoftDirtyUnavailable("ENOSYS".to_owned())),
    );

    assert_eq!(tracker.mode(), DirtyTrackerMode::PageWalkerFallback);
    tracker.record_write_range(0, PAGE_SIZE_BYTES);
    assert!(tracker.is_dirty(0));
}

struct StaticPageSource {
    latency: Duration,
    bytes: Vec<u8>,
}

impl PageFaultSource for StaticPageSource {
    fn fetch_page(&self, _page_addr: u64, _source_peer: &str) -> PageFetch {
        PageFetch {
            latency: self.latency,
            bytes: self.bytes.clone(),
        }
    }
}

fn expected_dirty_pages(seed: u64) -> BTreeSet<u64> {
    let mut expected = BTreeSet::new();
    for worker_idx in 0_u64..16 {
        let mut state = seed ^ worker_idx.rotate_left(13);
        for _ in 0..WRITES_PER_WORKER {
            expected.insert(next_page(&mut state));
        }
    }
    expected
}

const fn next_page(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state % PAGE_COUNT
}

#[test]
fn high_dirty_rate_outcome_variant_is_stop_and_checkpoint() {
    let controller = PreCopyController::new(Bandwidth::from_mib_per_second(100), 80, 5);
    let outcome = controller.run_precopy(&Workload::new(256 * MIB, 85 * MIB, PAGE_SIZE_BYTES));

    assert!(matches!(outcome, PreCopyOutcome::StopAndCheckpoint(_)));
}
