#![cfg(target_pointer_width = "64")]
#![forbid(unsafe_code)]

use std::cell::RefCell;
use std::error::Error;
use std::time::Duration;

use fcp_migrate::{
    Bandwidth, PageFaultSource, PageFetch, PostCopyDecision, PostCopyForwarder, PreCopyController,
    PreCopyDecision, Workload,
};

const MIB: u64 = 1024 * 1024;
const WORKING_SET_BYTES: u64 = 1024 * MIB;
const DIRTY_RATE_BYTES_PER_SECOND: u64 = 100 * MIB;
const BANDWIDTH_BYTES_PER_SECOND: u64 = 100 * MIB;
const PAGE_SIZE_BYTES: u64 = 4096;
const PAGE_FAULT_TIMEOUT_MS: u64 = 100;
const SOURCE_PEER: &str = "source-node";

#[test]
fn test_1gb_working_set_100mb_dirty_rate_falls_back_after_5_rounds() -> Result<(), Box<dyn Error>> {
    let mut source_heap = vec![0_u8; usize::try_from(WORKING_SET_BYTES)?];
    dirty_100mb_working_set(&mut source_heap);
    let source_hash = blake3::hash(&source_heap).to_hex().to_string();

    let controller = PreCopyController::new(
        Bandwidth::from_bytes_per_second(BANDWIDTH_BYTES_PER_SECOND),
        80,
        5,
    );
    let workload = Workload::new(
        WORKING_SET_BYTES,
        DIRTY_RATE_BYTES_PER_SECOND,
        PAGE_SIZE_BYTES,
    );
    let outcome = controller.run_precopy(&workload);

    assert!(outcome.is_stop_and_checkpoint(), "{outcome:?}");
    assert_eq!(outcome.report().rounds, 5);
    assert_eq!(
        outcome.report().logs.last().map(|log| log.decision),
        Some(PreCopyDecision::StopAndCheckpoint)
    );
    assert_eq!(
        outcome
            .report()
            .logs
            .last()
            .map(|log| log.dirty_pages_this_round),
        Some(dirty_pages_per_round())
    );

    let jsonl = outcome
        .report()
        .jsonl_round_logs("2026-05-18T00:00:00Z", "op_1gb_dirty_pressure")?;
    assert_eq!(jsonl.lines().count(), 5);

    let forwarder = page_forwarder_for_full_working_set();
    let destination = HashingDestinationPageSource::new(&source_heap, Duration::from_micros(75));
    for page_idx in 0..page_count() {
        let page_addr = page_idx.saturating_mul(PAGE_SIZE_BYTES);
        let outcome = forwarder.resolve_fault(page_addr, &destination);
        assert_eq!(outcome.decision(), PostCopyDecision::Forwarded);
        let trace = outcome.trace_event();
        assert_eq!(trace.page_addr, page_addr);
        assert_eq!(trace.source_peer.as_deref(), Some(SOURCE_PEER));
        assert_eq!(trace.latency_us, Some(75));
        assert_eq!(trace.timeout_ms, None);
        match outcome {
            fcp_migrate::PostCopyOutcome::Forwarded { bytes_len, .. } => {
                assert_eq!(bytes_len, usize::try_from(PAGE_SIZE_BYTES)?);
            }
            other => panic!("expected forwarded page fault, got {other:?}"),
        }
    }

    assert_eq!(
        destination.destination_hash(),
        source_hash,
        "post-copy destination stream must be byte-equivalent to source heap"
    );

    Ok(())
}

struct HashingDestinationPageSource<'a> {
    heap: &'a [u8],
    latency: Duration,
    destination_hasher: RefCell<blake3::Hasher>,
}

impl<'a> HashingDestinationPageSource<'a> {
    fn new(heap: &'a [u8], latency: Duration) -> Self {
        Self {
            heap,
            latency,
            destination_hasher: RefCell::new(blake3::Hasher::new()),
        }
    }

    fn destination_hash(&self) -> String {
        self.destination_hasher
            .borrow()
            .clone()
            .finalize()
            .to_hex()
            .to_string()
    }
}

impl PageFaultSource for HashingDestinationPageSource<'_> {
    fn fetch_page(&self, page_addr: u64, _source_peer: &str) -> PageFetch {
        let start = usize::try_from(page_addr).expect("page address should fit usize");
        let page_size = usize::try_from(PAGE_SIZE_BYTES).expect("page size should fit usize");
        let end = start.saturating_add(page_size);
        let bytes = self.heap[start..end].to_vec();
        self.destination_hasher.borrow_mut().update(&bytes);
        PageFetch {
            latency: self.latency,
            bytes,
        }
    }
}

fn dirty_100mb_working_set(heap: &mut [u8]) {
    let page_size = usize::try_from(PAGE_SIZE_BYTES).expect("page size should fit usize");
    for page_idx in 0..usize::try_from(dirty_pages_per_round()).expect("dirty pages fit usize") {
        let start = page_idx.saturating_mul(page_size);
        let end = start.saturating_add(page_size);
        fill_dirty_page(page_idx, &mut heap[start..end]);
    }
}

fn fill_dirty_page(page_idx: usize, page: &mut [u8]) {
    let digest = blake3::hash(&page_idx.to_le_bytes());
    let pattern = digest.as_bytes();
    for (offset, byte) in page.iter_mut().enumerate() {
        *byte = pattern[offset % pattern.len()];
    }
}

fn page_forwarder_for_full_working_set() -> PostCopyForwarder {
    let mut forwarder = PostCopyForwarder::new(Duration::from_millis(PAGE_FAULT_TIMEOUT_MS));
    for page_idx in 0..page_count() {
        let page_addr = page_idx.saturating_mul(PAGE_SIZE_BYTES);
        forwarder = forwarder.with_source(page_addr, SOURCE_PEER);
    }
    forwarder
}

const fn page_count() -> u64 {
    WORKING_SET_BYTES / PAGE_SIZE_BYTES
}

const fn dirty_pages_per_round() -> u64 {
    DIRTY_RATE_BYTES_PER_SECOND / PAGE_SIZE_BYTES
}
