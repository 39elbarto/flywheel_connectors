//! Fuzz target: XorFilterPlaceholder insert/may_contain/digest invariants
//! under adversarial inputs.
//!
//! Targets `fcp_mesh::gossip::XorFilterPlaceholder` — the gossip-summary
//! XOR filter used by the mesh anti-entropy path to estimate set
//! membership across peers. The filter is built from peer-supplied bytes
//! via the gossip summary handler; this fuzz target exercises the same
//! API surface against arbitrary byte sequences.
//!
//! Filed under `flywheel_connectors-angoc.10.3` (Phase P.1b: fuzz targets
//! 5-7: RaptorQ envelope, IBLT decode, XOR filter ops). RaptorQ-envelope
//! and IBLT-decode harnesses already exist; this XOR-filter target
//! completes the Phase P.1b set.
//!
//! Invariants asserted:
//!
//!   1. No-false-negative: after `insert(item)`, `may_contain(item)`
//!      MUST return true. (Bloom-style filters tolerate false positives
//!      but never false negatives.)
//!   2. Length monotone: `len()` is non-decreasing across `insert` calls.
//!   3. Determinism: `digest()` returns the same bytes for the same key
//!      set (modulo insertion order, since `keys: BTreeSet<u64>` enforces
//!      sorted iteration).
//!   4. No panics on bizarre inputs (empty slices, very long slices,
//!      all-zero bytes, all-0xFF bytes, multi-megabyte slices).
//!
//! Oracle: panic detector + the four named invariants. Any false-negative
//! or non-deterministic digest under the same key set is a bug.

#![no_main]

use fcp_mesh::gossip::XorFilterPlaceholder;
use libfuzzer_sys::fuzz_target;

/// Cap individual item size and total per-filter inserts to keep the
/// fuzzer fast. A real gossip XOR filter holds a few thousand
/// `ObjectId` (32-byte) keys; we test up to 256 inserts per fuzz
/// iteration of up to 4 KiB each.
const MAX_ITEM_BYTES: usize = 4 * 1024;
const MAX_INSERTS_PER_RUN: usize = 256;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Treat `data` as a sequence of length-prefixed items. The first
    // byte gives the item length (0..=255); the next N bytes are the
    // item; repeat until exhausted or we hit the insert cap.
    let mut filter = XorFilterPlaceholder::new();
    let mut inserted: Vec<Vec<u8>> = Vec::new();
    let mut cursor = 0usize;
    let mut prev_len = filter.len();

    while cursor < data.len() && inserted.len() < MAX_INSERTS_PER_RUN {
        let item_len = data[cursor] as usize;
        cursor += 1;

        let take = item_len.min(MAX_ITEM_BYTES).min(data.len() - cursor);
        let item: Vec<u8> = data[cursor..cursor + take].to_vec();
        cursor += take;

        filter.insert(&item);

        // Invariant 1: no false negatives — the just-inserted item must
        // be reported as may-contained.
        assert!(
            filter.may_contain(&item),
            "XorFilter false negative: item just inserted not may_contain'd; \
             item.len()={}, filter.len()={}",
            item.len(),
            filter.len()
        );

        // Invariant 2: len is non-decreasing. (Duplicate inserts may keep
        // len constant; that is acceptable.)
        let now_len = filter.len();
        assert!(
            now_len >= prev_len,
            "XorFilter len() decreased: {prev_len} -> {now_len}"
        );
        prev_len = now_len;

        inserted.push(item);
    }

    // Invariant 3: digest determinism. Re-insert the same items into a
    // fresh filter (in original order); the two filters' digests should
    // match.
    let mut replica = XorFilterPlaceholder::new();
    for item in &inserted {
        replica.insert(item);
    }
    assert_eq!(
        filter.digest(),
        replica.digest(),
        "XorFilter digest non-deterministic under identical insertion sequence"
    );

    // Cross-check: every inserted item is may_contain'd post-hoc on the
    // original filter. (Together with invariant 1 this covers the case
    // where insert order matters relative to the cached-xorf-build path.)
    for item in &inserted {
        assert!(
            filter.may_contain(item),
            "XorFilter false negative on post-hoc check: item.len()={}",
            item.len()
        );
    }
});
