//! Fuzz target: production IBLT decode + subtract under adversarial bytes.
//!
//! Targets `fcp_mesh::Iblt` — the production IBLT used by the gossip
//! anti-entropy path after the IbltPlaceholder→Iblt migration. The
//! gossip layer accepts an attacker-controlled CBOR-encoded IBLT from
//! a peer; the goal here is to ensure that **no input causes a panic,
//! infinite loop, or unbounded allocation in the decode pipeline.**
//!
//! Specifically exercises:
//!
//!   1. `ciborium` deserialization of `Iblt` from arbitrary bytes
//!      (the wire path via `gossip::Iblt`).
//!   2. `Iblt::subtract` cell-count-mismatch handling against a
//!      locally-built reference IBLT.
//!   3. `Iblt::decode` peeling loop: pure-cell discovery, termination,
//!      result reporting.
//!   4. `IbltCell::pure_key`'s cap on `count.abs()` — the previous
//!      `i32::MIN.abs()` panic was patched in commit 92e4dbd1; this
//!      target keeps that fix honest by hammering arbitrary `count`
//!      values from the wire.
//!
//! Oracle: crash detector. The decode path returns `IbltDecodeResult`
//! unconditionally (no `Result`-typed errors at the API boundary); any
//! panic, sanitizer violation, or OOM is the bug. We also assert the
//! bookkeeping invariant `remaining_nonzero_cells > 0 ⟺ !complete` to
//! catch silent inconsistencies in the decoder's accounting.

#![no_main]

use fcp_core::ObjectId;
use fcp_mesh::Iblt;
use libfuzzer_sys::fuzz_target;

/// Cap the input to keep the fuzzer fast and to bound CBOR allocation.
/// 1 MiB is generous: a well-formed IBLT cell is 40 bytes (i32 count +
/// [u8;32] key_sum + u32 hash_check), so 1 MiB encodes ~25k cells —
/// far above any realistic gossip exchange.
const MAX_INPUT_BYTES: usize = 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    // Path 1: deserialize an arbitrary peer-supplied IBLT.
    let peer: Iblt = match ciborium::from_reader(data) {
        Ok(iblt) => iblt,
        Err(_) => return,
    };

    // Path 2: reference local IBLT pre-populated with a few real
    // ObjectIds — this is what `GossipState::reconcile_with_peer_iblt`
    // does in production. We size it independently so `subtract` may or
    // may not match the peer's cell count, exercising both branches.
    let mut local = Iblt::with_expected_difference(8);
    for seed in 0u8..4 {
        local.insert(ObjectId::from_unscoped_bytes(&[seed]));
    }

    // Path 3: subtraction. May fail with CellCountMismatch — that is the
    // expected, well-typed outcome; only a panic would be a bug.
    if let Ok(diff) = local.subtract(&peer) {
        // Path 4: decode the difference. Must not panic for any peer
        // input that survived deserialization. Decode is infallible at
        // the API; any internal panic (e.g. the patched i32::MIN.abs())
        // is what the fuzzer is hunting.
        let result = diff.decode();

        // Bookkeeping invariant: complete ⇔ no nonzero cells remain.
        assert_eq!(
            result.complete,
            result.remaining_nonzero_cells == 0,
            "IbltDecodeResult.complete out of sync with remaining_nonzero_cells"
        );

        // Self-consistent set membership: the same ObjectId cannot be
        // reported in both `only_left` and `only_right` for a single
        // sketch — that would mean the decoder asserted "we have it AND
        // they have it AND nobody has it," which is incoherent.
        for object_id in &result.only_left {
            assert!(
                !result.only_right.contains(object_id),
                "object {object_id:?} reported in both only_left and only_right"
            );
        }
    }

    // Path 5: also decode the peer IBLT directly (without subtraction)
    // — this is what a callsite that received a fully-encoded
    // difference sketch does. Same invariants.
    let direct = peer.decode();
    assert_eq!(
        direct.complete,
        direct.remaining_nonzero_cells == 0,
        "direct decode complete/remaining out of sync"
    );
});
