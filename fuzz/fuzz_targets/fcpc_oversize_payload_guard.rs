//! FCPC payload-length memory-amplification guard fuzz target
//! (mechanical port of the proptest harness shipped in commit
//! 2ace18e83 — `fcpc_frame_decode_never_panics_and_rejects_oversized_length_claim`).
//!
//! Pins the memory-amplification oracle for `FcpcFrame::decode_with_limit`:
//! the payload-length check at `crates/fcp-protocol/src/fcpc.rs:228` MUST
//! reject any header-claimed length that exceeds the caller-supplied
//! `max_payload_len` BEFORE attempting any allocation proportional to
//! that claim. The proptest harness tests this with default + tight
//! limits; this libFuzzer target sweeps the full input space looking
//! for header shapes that bypass the gate (e.g., a length claim that
//! triggers the pre-check usize overflow path on 32-bit targets).
//!
//! ## Crash-only oracle
//!
//! No `assert!` — the only invariant is "never panics, always returns
//! Result". Coverage-guided exploration finds inputs that exercise
//! the boundary cases (claim exactly == limit, claim == limit + 1,
//! claim == usize::MAX, etc.) more effectively than random sampling.
//!
//! ## Run command
//!
//! ```bash
//! cd /Users/jemanuel/projects/flywheel_connectors
//! cargo +nightly fuzz run fuzz_fcpc_oversize_payload_guard
//! # Tighter run (CI-friendly):
//! cargo +nightly fuzz run fuzz_fcpc_oversize_payload_guard -- -runs=100000 -max_total_time=60
//! ```

#![no_main]

use fcp_protocol::FcpcFrame;
use libfuzzer_sys::fuzz_target;

/// Cap input size so a malformed header that declares a near-`u32::MAX`
/// payload doesn't trigger a >2GiB allocation in the fuzz process
/// itself before the gate fires. The gate is what we're testing —
/// allowing the fuzz harness to OOM hides real bugs.
const MAX_INPUT_BYTES: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    // Exercise the gate at multiple limit values so libFuzzer's
    // coverage feedback distinguishes "rejected by tight limit" from
    // "rejected by parse failure" from "accepted within limit". A
    // header shape that flips between these branches is the most
    // valuable input for finding the oversize-bypass class of bugs.
    for limit in [
        0_usize,           // every header MUST reject (claim > 0)
        16,                // tight: most claims reject
        1024,              // typical small budget
        1024 * 1024,       // 1 MiB
        4 * 1024 * 1024,   // default cap
        usize::MAX,        // no-cap mode — proves the parse layer
                           // alone never panics on a header claiming
                           // a near-`u32::MAX` length
    ] {
        let _ = FcpcFrame::decode_with_limit(data, limit);
    }
});
