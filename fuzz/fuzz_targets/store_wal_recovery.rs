//! Fuzz target: WAL + snapshot recovery against adversarial on-disk bytes.
//!
//! Exercises `DurableObjectStore::open` end-to-end with attacker-controlled
//! contents in `objects.wal.jsonl` and `objects.snapshot.json`. The recovery
//! path must:
//!
//!   1. **Never panic.** All errors must be returned as `ObjectStoreError`,
//!      not surface as a thread panic.
//!   2. **Bound memory.** A single oversized line must NOT allocate >
//!      `MAX_WAL_RECORD_BYTES` (512 MiB). A snapshot file larger than
//!      `MAX_SNAPSHOT_BYTES` (4 GiB) must error before allocating.
//!      (Closes the gap that bead `flywheel_connectors-yhmwv` patched in
//!      commit 4cea6816.)
//!   3. **Bound time.** Recovery on a torn WAL must terminate. A line of
//!      arbitrary bytes without a newline used to spin until OOM; the
//!      bounded reader must short-circuit.
//!
//! Oracle: crash detector + invariant. The fuzzer wins on:
//!   - any panic during `open`
//!   - sanitizer violation (ASan/UBSan)
//!   - timeout (libfuzzer rss_limit / timeout flags)
//!
//! The fuzzed inputs are split into a snapshot prefix and a WAL suffix
//! controlled by a single byte at the head, so the corpus exercises both
//! files independently and together.

#![no_main]

use std::fs;

use fcp_store::{DurableObjectStore, DurableObjectStoreConfig};
use libfuzzer_sys::fuzz_target;
use tempfile::TempDir;

/// Cap input size so the harness can run >100 exec/s without blowing
/// real disk on each iteration. 256 KiB is generous for realistic WAL +
/// snapshot crash scenarios while keeping per-iteration I/O fast.
const MAX_INPUT_BYTES: usize = 256 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES || data.is_empty() {
        return;
    }

    // First byte selects which files we populate, exercising:
    //   - WAL only (no snapshot — pure WAL-replay path)
    //   - Snapshot only (recovery from snapshot, empty WAL)
    //   - Both (snapshot anchors state, WAL applies tail mutations)
    //   - Both with split byte boundary somewhere in the input
    let mode = data[0];
    let payload = &data[1..];

    let dir = match TempDir::new() {
        Ok(d) => d,
        Err(_) => return,
    };
    let snapshot_path = dir.path().join("objects.snapshot.json");
    let wal_path = dir.path().join("objects.wal.jsonl");

    match mode % 4 {
        0 => {
            // WAL-only.
            if fs::write(&wal_path, payload).is_err() {
                return;
            }
        }
        1 => {
            // Snapshot-only.
            if fs::write(&snapshot_path, payload).is_err() {
                return;
            }
        }
        2 => {
            // Both files identical contents.
            if fs::write(&wal_path, payload).is_err() {
                return;
            }
            if fs::write(&snapshot_path, payload).is_err() {
                return;
            }
        }
        _ => {
            // Both files with payload split. Boundary picked from the
            // second byte (if present) so the fuzzer can drive split
            // points; otherwise default to halfway.
            let split = if payload.len() >= 2 {
                (payload[0] as usize) % payload.len()
            } else {
                payload.len() / 2
            };
            if fs::write(&snapshot_path, &payload[..split]).is_err() {
                return;
            }
            if fs::write(&wal_path, &payload[split..]).is_err() {
                return;
            }
        }
    }

    // Recovery must not panic regardless of file contents. Errors are
    // expected and acceptable — they're the well-typed outcome for any
    // malformed file. A panic, abort, or timeout is the bug.
    let config = DurableObjectStoreConfig::new(dir.path().to_path_buf());
    let _ = DurableObjectStore::open(config);

    // TempDir auto-cleans on drop.
});
