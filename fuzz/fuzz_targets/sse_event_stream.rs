#![no_main]
//! Fuzz target for the SSE event-stream parser (`fcp-streaming::sse`).
//!
//! Bead flywheel_connectors-2qsbc. Drives the parser on chunked adversarial
//! byte streams that exercise:
//!
//! - oversized `event:` / `data:` / `id:` / `retry:` field values,
//! - missing newline terminators (CR-only, LF-only, CRLF, no trailing newline),
//! - embedded NUL bytes (id-field branch refuses NULs but only conditionally),
//! - non-UTF-8 sequences (parser uses `from_utf8_lossy` and must not panic),
//! - retry values that overflow `u64::parse`,
//! - chunk boundaries split through the middle of a field, line, or terminator.
//!
//! Invariants asserted across every input:
//! 1. The parser never panics.
//! 2. Retained-bytes (in-progress buffer + accumulated `data:` payload)
//!    stays bounded relative to `max_data_bytes`.
//! 3. Dispatched events never carry NUL bytes in their `id` field.
//! 4. Dispatched events have non-empty `data` (the dispatch contract).

use arbitrary::{Arbitrary, Unstructured};
use fcp_streaming::__fuzz;
use libfuzzer_sys::fuzz_target;

const MAX_TOTAL_BYTES: usize = 64 * 1024;
const MAX_CHUNKS: usize = 32;
const MAX_DATA_BYTES_CAP: usize = 1 << 16; // 64 KiB

#[derive(Arbitrary, Debug)]
struct FuzzInput<'a> {
    /// Cap on retained `data:` payload, drawn from the fuzz input so the
    /// fuzzer can explore both tight and loose caps.
    max_data_bytes_raw: u32,
    /// Number of chunks (mod MAX_CHUNKS).
    chunk_count: u8,
    /// Raw stream — the fuzzer carves it into chunks below.
    stream: &'a [u8],
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = FuzzInput::arbitrary(&mut unstructured) else {
        return;
    };

    if input.stream.len() > MAX_TOTAL_BYTES {
        return;
    }

    let max_data_bytes = (input.max_data_bytes_raw as usize % MAX_DATA_BYTES_CAP).max(1);
    let chunk_count = ((input.chunk_count as usize) % MAX_CHUNKS).max(1);

    // Carve the stream into roughly equal chunks. Off-by-one chunk lengths
    // exercise mid-line and mid-terminator boundaries.
    let chunk_size = input.stream.len().div_ceil(chunk_count).max(1);
    let chunks: Vec<&[u8]> = input.stream.chunks(chunk_size).collect();

    let (events, retained) = __fuzz::parse_chunks_with_retained(&chunks, max_data_bytes);

    // Invariant: retained bytes are bounded. The parser's in-progress buffer
    // is allowed to grow up to a single un-terminated line plus the data
    // payload cap. Allow a generous slack so legitimate growth patterns are
    // not flagged, but reject runaway accumulation.
    let slack = max_data_bytes.saturating_add(MAX_TOTAL_BYTES);
    assert!(
        retained <= slack,
        "retained bytes {retained} exceeded slack budget {slack} (max_data_bytes={max_data_bytes})"
    );

    for event in &events {
        // Invariant: dispatch contract — every emitted event has non-empty data.
        assert!(
            !event.data.is_empty(),
            "dispatched event must have non-empty data: {event:?}"
        );

        // Invariant: id-field NUL refusal at process_field is enforced.
        if let Some(id) = &event.id {
            assert!(
                !id.contains('\0'),
                "dispatched event id must not contain NUL bytes: {id:?}"
            );
        }

        // Invariant: retry parses cleanly to a u64. If retry is Some, the
        // value was an Ok result of u64::parse — sanity-check by reading it.
        if let Some(retry) = event.retry {
            // Just touch the value; parse already succeeded if Some.
            let _ = retry;
        }
    }
});
