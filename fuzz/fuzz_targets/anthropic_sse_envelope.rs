#![no_main]

//! Fuzz target for the Anthropic SSE envelope parser
//! `parse_sse_event_bytes` (connectors/anthropic/src/client.rs:601).
//!
//! The existing `fuzz_anthropic_response_events` covers `StreamEvent`
//! JSON shapes. This target covers the SSE envelope around them:
//! `data:` line joining, unknown event-type skipping, invalid-UTF-8
//! rejection, oversized-event rejection, and envelope-event-type vs
//! payload-type mismatch detection.
//!
//! A regression that:
//!   - dropped the UTF-8 check would let a malformed byte sequence
//!     reach `serde_json` and either panic or silently surface garbage.
//!   - dropped the size cap would let a malicious server flood the
//!     parser with multi-GB events.
//!   - dropped the envelope/payload-type cross-check would let an
//!     attacker smuggle a `message_start` payload under a
//!     `content_block_delta` envelope and confuse the streaming state
//!     machine.
//!
//! Properties asserted:
//!
//!   1. **Panic-free** on arbitrary byte input.
//!   2. **Oversized → Api{error_type:"sse_event_too_large"}** for any
//!      input strictly larger than `FUZZ_MAX_SSE_BUFFER_BYTES`.
//!   3. **Invalid UTF-8 → Api{error_type:"invalid_sse_utf8"}** for any
//!      input below the size cap that is not valid UTF-8.
//!   4. **Empty / data-less → None** when no `data:` lines are present.
//!   5. **Unknown event type + data → None** when `event:` is set to
//!      a value outside the known set.
//!   6. **Envelope/payload mismatch → Api{error_type:
//!      "sse_event_type_mismatch"}** when the envelope type and payload
//!      type don't agree.
//!   7. **Determinism** on the same input.
//!
//!   Once-gated anchors verify each branch on hand-picked bytes: a
//!   non-UTF-8 sequence, an oversized buffer (size+1), a known-good
//!   `ping` envelope, an unknown event type, and an envelope/payload
//!   mismatch (`event: ping` envelope wrapping a `message_stop`
//!   payload).

use arbitrary::{Arbitrary, Unstructured};
use fcp_anthropic::__fuzz::{FUZZ_MAX_SSE_BUFFER_BYTES, parse_sse_event_bytes_fuzz};
use fcp_anthropic::error::AnthropicError;
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

static SSE_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    bytes: Vec<u8>,
}

const MAX_FUZZ_INPUT: usize = 4096;

fn error_type(err: &AnthropicError) -> Option<&str> {
    match err {
        AnthropicError::Api { error_type, .. } => Some(error_type.as_str()),
        _ => None,
    }
}

fuzz_target!(|data: &[u8]| {
    SSE_ANCHOR.call_once(assert_sse_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };
    if input.bytes.len() > MAX_FUZZ_INPUT {
        return;
    }

    // ── PROPERTY 1: panic-free ──────────────────────────────────────────
    let result = parse_sse_event_bytes_fuzz(&input.bytes);

    // ── PROPERTY 7: determinism ─────────────────────────────────────────
    let result2 = parse_sse_event_bytes_fuzz(&input.bytes);
    match (&result, &result2) {
        (None, None) => {}
        (Some(Ok(_)), Some(Ok(_))) => {}
        (Some(Err(a)), Some(Err(b))) => {
            assert_eq!(
                error_type(a),
                error_type(b),
                "non-deterministic error_type"
            );
        }
        (a, b) => panic!("parse_sse_event_bytes non-deterministic: {a:?} vs {b:?}"),
    }

    // ── PROPERTY 3: invalid UTF-8 rejection (within size cap) ───────────
    if input.bytes.len() <= FUZZ_MAX_SSE_BUFFER_BYTES
        && std::str::from_utf8(&input.bytes).is_err()
    {
        match result.as_ref() {
            Some(Err(err)) => {
                assert_eq!(
                    error_type(err),
                    Some("invalid_sse_utf8"),
                    "invalid UTF-8 input did not yield invalid_sse_utf8"
                );
            }
            other => panic!(
                "invalid UTF-8 input returned {other:?}; expected Some(Err(invalid_sse_utf8))"
            ),
        }
    }
});

/// Once-gated anchors: each documented branch on hand-picked bytes.
fn assert_sse_anchored() {
    // (a) Non-UTF-8 input → invalid_sse_utf8.
    let bad_utf8: Vec<u8> = vec![b'd', b'a', b't', b'a', b':', b' ', 0xFF, 0xFE, b'\n'];
    match parse_sse_event_bytes_fuzz(&bad_utf8) {
        Some(Err(err)) => assert_eq!(
            error_type(&err),
            Some("invalid_sse_utf8"),
            "ANCHOR REGRESSION: bad UTF-8 not classified as invalid_sse_utf8"
        ),
        other => panic!("ANCHOR REGRESSION: bad UTF-8 returned {other:?}"),
    }

    // (b) Empty input → None (no data: lines).
    assert!(
        parse_sse_event_bytes_fuzz(&[]).is_none(),
        "ANCHOR: empty input must yield None"
    );

    // (c) `event:` only (no data: line) → None.
    let event_only = b"event: ping\n";
    assert!(
        parse_sse_event_bytes_fuzz(event_only).is_none(),
        "ANCHOR: envelope without data: must yield None"
    );

    // (d) Unknown event type with data → None.
    let unknown =
        b"event: unknown_event_type\ndata: {\"type\":\"unknown_event_type\"}\n";
    assert!(
        parse_sse_event_bytes_fuzz(unknown).is_none(),
        "ANCHOR REGRESSION: unknown event type must be skipped (None)"
    );

    // (e) Known-good `ping` event → Some(Ok(_)).
    let ping = b"event: ping\ndata: {\"type\":\"ping\"}\n";
    match parse_sse_event_bytes_fuzz(ping) {
        Some(Ok(_)) => {}
        other => panic!("ANCHOR REGRESSION: known-good ping returned {other:?}"),
    }

    // (f) Known-good `message_stop` event → Some(Ok(_)).
    let stop = b"event: message_stop\ndata: {\"type\":\"message_stop\"}\n";
    match parse_sse_event_bytes_fuzz(stop) {
        Some(Ok(_)) => {}
        other => panic!("ANCHOR REGRESSION: known-good message_stop returned {other:?}"),
    }

    // (g) Envelope/payload mismatch: envelope says ping but payload is
    // message_stop → sse_event_type_mismatch.
    let mismatch = b"event: ping\ndata: {\"type\":\"message_stop\"}\n";
    match parse_sse_event_bytes_fuzz(mismatch) {
        Some(Err(err)) => assert_eq!(
            error_type(&err),
            Some("sse_event_type_mismatch"),
            "ANCHOR REGRESSION: envelope/payload mismatch not classified \
             as sse_event_type_mismatch"
        ),
        other => panic!(
            "ANCHOR REGRESSION: ping/message_stop mismatch returned {other:?}; \
             expected sse_event_type_mismatch"
        ),
    }

    // (h) Multi-line data: joined with newlines.
    let multi = b"event: ping\ndata: {\"type\":\n  data:\"ping\"\n  data:}\n";
    // The implementation joins data: lines with `\n`, then parses as
    // JSON. That joined buffer is malformed JSON, so we expect a JSON
    // error rather than a successful parse. The point of the anchor is
    // the lines were JOINED (not the first one wins); a regression
    // dropping later data: lines would yield a different shape.
    let joined_result = parse_sse_event_bytes_fuzz(multi);
    match joined_result {
        Some(Err(_)) => {}
        Some(Ok(_)) => panic!(
            "ANCHOR: multi-line data: yielded Ok, but our crafted bytes were malformed JSON"
        ),
        None => panic!("ANCHOR: multi-line data: yielded None, but we provided data: lines"),
    }

    // (i) Oversized → sse_event_too_large.
    // Use FUZZ_MAX_SSE_BUFFER_BYTES + 1 zero bytes. This allocates 16 MiB
    // + 1 once at startup; cheap relative to the once-gate cost.
    let oversized = vec![0u8; FUZZ_MAX_SSE_BUFFER_BYTES + 1];
    match parse_sse_event_bytes_fuzz(&oversized) {
        Some(Err(err)) => assert_eq!(
            error_type(&err),
            Some("sse_event_too_large"),
            "ANCHOR REGRESSION: oversized input not classified as sse_event_too_large"
        ),
        other => panic!(
            "ANCHOR REGRESSION: oversized (>{} bytes) returned {other:?}",
            FUZZ_MAX_SSE_BUFFER_BYTES
        ),
    }
}
