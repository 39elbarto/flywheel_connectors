#![no_main]

//! Fuzz target for `EncodingDecision::for_payload` Direct/Chunked
//! decision boundary (encode.rs:281).
//!
//! `EncodingDecision::for_payload` decides between in-line RaptorQ
//! encoding (`Direct`) for small payloads and a `ChunkedObjectManifest`
//! split (`Chunked`) for large ones. NOT covered as a discrete unit;
//! `raptorq_roundtrip` exercises the encoder + decoder loop but never
//! the decision branch.
//!
//! A regression that:
//!   - dropped the `requires_chunking` gate would force every payload
//!     through `RaptorQEncoder` — payloads above the chunking threshold
//!     would either OOM the encoder or violate the symbol-count budget.
//!   - dropped the `max_object_size` gate would let an attacker push a
//!     pathological payload through the encode path uncapped.
//!   - swapped Direct/Chunked branches would silently break decoders
//!     that branch on the discriminant.
//!
//! Properties asserted:
//!
//!   1. **Empty payload → Direct** with empty `symbols`.
//!   2. **Oversized payload → PayloadTooLarge** carrying `size ==
//!      payload.len()` and `max == config.max_object_size as usize`.
//!   3. **`requires_chunking` agreement**: when payload size is
//!      non-empty and within `max_object_size`,
//!      `decision.is_chunked() == config.requires_chunking(payload.len())`.
//!   4. **`is_direct` / `is_chunked` complementary**: exactly one is
//!      true.
//!   5. **Direct symbol-size carries config**: for a non-empty Direct
//!      decision, `transmission_info.symbol_size() == config.symbol_size`.
//!   6. **Chunked invariants**: `manifest.chunk_count() == chunks.len()`,
//!      `manifest.len() == payload.len()`, `verify_hash(payload) ==
//!      true`, and `manifest.reconstruct(chunks) == payload`.
//!   7. **Determinism on the discriminant** under repeated calls.
//!
//!   Once-gated anchors verify each branch on hand-picked payload sizes:
//!   empty / small / boundary / chunked / oversized.

use arbitrary::{Arbitrary, Unstructured};
use fcp_raptorq::{EncodeError, EncodingDecision, RaptorQConfig};
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

static DECISION_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    payload: Vec<u8>,
}

const MAX_PAYLOAD: usize = 8 * 1024;

/// Fuzz-friendly config: small thresholds so the fuzzer routinely hits
/// both Direct and Chunked branches without large allocations.
fn fuzz_config() -> RaptorQConfig {
    RaptorQConfig {
        symbol_size: 64,
        repair_ratio_bps: 500,
        max_object_size: 4 * 1024,
        decode_timeout: std::time::Duration::from_secs(10),
        max_chunk_threshold: 512,
        chunk_size: 256,
    }
}

fuzz_target!(|data: &[u8]| {
    DECISION_ANCHOR.call_once(assert_decision_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };
    if input.payload.len() > MAX_PAYLOAD {
        return;
    }

    let config = fuzz_config();
    let result = EncodingDecision::for_payload(&input.payload, &config);

    // ── PROPERTY 2: oversized → PayloadTooLarge ─────────────────────────
    if input.payload.len() > config.max_object_size as usize {
        match result {
            Err(EncodeError::PayloadTooLarge { size, max }) => {
                assert_eq!(size, input.payload.len(), "PayloadTooLarge.size mismatch");
                assert_eq!(
                    max, config.max_object_size as usize,
                    "PayloadTooLarge.max mismatch"
                );
            }
            other => panic!(
                "oversized payload (len={}) returned {other:?}; expected PayloadTooLarge",
                input.payload.len()
            ),
        }
        return;
    }

    let decision = match result {
        Ok(d) => d,
        Err(e) => panic!(
            "for_payload on len={} (within max_object_size {}) returned unexpected error {e:?}",
            input.payload.len(),
            config.max_object_size
        ),
    };

    // ── PROPERTY 4: complementary discriminants ─────────────────────────
    assert_ne!(
        decision.is_direct(),
        decision.is_chunked(),
        "is_direct and is_chunked must be complementary"
    );

    // ── PROPERTY 3: requires_chunking agreement (for non-empty) ─────────
    let expected_chunked =
        !input.payload.is_empty() && config.requires_chunking(input.payload.len());
    assert_eq!(
        decision.is_chunked(),
        expected_chunked,
        "decision branch disagrees with config.requires_chunking({})",
        input.payload.len()
    );

    match &decision {
        EncodingDecision::Direct {
            symbols,
            transmission_info,
        } => {
            if input.payload.is_empty() {
                // ── PROPERTY 1: empty → Direct with empty symbols ──────
                assert!(
                    symbols.is_empty(),
                    "empty payload Direct decision had {} symbols",
                    symbols.len()
                );
            } else {
                // ── PROPERTY 5: Direct.transmission_info.symbol_size ──
                assert_eq!(
                    transmission_info.symbol_size(),
                    config.symbol_size,
                    "Direct.transmission_info.symbol_size diverges from config"
                );
            }
        }
        EncodingDecision::Chunked { manifest, chunks } => {
            // ── PROPERTY 6: Chunked invariants ─────────────────────────
            assert_eq!(
                manifest.chunk_count(),
                chunks.len(),
                "manifest.chunk_count != chunks.len"
            );
            assert_eq!(
                manifest.total_len,
                input.payload.len() as u64,
                "manifest.total_len != payload.len"
            );
            assert!(
                manifest.verify_hash(&input.payload),
                "manifest.verify_hash returned false on the originating payload"
            );
            let reconstructed = manifest
                .reconstruct(chunks)
                .expect("Chunked manifest reconstruct on its own chunks must succeed");
            assert_eq!(
                reconstructed, input.payload,
                "Chunked round-trip lost bytes"
            );
        }
    }

    // ── PROPERTY 7: discriminant determinism ────────────────────────────
    let again = EncodingDecision::for_payload(&input.payload, &config)
        .expect("for_payload repeat on within-bounds payload");
    assert_eq!(
        decision.is_chunked(),
        again.is_chunked(),
        "discriminant flipped between repeated calls"
    );
});

/// Once-gated anchors: explicit branch coverage on hand-picked sizes.
fn assert_decision_anchored() {
    let config = fuzz_config();

    // (a) Empty payload → Direct with empty symbols.
    match EncodingDecision::for_payload(&[], &config).expect("ANCHOR: empty") {
        EncodingDecision::Direct { symbols, .. } => {
            assert!(
                symbols.is_empty(),
                "ANCHOR: empty Direct should have no symbols"
            );
        }
        other => panic!("ANCHOR REGRESSION: empty payload returned {other:?}; expected Direct"),
    }

    // (b) Small payload at threshold-1 → Direct.
    let small = vec![
        0xABu8;
        (config.max_chunk_threshold as usize)
            .saturating_sub(1)
            .max(1)
    ];
    let dec_small = EncodingDecision::for_payload(&small, &config).expect("ANCHOR: small");
    assert!(
        dec_small.is_direct(),
        "ANCHOR REGRESSION: payload at threshold-1 should be Direct"
    );

    // (c) Boundary payload at exactly max_chunk_threshold → still Direct
    // (requires_chunking is strict greater-than).
    let boundary = vec![0xCDu8; config.max_chunk_threshold as usize];
    let dec_boundary = EncodingDecision::for_payload(&boundary, &config).expect("ANCHOR: boundary");
    assert!(
        dec_boundary.is_direct(),
        "ANCHOR REGRESSION: payload at exactly max_chunk_threshold should be Direct \
         (requires_chunking is len > threshold, not >=)"
    );

    // (d) Above-threshold payload → Chunked.
    let large = vec![0xEFu8; config.max_chunk_threshold as usize + 1];
    let dec_large = EncodingDecision::for_payload(&large, &config).expect("ANCHOR: large");
    assert!(
        dec_large.is_chunked(),
        "ANCHOR REGRESSION: payload above max_chunk_threshold should be Chunked"
    );

    // (e) Oversized payload → PayloadTooLarge.
    let huge = vec![0u8; config.max_object_size as usize + 1];
    match EncodingDecision::for_payload(&huge, &config) {
        Err(EncodeError::PayloadTooLarge { size, max }) => {
            assert_eq!(size, huge.len(), "ANCHOR: PayloadTooLarge.size");
            assert_eq!(
                max, config.max_object_size as usize,
                "ANCHOR: PayloadTooLarge.max"
            );
        }
        other => panic!(
            "ANCHOR REGRESSION: oversized payload returned {other:?}; expected PayloadTooLarge"
        ),
    }
}
