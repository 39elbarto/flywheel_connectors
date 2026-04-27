#![no_main]

//! Fuzz target for `to_canonical_cbor` `MAX_CANONICAL_OBJECT_BYTES`
//! boundary at the encoder layer (lib.rs:397-409).
//!
//! `to_canonical_cbor` caps the output at `MAX_CANONICAL_OBJECT_BYTES`
//! (64 MiB, RFC 8949 §4.2 size limit). Distinct from
//! `store_validate_structure` (k7w71) which tests this at the
//! StoredObject layer — this is the bare encoder boundary.
//!
//! A regression that dropped the size cap would let an attacker flood
//! downstream allocators with arbitrarily large canonical bytes, or
//! pass a > 64 MiB encoded payload through the canonical-encoding
//! gate that downstream verifiers (e.g. `CanonicalSerializer`,
//! `decode_canonical_cbor`) rely on.
//!
//! Properties asserted:
//!
//!   1. **Under-cap accept**: `bytes.len() ≤ MAX_CANONICAL_OBJECT_BYTES`
//!      MUST succeed (when other constraints aren't violated).
//!   2. **Over-cap reject**: an encoded value whose canonical bytes
//!      would exceed `MAX_CANONICAL_OBJECT_BYTES` MUST trip
//!      `PayloadTooLarge` with `(len, max)` matching the actual sizes.
//!
//!   Once-gated regression anchor:
//!     A `Value::Bytes(vec![0; MAX_CANONICAL_OBJECT_BYTES])` encodes to
//!     ~MAX+5 bytes (5-byte length prefix for u32-ranged length), which
//!     exceeds MAX. The encoder MUST trip `PayloadTooLarge` rather than
//!     return the oversized output.

use arbitrary::{Arbitrary, Unstructured};
use ciborium::value::Value;
use fcp_cbor::{MAX_CANONICAL_OBJECT_BYTES, SerializationError, to_canonical_cbor};
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

static MAX_OBJECT_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    /// Length of byte string to construct, capped at a safe fuzz size
    /// well under MAX. Boundary cases are anchored once-gated.
    seed_len: u32,
}

const FUZZ_MAX_LEN: usize = 1024 * 1024; // 1 MiB

fuzz_target!(|data: &[u8]| {
    MAX_OBJECT_ANCHOR.call_once(assert_max_object_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    let len = (input.seed_len as usize) % FUZZ_MAX_LEN;
    let value = Value::Bytes(vec![0u8; len]);

    // ── PROPERTY 1: under-cap accept ──────────────────────────────────
    let bytes = to_canonical_cbor(&value).expect("under-cap value MUST encode");
    assert!(
        bytes.len() <= MAX_CANONICAL_OBJECT_BYTES,
        "encoded length {} exceeds MAX_CANONICAL_OBJECT_BYTES {}",
        bytes.len(),
        MAX_CANONICAL_OBJECT_BYTES
    );
});

/// Once-gated anchor exercising the over-cap rejection path. Run once
/// per process so the 64 MiB allocation only happens once.
fn assert_max_object_anchored() {
    // Build a Value::Bytes of exactly MAX bytes — the canonical encoding
    // adds a length-prefix header (5 bytes for a 64 MiB byte string),
    // pushing the total past MAX_CANONICAL_OBJECT_BYTES.
    //
    // 64 MiB allocation only at the once-gated anchor — kept off the
    // per-iteration fuzz path to avoid burning fuzz budget.
    let value = Value::Bytes(vec![0u8; MAX_CANONICAL_OBJECT_BYTES]);
    match to_canonical_cbor(&value) {
        Err(SerializationError::PayloadTooLarge { len, max }) => {
            assert_eq!(
                max, MAX_CANONICAL_OBJECT_BYTES,
                "ANCHOR: PayloadTooLarge.max ({max}) ≠ MAX_CANONICAL_OBJECT_BYTES ({MAX_CANONICAL_OBJECT_BYTES})"
            );
            assert!(
                len > MAX_CANONICAL_OBJECT_BYTES,
                "ANCHOR: PayloadTooLarge.len ({len}) does not exceed MAX_CANONICAL_OBJECT_BYTES"
            );
        }
        Err(other) => panic!(
            "ANCHOR REGRESSION: oversized encode produced {other:?}; expected PayloadTooLarge"
        ),
        Ok(bytes) => panic!(
            "ANCHOR REGRESSION: to_canonical_cbor accepted a Value::Bytes of {} bytes \
             (encoded to {} bytes, MAX = {}) — encoder size cap at lib.rs:401-405 \
             dropped; downstream allocators can be flooded",
            MAX_CANONICAL_OBJECT_BYTES,
            bytes.len(),
            MAX_CANONICAL_OBJECT_BYTES
        ),
    }

    // Acceptance counterpart: a value safely under the cap MUST encode.
    let safe_value = Value::Bytes(vec![0u8; 1024]);
    let bytes = to_canonical_cbor(&safe_value).expect("ANCHOR: safe-size value must encode");
    assert!(bytes.len() < MAX_CANONICAL_OBJECT_BYTES);
}
