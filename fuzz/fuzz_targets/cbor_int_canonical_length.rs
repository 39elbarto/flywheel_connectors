#![no_main]

//! Fuzz target for CBOR integer canonical-encoding length boundaries
//! per RFC 8949 §4.2.1 (shortest-form requirement).
//!
//! `to_canonical_cbor` MUST emit integers in shortest-form:
//!   - [0, 23]            → 1 byte (head 0x00..0x17 = value)
//!   - [24, 255]          → 2 bytes (head 0x18, then 1-byte value)
//!   - [256, 65535]       → 3 bytes (head 0x19, then 2-byte BE value)
//!   - [65536, u32::MAX]  → 5 bytes (head 0x1a, then 4-byte BE value)
//!   - > u32::MAX         → 9 bytes (head 0x1b, then 8-byte BE value)
//!
//! Negative integers follow the same length table with head bits
//! 0x20-0x3b (Major Type 1 = NegInt).
//!
//! Existing `cbor_float_encoding_edges` (1y12u) covers Float↔Integer
//! type non-aliasing but NOT the integer length-boundary table. A
//! regression that emitted longer-than-shortest forms would let
//! ObjectIds drift across implementations and break the canonical-
//! encoding gate in `CanonicalSerializer::deserialize`.
//!
//! Properties asserted:
//!
//!   1. **u64 length boundary**: each documented range produces the
//!      documented byte count.
//!   2. **i64 negative length boundary**: same for the NegInt major type.
//!   3. **Head-byte verification**: known integer values produce the
//!      documented head bytes.
//!   4. **Ciborium round-trip**: decoding the canonical bytes recovers
//!      the original integer value.
//!
//!   Once-gated regression anchors verifying exact encodings for
//!   boundary values:
//!     u64:  0 → 0x00; 23 → 0x17 (1B);
//!           24 → 0x18 0x18; 255 → 0x18 0xff (2B);
//!           256 → 0x19 0x01 0x00; 65535 → 0x19 0xff 0xff (3B);
//!           65536 → 0x1a 00 01 00 00 (5B);
//!           u32::MAX+1 → 0x1b ... (9B).
//!     i64:  -1 → 0x20; -24 → 0x37 (1B);
//!           -25 → 0x38 0x18; -256 → 0x38 0xff (2B);
//!           -257 → 0x39 0x01 0x00 (3B).

use arbitrary::{Arbitrary, Unstructured};
use fcp_cbor::to_canonical_cbor;
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

static INT_LENGTH_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    /// Discriminator selecting which range to test.
    range_disc: u8,
    /// Seed value within the range.
    seed: u64,
    signed: bool,
}

fn expected_u64_len(n: u64) -> usize {
    if n <= 23 {
        1
    } else if n <= 255 {
        2
    } else if n <= 65_535 {
        3
    } else if n <= u32::MAX as u64 {
        5
    } else {
        9
    }
}

fn expected_i64_len(n: i64) -> usize {
    // CBOR NegInt encodes -1-n; length table same as u64.
    let neg_value: u64 = (-1 - n) as u64;
    expected_u64_len(neg_value)
}

fuzz_target!(|data: &[u8]| {
    INT_LENGTH_ANCHOR.call_once(assert_int_length_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    // Pick a value in a specific range based on range_disc.
    let value: u64 = match input.range_disc % 5 {
        0 => input.seed % 24,                                              // [0, 23]
        1 => 24 + (input.seed % (256 - 24)),                               // [24, 255]
        2 => 256 + (input.seed % (65_536 - 256)),                          // [256, 65535]
        3 => 65_536 + (input.seed % (u32::MAX as u64 - 65_536 + 1)),       // [65536, u32::MAX]
        _ => (u32::MAX as u64 + 1).saturating_add(input.seed % 1_000_000), // > u32::MAX
    };

    if input.signed {
        // ── PROPERTY 2: i64 negative length boundary ─────────────────
        // Build a negative i64 from value (clamped so cast is well-defined).
        let n = i64::try_from(value).unwrap_or(i64::MAX).saturating_neg() - 1;
        // n now ∈ [-(i64::MAX), -1]. Compute expected length from
        // CBOR's NegInt encoding (which uses -1-n).
        let bytes = to_canonical_cbor(&n).expect("encode i64");
        let expected = expected_i64_len(n);
        assert_eq!(
            bytes.len(),
            expected,
            "i64 {n} encoded to {} bytes; expected {expected} per RFC 8949 §4.2.1",
            bytes.len()
        );

        // Round-trip.
        let decoded: i64 = ciborium::from_reader(&bytes[..]).expect("ciborium decode i64");
        assert_eq!(decoded, n, "i64 round-trip lost value");
    } else {
        // ── PROPERTY 1: u64 length boundary ───────────────────────────
        let bytes = to_canonical_cbor(&value).expect("encode u64");
        let expected = expected_u64_len(value);
        assert_eq!(
            bytes.len(),
            expected,
            "u64 {value} encoded to {} bytes; expected {expected} per RFC 8949 §4.2.1",
            bytes.len()
        );

        // Round-trip.
        let decoded: u64 = ciborium::from_reader(&bytes[..]).expect("ciborium decode u64");
        assert_eq!(decoded, value, "u64 round-trip lost value");
    }
});

/// Once-gated anchors verifying exact byte encodings for documented
/// boundary values per RFC 8949 §3.1 / §4.2.1.
fn assert_int_length_anchored() {
    fn assert_encoded<T: serde::Serialize + std::fmt::Display + Copy>(value: T, expected: &[u8]) {
        let bytes = to_canonical_cbor(&value).expect("encode anchor");
        assert_eq!(
            bytes, expected,
            "ANCHOR REGRESSION: to_canonical_cbor({value}) = {bytes:?}; expected {expected:?} \
             per RFC 8949 canonical integer encoding"
        );
    }

    // u64 boundary anchors.
    assert_encoded(0u64, &[0x00]);
    assert_encoded(23u64, &[0x17]);
    assert_encoded(24u64, &[0x18, 0x18]);
    assert_encoded(255u64, &[0x18, 0xff]);
    assert_encoded(256u64, &[0x19, 0x01, 0x00]);
    assert_encoded(65_535u64, &[0x19, 0xff, 0xff]);
    assert_encoded(65_536u64, &[0x1a, 0x00, 0x01, 0x00, 0x00]);
    assert_encoded(u32::MAX as u64, &[0x1a, 0xff, 0xff, 0xff, 0xff]);
    assert_encoded(
        (u32::MAX as u64) + 1,
        &[0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
    );

    // i64 boundary anchors (NegInt major type, head bits 0x20-0x3b).
    // CBOR NegInt(n) encodes the value -1 - n.
    assert_encoded(-1i64, &[0x20]); // -1 → NegInt(0) → 0x20
    assert_encoded(-24i64, &[0x37]); // -24 → NegInt(23) → 0x37
    assert_encoded(-25i64, &[0x38, 0x18]); // -25 → NegInt(24) → 0x38 0x18
    assert_encoded(-256i64, &[0x38, 0xff]); // -256 → NegInt(255) → 0x38 0xff
    assert_encoded(-257i64, &[0x39, 0x01, 0x00]); // -257 → NegInt(256) → 0x39 01 00
    assert_encoded(-65_536i64, &[0x39, 0xff, 0xff]);
    assert_encoded(-65_537i64, &[0x3a, 0x00, 0x01, 0x00, 0x00]);
}
