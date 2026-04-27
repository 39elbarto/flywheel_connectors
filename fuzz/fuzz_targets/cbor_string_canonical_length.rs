#![no_main]

//! Fuzz target for CBOR text/byte-string canonical length encoding per
//! RFC 8949 §4.2.1.
//!
//! Major Type 2 (byte strings, head 0x40-0x5b) and Major Type 3 (text
//! strings, head 0x60-0x7b) MUST be emitted in shortest-form. The
//! length-prefix table:
//!   - len ∈ [0, 23]            → 1 + len bytes (embedded length)
//!   - len ∈ [24, 255]          → 2 + len bytes (0x78/0x58 + 1 byte len)
//!   - len ∈ [256, 65535]       → 3 + len bytes (0x79/0x59 + 2 bytes)
//!   - len ∈ [65536, u32::MAX]  → 5 + len bytes (0x7a/0x5a + 4 bytes)
//!
//! Existing `cbor_int_canonical_length` (lwzfk) covers integer length
//! boundaries but NOT string length encoding. A regression to
//! longer-than-shortest length encodings would let attackers smuggle
//! non-canonical wire forms past the canonical encoding gate.
//!
//! Properties asserted:
//!
//!   1. **Text string length boundary**: `Value::Text(s)` of length n
//!      encodes to the documented (1+n / 2+n / 3+n / 5+n) bytes.
//!   2. **Byte string length boundary**: `Value::Bytes(b)` of length n
//!      encodes to the documented (1+n / 2+n / 3+n / 5+n) bytes.
//!   3. **Head-byte major-type binding**: text head ∈ 0x60-0x7b, byte
//!      head ∈ 0x40-0x5b.
//!   4. **Ciborium round-trip**: decode → re-encode preserves bytes.
//!
//!   Once-gated regression anchors (exact bytes for boundary lengths):
//!     Text: ""→0x60; "a"*23→0x77 + 23 bytes; "a"*24→0x78 0x18 + 24 bytes;
//!           "a"*255→0x78 0xff + 255 bytes; "a"*256→0x79 0x01 0x00 + 256.
//!     Bytes: []→0x40; [0]*23→0x57 + 23 bytes; [0]*24→0x58 0x18 + 24 bytes;
//!            [0]*255→0x58 0xff + 255; [0]*256→0x59 0x01 0x00 + 256.

use arbitrary::{Arbitrary, Unstructured};
use ciborium::value::Value;
use fcp_cbor::to_canonical_cbor;
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

const MAX_LEN: usize = 16 * 1024;

static STRING_LEN_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    range_disc: u8,
    seed: u32,
    /// 0 = text, 1 = bytes.
    is_text: bool,
}

fn pick_len(disc: u8, seed: u32) -> usize {
    match disc % 4 {
        0 => (seed as usize) % 24,                     // [0, 23]
        1 => 24 + ((seed as usize) % (256 - 24)),      // [24, 255]
        2 => 256 + ((seed as usize) % (65_536 - 256)), // [256, 65535] (capped at MAX_LEN)
        _ => 65_536,                                   // [65536, ...]
    }
}

fn expected_text_byte_count(n: usize) -> usize {
    let header_len = if n <= 23 {
        1
    } else if n <= 255 {
        2
    } else if n <= 65_535 {
        3
    } else if n <= u32::MAX as usize {
        5
    } else {
        9
    };
    header_len + n
}

fuzz_target!(|data: &[u8]| {
    STRING_LEN_ANCHOR.call_once(assert_string_length_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    let len = pick_len(input.range_disc, input.seed).min(MAX_LEN);

    let value = if input.is_text {
        Value::Text("a".repeat(len))
    } else {
        Value::Bytes(vec![0u8; len])
    };

    let bytes = to_canonical_cbor(&value).expect("encode string");
    let expected = expected_text_byte_count(len);
    assert_eq!(
        bytes.len(),
        expected,
        "{} of length {len} encoded to {} bytes; expected {expected}",
        if input.is_text { "Text" } else { "Bytes" },
        bytes.len()
    );

    // ── PROPERTY 3: head-byte major-type binding ─────────────────────
    let head = bytes[0];
    let major = head >> 5;
    let expected_major = if input.is_text { 3 } else { 2 };
    assert_eq!(
        major,
        expected_major,
        "head byte 0x{head:02x} has major type {major}; expected {expected_major} for {}",
        if input.is_text { "Text" } else { "Bytes" }
    );

    // ── PROPERTY 4: ciborium round-trip ──────────────────────────────
    let decoded: Value = ciborium::from_reader(&bytes[..]).expect("ciborium decode");
    match (&decoded, &value) {
        (Value::Text(d), Value::Text(o)) => assert_eq!(d, o, "Text round-trip"),
        (Value::Bytes(d), Value::Bytes(o)) => assert_eq!(d, o, "Bytes round-trip"),
        _ => panic!("type-tag drift: encoded {:?}, decoded {:?}", value, decoded),
    }
});

/// Once-gated regression anchors verifying exact bytes at each
/// length-prefix boundary for both text and byte strings.
fn assert_string_length_anchored() {
    fn assert_bytes(value: &Value, expected_prefix: &[u8], expected_total_len: usize) {
        let bytes = to_canonical_cbor(value).expect("anchor encode");
        assert_eq!(
            bytes.len(),
            expected_total_len,
            "ANCHOR: encoded {value:?} to {} bytes; expected {expected_total_len}",
            bytes.len()
        );
        assert_eq!(
            &bytes[..expected_prefix.len()],
            expected_prefix,
            "ANCHOR REGRESSION: encoded prefix {:?} != expected {:?} for {value:?}",
            &bytes[..expected_prefix.len()],
            expected_prefix
        );
    }

    // Text boundary anchors.
    assert_bytes(&Value::Text(String::new()), &[0x60], 1);
    assert_bytes(&Value::Text("a".repeat(23)), &[0x77], 24);
    assert_bytes(&Value::Text("a".repeat(24)), &[0x78, 0x18], 26);
    assert_bytes(&Value::Text("a".repeat(255)), &[0x78, 0xff], 257);
    assert_bytes(&Value::Text("a".repeat(256)), &[0x79, 0x01, 0x00], 259);
    assert_bytes(
        &Value::Text("a".repeat(65_535)),
        &[0x79, 0xff, 0xff],
        65_538,
    );

    // Byte string boundary anchors.
    assert_bytes(&Value::Bytes(vec![]), &[0x40], 1);
    assert_bytes(&Value::Bytes(vec![0u8; 23]), &[0x57], 24);
    assert_bytes(&Value::Bytes(vec![0u8; 24]), &[0x58, 0x18], 26);
    assert_bytes(&Value::Bytes(vec![0u8; 255]), &[0x58, 0xff], 257);
    assert_bytes(&Value::Bytes(vec![0u8; 256]), &[0x59, 0x01, 0x00], 259);
    assert_bytes(
        &Value::Bytes(vec![0u8; 65_535]),
        &[0x59, 0xff, 0xff],
        65_538,
    );
}
