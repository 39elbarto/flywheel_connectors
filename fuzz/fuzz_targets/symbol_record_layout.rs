#![no_main]

//! Fuzz target for `fcp_protocol::SymbolRecord` encode/decode + layout
//! binding (fcps.rs:275-348).
//!
//! `SymbolRecord` is the per-symbol wire format inside FCPS frames:
//!   `esi (u32 LE) || k (u16 LE) || data || auth_tag (16 bytes)`
//!
//! Existing `fuzz_fcps_frame` tests `SymbolRecord::decode` panic-
//! freedom but NOT the round-trip / layout binding / encode_to
//! agreement as discrete MRs. A regression in any of the byte
//! positions would silently corrupt symbol routing (esi mismatch),
//! reconstruction threshold (k drift), or AEAD verification
//! (auth_tag misaligned).
//!
//! Properties asserted:
//!
//!   1. **Round-trip**: encode → decode(symbol_size) returns a record
//!      with byte-equal data + auth_tag and equal esi + k.
//!   2. **wire_size identity**: `wire_size() == encode().len() ==
//!      SYMBOL_RECORD_OVERHEAD + data.len()`.
//!   3. **encode_to agreement**: `encode_to(buf)` produces the same
//!      bytes as `encode()` and is a pure append.
//!   4. **Layout binding**: encoded bytes at fixed positions match the
//!      documented LE encodings (esi at [0..4), k at [4..6), data at
//!      [6..6+symbol_size), auth_tag at last 16 bytes).
//!   5. **TooShort rejection**: `decode(bytes, symbol_size)` with
//!      `bytes.len() < SYMBOL_RECORD_OVERHEAD + symbol_size` MUST trip
//!      `FrameError::TooShort` with correct (len, min) fields.
//!
//!   Once-gated regression anchors:
//!     (a) Known record (esi=0x12345678, k=0x9ABC, data=[0xAA;8],
//!         auth_tag=[0xBB;16]) round-trips byte-for-byte and matches
//!         the exact documented layout.
//!     (b) decode at exact boundary len = OVERHEAD + symbol_size - 1
//!         MUST trip TooShort.

use arbitrary::{Arbitrary, Unstructured};
use fcp_protocol::{FrameError, SYMBOL_RECORD_OVERHEAD, SymbolRecord};
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

const AUTH_TAG_LEN: usize = 16;

static SYMBOL_RECORD_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    esi: u32,
    k: u16,
    data: Vec<u8>,
    auth_tag: [u8; AUTH_TAG_LEN],
}

const MAX_DATA: usize = 4 * 1024;

fuzz_target!(|data: &[u8]| {
    SYMBOL_RECORD_ANCHOR.call_once(assert_symbol_record_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };
    if input.data.len() > MAX_DATA {
        return;
    }

    let record = SymbolRecord {
        esi: input.esi,
        k: input.k,
        data: input.data.clone(),
        auth_tag: input.auth_tag,
    };

    // ── PROPERTY 2: wire_size identity ────────────────────────────────
    assert_eq!(
        record.wire_size(),
        SYMBOL_RECORD_OVERHEAD + input.data.len(),
        "wire_size != OVERHEAD + data.len()"
    );

    // ── PROPERTY 3: encode_to agreement ───────────────────────────────
    let bytes = record.encode();
    assert_eq!(
        bytes.len(),
        record.wire_size(),
        "encode().len() != wire_size()"
    );

    let mut prefilled = vec![0xCDu8; 5];
    record.encode_to(&mut prefilled);
    assert_eq!(
        prefilled[5..],
        bytes[..],
        "encode_to does not append the same bytes as encode"
    );
    assert_eq!(
        &prefilled[..5],
        &[0xCDu8; 5],
        "encode_to mutated the prefix of an existing buffer"
    );

    // ── PROPERTY 4: layout binding ────────────────────────────────────
    if bytes.len() >= 6 {
        assert_eq!(
            &bytes[0..4],
            &input.esi.to_le_bytes(),
            "esi position [0..4) wrong"
        );
        assert_eq!(
            &bytes[4..6],
            &input.k.to_le_bytes(),
            "k position [4..6) wrong"
        );
        let data_end = 6 + input.data.len();
        assert_eq!(
            &bytes[6..data_end],
            input.data.as_slice(),
            "data position [6..6+len) wrong"
        );
        assert_eq!(
            &bytes[data_end..data_end + AUTH_TAG_LEN],
            &input.auth_tag,
            "auth_tag position (last 16) wrong"
        );
    }

    // Symbol size for decode = data.len() (clamp to u16).
    if input.data.len() > u16::MAX as usize {
        return;
    }
    let symbol_size = input.data.len() as u16;

    // ── PROPERTY 1: round-trip ────────────────────────────────────────
    let decoded = SymbolRecord::decode(&bytes, symbol_size).expect("round-trip decode");
    assert_eq!(decoded.esi, input.esi, "round-trip esi");
    assert_eq!(decoded.k, input.k, "round-trip k");
    assert_eq!(decoded.data, input.data, "round-trip data");
    assert_eq!(decoded.auth_tag, input.auth_tag, "round-trip auth_tag");

    // ── PROPERTY 5: TooShort at boundary ──────────────────────────────
    if !bytes.is_empty() {
        let too_short = &bytes[..bytes.len() - 1];
        match SymbolRecord::decode(too_short, symbol_size) {
            Err(FrameError::TooShort { len, min }) => {
                assert_eq!(len, too_short.len());
                assert_eq!(min, SYMBOL_RECORD_OVERHEAD + symbol_size as usize);
            }
            Err(other) => panic!("too-short returned {other:?}; expected TooShort"),
            Ok(_) => panic!(
                "too-short input (len={}, min={}) accepted",
                too_short.len(),
                SYMBOL_RECORD_OVERHEAD + symbol_size as usize
            ),
        }
    }
});

/// Once-gated regression anchors: exact byte layout per docs.
fn assert_symbol_record_anchored() {
    let record = SymbolRecord {
        esi: 0x1234_5678,
        k: 0x9ABC,
        data: vec![0xAAu8; 8],
        auth_tag: [0xBBu8; AUTH_TAG_LEN],
    };
    let bytes = record.encode();
    assert_eq!(
        bytes.len(),
        SYMBOL_RECORD_OVERHEAD + 8,
        "ANCHOR: wire_size for data.len()=8 is {} != {}",
        bytes.len(),
        SYMBOL_RECORD_OVERHEAD + 8
    );

    // Layout: esi at [0..4) LE, k at [4..6) LE, data at [6..14),
    // auth_tag at [14..30).
    assert_eq!(
        &bytes[0..4],
        &[0x78, 0x56, 0x34, 0x12],
        "ANCHOR REGRESSION: esi LE position [0..4) wrong"
    );
    assert_eq!(
        &bytes[4..6],
        &[0xBC, 0x9A],
        "ANCHOR REGRESSION: k LE position [4..6) wrong"
    );
    assert_eq!(
        &bytes[6..14],
        &[0xAAu8; 8],
        "ANCHOR REGRESSION: data position [6..14) wrong"
    );
    assert_eq!(
        &bytes[14..30],
        &[0xBBu8; 16],
        "ANCHOR REGRESSION: auth_tag position [14..30) wrong"
    );

    // Round-trip.
    let decoded = SymbolRecord::decode(&bytes, 8).expect("ANCHOR: round-trip decode");
    assert_eq!(decoded.esi, 0x1234_5678, "ANCHOR: esi round-trip");
    assert_eq!(decoded.k, 0x9ABC, "ANCHOR: k round-trip");
    assert_eq!(decoded.data, vec![0xAAu8; 8], "ANCHOR: data round-trip");
    assert_eq!(
        decoded.auth_tag, [0xBBu8; AUTH_TAG_LEN],
        "ANCHOR: auth_tag round-trip"
    );

    // Boundary: len = OVERHEAD + 8 - 1 = 29 → TooShort.
    let truncated = &bytes[..bytes.len() - 1];
    match SymbolRecord::decode(truncated, 8) {
        Err(FrameError::TooShort { len, min }) => {
            assert_eq!(len, 29);
            assert_eq!(min, 30);
        }
        Err(other) => panic!("ANCHOR: boundary len=29 returned {other:?}"),
        Ok(_) => panic!(
            "ANCHOR REGRESSION: SymbolRecord::decode accepted len=29 < expected 30 — \
             TooShort gate at fcps.rs:318-322 broken"
        ),
    }
}
