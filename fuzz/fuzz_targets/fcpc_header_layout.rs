#![no_main]

//! Fuzz target for `FcpcFrameHeader` encode/decode round-trip + layout
//! binding (fcpc.rs:89-152).
//!
//! `FcpcFrameHeader` is the 36-byte fixed-layout FCPC header:
//!   magic   [0..4)   = b"FCPC"
//!   version [4..6)   u16 LE  (must == FCPC_VERSION = 1)
//!   session_id [6..22) (16 bytes)
//!   seq     [22..30) u64 LE
//!   flags   [30..32) u16 LE  (must be a subset of FcpcFrameFlags::all())
//!   len     [32..36) u32 LE
//!
//! Existing `fuzz_fcpc_frame` tests decode panic-freedom; `fcpc_seal_open`
//! (4cka5) covers the AEAD layer. Header round-trip + per-byte-position
//! layout is covered transitively but NOT as a discrete MR.
//!
//! Properties asserted:
//!
//!   1. **Round-trip**: encode → decode preserves all 5 fields.
//!   2. **Layout binding**: encoded bytes match documented LE positions.
//!   3. **InvalidMagic**: wrong magic prefix MUST trip InvalidMagic.
//!   4. **UnsupportedVersion**: version != FCPC_VERSION MUST trip
//!      UnsupportedVersion.
//!   5. **TooShort**: bytes < FCPC_HEADER_LEN MUST trip TooShort.
//!
//!   Once-gated anchors verify exact byte positions for a known header.

use arbitrary::{Arbitrary, Unstructured};
use fcp_protocol::{FCPC_HEADER_LEN, FcpcError, FcpcFrameFlags, FcpcFrameHeader, MeshSessionId};
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

static FCPC_HEADER_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    session_id: [u8; 16],
    seq: u64,
    flags_bits: u16,
    len: u32,
}

fuzz_target!(|data: &[u8]| {
    FCPC_HEADER_ANCHOR.call_once(assert_fcpc_header_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    // Use only flag bits within the known mask to make round-trip well-defined.
    let flags = FcpcFrameFlags::from_bits_truncate(input.flags_bits);

    let header = FcpcFrameHeader {
        version: 1, // FCPC_VERSION
        session_id: MeshSessionId(input.session_id),
        seq: input.seq,
        flags,
        len: input.len,
    };

    // ── PROPERTY 1: round-trip ────────────────────────────────────────
    let bytes = header.encode();
    assert_eq!(
        bytes.len(),
        FCPC_HEADER_LEN,
        "encoded len != FCPC_HEADER_LEN"
    );

    let decoded = FcpcFrameHeader::decode(&bytes).expect("encode→decode round-trip");
    assert_eq!(decoded.version, header.version, "round-trip version");
    assert_eq!(
        decoded.session_id, header.session_id,
        "round-trip session_id"
    );
    assert_eq!(decoded.seq, header.seq, "round-trip seq");
    assert_eq!(decoded.flags, header.flags, "round-trip flags");
    assert_eq!(decoded.len, header.len, "round-trip len");

    // ── PROPERTY 2: layout binding ────────────────────────────────────
    assert_eq!(&bytes[0..4], b"FCPC", "magic position [0..4)");
    assert_eq!(
        &bytes[4..6],
        &1u16.to_le_bytes(),
        "version LE position [4..6)"
    );
    assert_eq!(
        &bytes[6..22],
        &input.session_id,
        "session_id position [6..22)"
    );
    assert_eq!(
        &bytes[22..30],
        &input.seq.to_le_bytes(),
        "seq LE position [22..30)"
    );
    assert_eq!(
        &bytes[30..32],
        &flags.bits().to_le_bytes(),
        "flags LE position [30..32)"
    );
    assert_eq!(
        &bytes[32..36],
        &input.len.to_le_bytes(),
        "len LE position [32..36)"
    );

    // ── PROPERTY 3: InvalidMagic ──────────────────────────────────────
    let mut bad_magic = bytes;
    bad_magic[0] ^= 0x01; // 'F' → 'G'
    match FcpcFrameHeader::decode(&bad_magic) {
        Err(FcpcError::InvalidMagic { .. }) => {}
        Err(other) => panic!("bad magic returned {other:?}; expected InvalidMagic"),
        Ok(_) => panic!("bad magic accepted by decode"),
    }

    // ── PROPERTY 4: UnsupportedVersion ────────────────────────────────
    let mut bad_version = bytes;
    bad_version[4] = 0x99; // version=0x99 (or whatever the LSB is) ≠ 1
    bad_version[5] = 0x99;
    if u16::from_le_bytes([bad_version[4], bad_version[5]]) != 1 {
        match FcpcFrameHeader::decode(&bad_version) {
            Err(FcpcError::UnsupportedVersion { .. }) => {}
            Err(other) => panic!("bad version returned {other:?}; expected UnsupportedVersion"),
            Ok(_) => panic!("bad version accepted by decode"),
        }
    }

    // ── PROPERTY 5: TooShort ──────────────────────────────────────────
    let too_short = &bytes[..FCPC_HEADER_LEN - 1];
    match FcpcFrameHeader::decode(too_short) {
        Err(FcpcError::TooShort { len, min }) => {
            assert_eq!(len, FCPC_HEADER_LEN - 1);
            assert_eq!(min, FCPC_HEADER_LEN);
        }
        Err(other) => panic!("too-short returned {other:?}; expected TooShort"),
        Ok(_) => panic!(
            "too-short input ({} < {FCPC_HEADER_LEN}) accepted",
            FCPC_HEADER_LEN - 1
        ),
    }
});

/// Once-gated anchor: known header byte-for-byte layout.
fn assert_fcpc_header_anchored() {
    let header = FcpcFrameHeader {
        version: 1,
        session_id: MeshSessionId([0x11u8; 16]),
        seq: 0x0807_0605_0403_0201,
        flags: FcpcFrameFlags::ENCRYPTED,
        len: 0x1213_1415,
    };
    let bytes = header.encode();

    // Magic.
    assert_eq!(
        &bytes[0..4],
        b"FCPC",
        "ANCHOR REGRESSION: FCPC magic byte sequence wrong"
    );
    // Version 1 LE.
    assert_eq!(
        &bytes[4..6],
        &[0x01, 0x00],
        "ANCHOR REGRESSION: version LE wrong"
    );
    // Session id (all 0x11).
    assert_eq!(
        &bytes[6..22],
        &[0x11u8; 16],
        "ANCHOR REGRESSION: session_id position wrong"
    );
    // Seq LE.
    assert_eq!(
        &bytes[22..30],
        &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        "ANCHOR REGRESSION: seq LE position wrong"
    );
    // Flags = ENCRYPTED = 0x0001 LE.
    assert_eq!(
        &bytes[30..32],
        &[0x01, 0x00],
        "ANCHOR REGRESSION: flags LE position wrong"
    );
    // Len 0x1213_1415 LE.
    assert_eq!(
        &bytes[32..36],
        &[0x15, 0x14, 0x13, 0x12],
        "ANCHOR REGRESSION: len LE position wrong"
    );

    // Round-trip.
    let decoded = FcpcFrameHeader::decode(&bytes).expect("ANCHOR: round-trip decode");
    assert_eq!(decoded.session_id.0, [0x11u8; 16]);
    assert_eq!(decoded.seq, 0x0807_0605_0403_0201);
    assert_eq!(decoded.flags, FcpcFrameFlags::ENCRYPTED);
    assert_eq!(decoded.len, 0x1213_1415);
}
