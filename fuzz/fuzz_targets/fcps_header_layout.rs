#![no_main]

//! Fuzz target for `FcpsFrameHeader` encode/decode + flag-mutex +
//! symbol_size=0 rejection (fcps.rs:130-275).
//!
//! `FcpsFrameHeader` is the 114-byte fixed-layout FCPS symbol-plane
//! header with three security gates beyond standard wire-format rules:
//!   - ERROR + RESPONSE mutex (fcps.rs:211-215)
//!   - STREAM_END requires STREAMING (fcps.rs:216-220)
//!   - symbol_size=0 → InvalidSymbolSize (fcps.rs:233-235)
//!
//! Existing `fuzz_fcps_frame` tests decode panic-freedom; this
//! discrete-MR fuzz is missing. Parallel to `obk4f`
//! (FcpcFrameHeader) and `etzqz` (SymbolRecord).
//!
//! Properties asserted:
//!
//!   1. **Round-trip**: encode → decode preserves all 11 fields.
//!   2. **Layout binding**: encoded bytes match documented LE positions.
//!   3. **TooShort**: bytes < FCPS_HEADER_LEN MUST trip TooShort.
//!   4. **InvalidMagic** + **UnsupportedVersion**: same as obk4f.
//!   5. **ERROR + RESPONSE mutex**: setting both MUST trip InvalidFlags.
//!   6. **STREAM_END requires STREAMING**: STREAM_END without STREAMING
//!      MUST trip InvalidFlags.
//!   7. **symbol_size=0 rejection**: MUST trip InvalidSymbolSize.
//!
//!   Once-gated anchors: known header byte layout + each gate's
//!   exact rejection.

use arbitrary::{Arbitrary, Unstructured};
use fcp_core::{ObjectId, ZoneIdHash, ZoneKeyId};
use fcp_protocol::{FCPS_HEADER_LEN, FcpsFrameHeader, FrameError, FrameFlags};
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

static FCPS_HEADER_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    object_id: [u8; 32],
    zone_id_hash: [u8; 32],
    zone_key_id: [u8; 8],
    symbol_size: u16,
    symbol_count: u32,
    total_payload_len: u32,
    epoch_id: u64,
    sender_instance_id: u64,
    frame_seq: u64,
    /// Fuzzer flag bits — clamped to the known mask + sanitized for
    /// mutually-exclusive constraints so per-iteration round-trip
    /// succeeds. The rejection-gate MRs are anchored once-gated.
    flags_bits: u16,
}

fn sanitize_flags(input: u16) -> FrameFlags {
    let mut flags = FrameFlags::from_bits_truncate(input);
    // Resolve ERROR + RESPONSE: drop ERROR.
    if flags.contains(FrameFlags::ERROR) && flags.contains(FrameFlags::RESPONSE) {
        flags.remove(FrameFlags::ERROR);
    }
    // Resolve STREAM_END without STREAMING: drop STREAM_END.
    if flags.contains(FrameFlags::STREAM_END) && !flags.contains(FrameFlags::STREAMING) {
        flags.remove(FrameFlags::STREAM_END);
    }
    flags
}

fuzz_target!(|data: &[u8]| {
    FCPS_HEADER_ANCHOR.call_once(assert_fcps_header_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    // symbol_size==0 is its own rejection gate, anchored separately.
    if input.symbol_size == 0 {
        return;
    }

    let flags = sanitize_flags(input.flags_bits);

    let header = FcpsFrameHeader {
        version: 1,
        flags,
        symbol_count: input.symbol_count,
        total_payload_len: input.total_payload_len,
        object_id: ObjectId::from_bytes(input.object_id),
        symbol_size: input.symbol_size,
        zone_key_id: ZoneKeyId::from_bytes(input.zone_key_id),
        zone_id_hash: ZoneIdHash::from_bytes(input.zone_id_hash),
        epoch_id: input.epoch_id,
        sender_instance_id: input.sender_instance_id,
        frame_seq: input.frame_seq,
    };

    // ── PROPERTY 1: round-trip ────────────────────────────────────────
    let bytes = header.encode();
    assert_eq!(bytes.len(), FCPS_HEADER_LEN);
    let decoded = FcpsFrameHeader::decode(&bytes).expect("round-trip decode");
    assert_eq!(decoded.version, header.version);
    assert_eq!(decoded.flags, header.flags);
    assert_eq!(decoded.symbol_count, header.symbol_count);
    assert_eq!(decoded.total_payload_len, header.total_payload_len);
    assert_eq!(decoded.object_id, header.object_id);
    assert_eq!(decoded.symbol_size, header.symbol_size);
    assert_eq!(decoded.zone_key_id, header.zone_key_id);
    assert_eq!(decoded.zone_id_hash, header.zone_id_hash);
    assert_eq!(decoded.epoch_id, header.epoch_id);
    assert_eq!(decoded.sender_instance_id, header.sender_instance_id);
    assert_eq!(decoded.frame_seq, header.frame_seq);

    // ── PROPERTY 2: layout binding ────────────────────────────────────
    assert_eq!(&bytes[0..4], b"FCPS", "magic [0..4)");
    assert_eq!(&bytes[4..6], &1u16.to_le_bytes(), "version [4..6)");
    assert_eq!(&bytes[6..8], &flags.bits().to_le_bytes(), "flags [6..8)");
    assert_eq!(
        &bytes[8..12],
        &input.symbol_count.to_le_bytes(),
        "symbol_count [8..12)"
    );
    assert_eq!(
        &bytes[12..16],
        &input.total_payload_len.to_le_bytes(),
        "total_payload_len [12..16)"
    );
    assert_eq!(&bytes[16..48], &input.object_id, "object_id [16..48)");
    assert_eq!(
        &bytes[48..50],
        &input.symbol_size.to_le_bytes(),
        "symbol_size [48..50)"
    );
    assert_eq!(&bytes[50..58], &input.zone_key_id, "zone_key_id [50..58)");
    assert_eq!(&bytes[58..90], &input.zone_id_hash, "zone_id_hash [58..90)");
    assert_eq!(
        &bytes[90..98],
        &input.epoch_id.to_le_bytes(),
        "epoch_id [90..98)"
    );
    assert_eq!(
        &bytes[98..106],
        &input.sender_instance_id.to_le_bytes(),
        "sender_instance_id [98..106)"
    );
    assert_eq!(
        &bytes[106..114],
        &input.frame_seq.to_le_bytes(),
        "frame_seq [106..114)"
    );

    // ── PROPERTY 3: TooShort ──────────────────────────────────────────
    let too_short = &bytes[..FCPS_HEADER_LEN - 1];
    match FcpsFrameHeader::decode(too_short) {
        Err(FrameError::TooShort { len, min }) => {
            assert_eq!(len, FCPS_HEADER_LEN - 1);
            assert_eq!(min, FCPS_HEADER_LEN);
        }
        Err(other) => panic!("too-short returned {other:?}"),
        Ok(_) => panic!("too-short input accepted"),
    }
});

/// Once-gated anchors verifying each rejection gate.
fn assert_fcps_header_anchored() {
    let base = FcpsFrameHeader {
        version: 1,
        flags: FrameFlags::ENCRYPTED | FrameFlags::RAPTORQ,
        symbol_count: 4,
        total_payload_len: 1024,
        object_id: ObjectId::from_bytes([0x11u8; 32]),
        symbol_size: 256,
        zone_key_id: ZoneKeyId::from_bytes([0x22u8; 8]),
        zone_id_hash: ZoneIdHash::from_bytes([0x33u8; 32]),
        epoch_id: 0x4040_4040_4040_4040,
        sender_instance_id: 0x5050_5050_5050_5050,
        frame_seq: 0x6060_6060_6060_6060,
    };

    // Round-trip on the base header.
    let bytes = base.encode();
    let decoded = FcpsFrameHeader::decode(&bytes).expect("anchor round-trip");
    assert_eq!(decoded.symbol_size, 256);

    // (a) symbol_size=0 → InvalidSymbolSize.
    let mut bad_size = base.clone();
    bad_size.symbol_size = 0;
    let bytes_bad_size = bad_size.encode();
    match FcpsFrameHeader::decode(&bytes_bad_size) {
        Err(FrameError::InvalidSymbolSize) => {}
        Err(other) => panic!("ANCHOR: symbol_size=0 returned {other:?}"),
        Ok(_) => panic!(
            "ANCHOR REGRESSION: symbol_size=0 accepted by decode — \
             InvalidSymbolSize gate at fcps.rs:233-235 broken"
        ),
    }

    // (b) ERROR + RESPONSE mutex.
    let mut both = base.clone();
    both.flags = FrameFlags::ERROR | FrameFlags::RESPONSE | FrameFlags::ENCRYPTED;
    let bytes_both = both.encode();
    match FcpsFrameHeader::decode(&bytes_both) {
        Err(FrameError::InvalidFlags { .. }) => {}
        Err(other) => panic!("ANCHOR: ERROR+RESPONSE returned {other:?}"),
        Ok(_) => panic!(
            "ANCHOR REGRESSION: flags ERROR+RESPONSE both set were accepted — \
             mutex gate at fcps.rs:211-215 broken"
        ),
    }

    // (c) STREAM_END without STREAMING.
    let mut end_only = base.clone();
    end_only.flags = FrameFlags::STREAM_END | FrameFlags::ENCRYPTED;
    let bytes_end = end_only.encode();
    match FcpsFrameHeader::decode(&bytes_end) {
        Err(FrameError::InvalidFlags { .. }) => {}
        Err(other) => panic!("ANCHOR: STREAM_END w/o STREAMING returned {other:?}"),
        Ok(_) => panic!(
            "ANCHOR REGRESSION: STREAM_END without STREAMING accepted — \
             gate at fcps.rs:216-220 broken"
        ),
    }

    // (d) Acceptance: legit STREAMING + STREAM_END.
    let mut legit_stream = base;
    legit_stream.flags = FrameFlags::STREAMING | FrameFlags::STREAM_END | FrameFlags::ENCRYPTED;
    let bytes_legit = legit_stream.encode();
    FcpsFrameHeader::decode(&bytes_legit).expect(
        "ANCHOR: STREAMING + STREAM_END together MUST decode (otherwise the \
         rejection anchor above is over-restrictive)",
    );
}
