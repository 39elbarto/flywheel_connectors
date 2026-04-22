//! FCPS Frame Fuzz Target (flywheel_connectors-1n78.12 / br-gh0j7).
//!
//! Fuzzes FCPS symbol-plane frame parsing including:
//! - Header decoding (magic, version, flags, lengths, object_id, zone IDs)
//! - Symbol record parsing
//! - Full frame decoding with MTU enforcement
//!
//! Goals:
//!   1. No panics on arbitrary input (crash-resistance).
//!   2. **Semantic invariants** on accepted frames (bead gh0j7):
//!      header fields agree with the decoded frame, lengths are
//!      consistent, and accepted frames round-trip stably through
//!      encode → decode.

#![no_main]

use fcp_protocol::{FCPS_HEADER_LEN, FcpsFrame, FcpsFrameHeader, FrameFlags, SymbolRecord};
use libfuzzer_sys::fuzz_target;

/// Maximum MTU for fuzz testing (64 KiB is generous).
const FUZZ_MTU: usize = 65536;

fuzz_target!(|data: &[u8]| {
    // Crash-resistance: header decoding, symbol record parsing across
    // representative symbol sizes, and frame decoding under MTU must all
    // never panic on arbitrary input.
    let _ = FcpsFrameHeader::decode(data);

    for symbol_size in [1u16, 64, 128, 256, 512, 1024, 2048] {
        let _ = SymbolRecord::decode(data, symbol_size);
    }

    // Fuzz frame decoding across MTU limits so the ExceedsMtu gate is
    // also exercised (including MTU=0 which must uniformly reject).
    for limit in [0usize, 64, FCPS_HEADER_LEN, 4096, FUZZ_MTU] {
        let _ = FcpsFrame::decode(data, limit);
    }

    // FrameFlags::from_bits_truncate must be idempotent — truncating an
    // already-truncated flag set must be a no-op. A regression that
    // dropped bits conditionally would desynchronize decode(encode(f))
    // against f.
    if data.len() >= 2 {
        let flags_bits = u16::from_le_bytes([data[0], data[1]]);
        let once = FrameFlags::from_bits_truncate(flags_bits);
        let twice = FrameFlags::from_bits_truncate(once.bits());
        assert_eq!(
            once, twice,
            "FrameFlags::from_bits_truncate must be idempotent",
        );
    }

    // ───────────────────────────────────────────────────────────────
    // Semantic invariants for accepted frames (br-gh0j7).
    //
    // The prior fuzz body only proved "no panic on arbitrary input."
    // Every invariant below is asserted only on the success branch, so
    // malformed / garbage inputs still exercise the error paths without
    // spurious assertion pressure.
    // ───────────────────────────────────────────────────────────────
    let Ok(frame) = FcpsFrame::decode(data, FUZZ_MTU) else {
        return;
    };

    // (c) Length-field consistency.
    //
    // `FcpsFrame::decode` runs `validate_frame_lengths` before returning
    // Ok and then consumes exactly `header.symbol_count` symbol records
    // of size `SYMBOL_RECORD_OVERHEAD + header.symbol_size`. After decode
    // the following invariants therefore MUST hold:
    //
    //   * `frame.symbols.len() == header.symbol_count as usize`
    //   * `sum(symbol.wire_size()) == header.total_payload_len as usize`
    //
    // A regression that accepted a frame with mismatched length fields
    // would break every downstream reader that trusts the header.
    assert_eq!(
        frame.symbols.len(),
        frame.header.symbol_count as usize,
        "decoded symbol count must equal header.symbol_count",
    );
    let computed_payload_len: usize = frame.symbols.iter().map(SymbolRecord::wire_size).sum();
    assert_eq!(
        computed_payload_len, frame.header.total_payload_len as usize,
        "sum of symbol wire sizes must equal header.total_payload_len",
    );

    // Every symbol's data segment must match the header's declared
    // symbol_size exactly. SymbolRecord::decode enforces this at parse
    // time, but pinning it post-decode catches a class of bugs where a
    // future zero-copy path accepts ragged symbol payloads.
    for symbol in &frame.symbols {
        assert_eq!(
            symbol.data.len(),
            frame.header.symbol_size as usize,
            "symbol.data.len() must equal header.symbol_size",
        );
    }

    // (a) Round-trip structural equality. Accepted frames MUST re-decode
    // (after re-encoding) to a byte-equal struct. This catches bugs
    // where decode normalizes the frame but encode doesn't, or vice
    // versa.
    //
    //     let Ok(frame) = decode(&data, mtu) else { return; };
    //     let re = encode(&frame)?;
    //     assert_eq!(decode(&re, mtu)?, frame);
    let re_encoded = frame
        .encode()
        .expect("frame that just decoded cleanly must re-encode without LengthMismatch");
    let redecoded = FcpsFrame::decode(&re_encoded, FUZZ_MTU)
        .expect("frame we just re-encoded must decode under the same MTU");
    assert_eq!(
        redecoded, frame,
        "decode(encode(frame)) must be structurally identical to the original",
    );

    // (b) Untruncated flags produce the same struct as truncated ones
    // only when truncation is semantic-preserving. `FcpsFrameHeader::
    // decode` passes the on-wire u16 at bytes 6..8 through
    // `from_bits_truncate`, so byte-identical re-encoding of the header
    // range is conditional on the on-wire flag bits having carried no
    // unknown bits. When that condition holds, `encode` MUST reproduce
    // the original header bytes verbatim; when it doesn't, the
    // structural equality from (a) still holds but the raw header
    // bytes legitimately differ at [6..8].
    //
    // `data.len() >= FCPS_HEADER_LEN` is guaranteed because the decoder
    // already returned Ok.
    let wire_flags_bits = u16::from_le_bytes([data[6], data[7]]);
    if wire_flags_bits == frame.header.flags.bits() {
        assert_eq!(
            &re_encoded[..FCPS_HEADER_LEN],
            &data[..FCPS_HEADER_LEN],
            "encode must reproduce original header bytes when the on-wire flags \
             were already semantic-preserving (no unknown bits)",
        );
    }

    // Header-vs-frame agreement. The standalone header decoder and the
    // full-frame decoder MUST agree on every header field for the same
    // input — a regression where one drifts past the other would let a
    // frame-level reader see different flags/lengths/object_id than a
    // header-only reader.
    let header_only = FcpsFrameHeader::decode(data)
        .expect("header decode must succeed on a prefix of a valid full frame");
    assert_eq!(
        header_only, frame.header,
        "standalone header decode must match the full frame's header",
    );

    // Idempotence of the full round-trip: re-encoding the re-decoded
    // frame must produce byte-identical output. A normalization bug
    // that only emerges on the second re-encode (e.g. a mutable-on-
    // decode field that changes) would fail here.
    let re_re_encoded = redecoded
        .encode()
        .expect("second re-encode of a just-decoded frame must succeed");
    assert_eq!(
        re_encoded, re_re_encoded,
        "encode must be deterministic across repeated applications",
    );
});
