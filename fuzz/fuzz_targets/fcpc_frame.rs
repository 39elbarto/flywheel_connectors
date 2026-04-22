//! FCPC Frame Fuzz Target (flywheel_connectors-1n78.13 / br-j5iby).
//!
//! Fuzzes FCPC control-plane frame parsing including:
//! - Header decoding (magic, version, session_id, seq, flags, length)
//! - Full frame decoding with payload limit enforcement
//! - Frame flags parsing
//!
//! Goals:
//!   1. No panics on arbitrary input (crash-resistance).
//!   2. **Semantic invariants** on accepted frames (bead j5iby): header
//!      fields agree with the decoded frame, lengths are consistent,
//!      and accepted frames round-trip stably through encode → decode.

#![no_main]

use fcp_protocol::{FCPC_HEADER_LEN, FCPC_TAG_LEN, FcpcFrame, FcpcFrameFlags, FcpcFrameHeader};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz header decoding — tests magic validation, version check,
    // session_id parsing, seq/flags/len fields.
    let _ = FcpcFrameHeader::decode(data);

    // Fuzz frame decoding with the default limit (4 MiB) and several
    // smaller limits so the PayloadTooLarge gate is also exercised.
    for limit in [0, 64, 256, 1024, 4096, 65536] {
        let _ = FcpcFrame::decode_with_limit(data, limit);
    }

    // Fuzz flags parsing and verify from_bits_truncate is idempotent —
    // truncating an already-truncated flag set must be a no-op. A
    // regression that dropped bits conditionally would desynchronize
    // decode(encode(f)) against f.
    if data.len() >= 2 {
        let flags_bits = u16::from_le_bytes([data[0], data[1]]);
        let once = FcpcFrameFlags::from_bits_truncate(flags_bits);
        let twice = FcpcFrameFlags::from_bits_truncate(once.bits());
        assert_eq!(
            once, twice,
            "FcpcFrameFlags::from_bits_truncate must be idempotent",
        );
    }

    // ───────────────────────────────────────────────────────────────
    // Semantic invariants for accepted frames (br-j5iby).
    //
    // The original fuzz body only proved "no panic on arbitrary input."
    // Every invariant below is asserted only on the success branch, so
    // malformed / garbage inputs still exercise the error paths without
    // spurious assertion pressure.
    // ───────────────────────────────────────────────────────────────
    let Ok(frame) = FcpcFrame::decode(data) else {
        return;
    };

    // (c) Length consistency. FcpcFrame::decode_with_limit checks
    // `bytes.len() == FCPC_HEADER_LEN + header.len + FCPC_TAG_LEN`
    // before returning Ok, so the ciphertext payload it built MUST be
    // exactly `header.len` bytes. A regression that assembled a frame
    // with mismatched length fields would be caught here instead of
    // silently producing frames whose encode() emits a different byte
    // count than their decoder expected.
    assert_eq!(
        frame.header.len as usize,
        frame.ciphertext.len(),
        "decoded frame header.len must equal ciphertext.len()",
    );
    assert_eq!(
        frame.tag.len(),
        FCPC_TAG_LEN,
        "tag length must equal FCPC_TAG_LEN",
    );

    // (a) Round-trip structural equality. Accepted frames MUST
    // re-decode (after re-encoding) to a byte-equal struct. This
    // catches bugs where decode normalizes the frame but encode
    // doesn't, or vice-versa.
    //
    //     let Ok(frame) = decode(&data) else { return; };
    //     let re = encode(&frame);
    //     assert_eq!(decode(&re).unwrap(), frame);
    let re_encoded = frame.encode();
    let redecoded = FcpcFrame::decode(&re_encoded).expect("frame we just encoded must decode");
    assert_eq!(
        redecoded, frame,
        "decode(encode(frame)) must be structurally identical to the original",
    );

    // (b) Untruncated flags produce the same struct as truncated ones
    // only when truncation is semantic-preserving. Concretely: the
    // decoder passes the on-wire u16 through `from_bits_truncate`, so
    // any unknown bits are dropped. Byte-identical re-encoding of the
    // *header* is therefore conditional on the on-wire flags having
    // carried no unknown bits. When that condition holds, encode MUST
    // reproduce the original header bytes verbatim; when it doesn't,
    // the structural equality above still holds but the raw header
    // bytes legitimately differ at [30..32].
    //
    // `data.len() >= FCPC_HEADER_LEN + FCPC_TAG_LEN` is guaranteed
    // because the decoder already returned Ok.
    let wire_flags_bits = u16::from_le_bytes([data[30], data[31]]);
    if wire_flags_bits == frame.header.flags.bits() {
        assert_eq!(
            &re_encoded[..FCPC_HEADER_LEN],
            &data[..FCPC_HEADER_LEN],
            "encode must reproduce original header bytes when the on-wire flags \
             were already semantic-preserving (no unknown bits)",
        );
    }

    // Header-vs-frame agreement. The standalone header decoder and the
    // full-frame decoder MUST agree on every header field for the same
    // input — a regression where one drifts past the other would let
    // a frame-level reader see different flags/seq/len than a
    // header-only reader.
    let header_only = FcpcFrameHeader::decode(data)
        .expect("header decode must succeed on a prefix of a valid full frame");
    assert_eq!(
        header_only, frame.header,
        "standalone header decode must match the full frame's header",
    );

    // Idempotence of the full round-trip: re-encoding the re-decoded
    // frame must produce byte-identical output. A normalization bug
    // that only emerges on second re-encode (e.g. a mutable-on-decode
    // field that changes) would fail here.
    let re_re_encoded = redecoded.encode();
    assert_eq!(
        re_encoded, re_re_encoded,
        "encode must be deterministic across repeated applications",
    );
});
