#![no_main]

//! Round-trip fuzz target for fcp-protocol framing.
//!
//! Property: for every input that `decode` accepts, the frame produced by
//! `decode(bytes) → encode → decode` is semantically equal to `decode(bytes)`.
//! This catches:
//!
//!   * silent drift between encoder and decoder (fields read in one byte order
//!     but written in another),
//!   * lossy round-trips that leak unknown flag bits, length claims, or
//!     padding between frame instances,
//!   * encoder panics on structurally-valid-but-weird decoded frames.
//!
//! Byte-exact input equality is **not** asserted because `FrameFlags::
//! from_bits_truncate` deliberately drops reserved bits — the decoder is
//! authoritative, and the invariant we care about is that re-encoding is
//! idempotent under `decode`.
//!
//! Three frame types are fuzzed side-by-side from a single corpus entry so
//! the fuzzer can share coverage signal across the related parsers.

use fcp_protocol::{
    FCPC_HEADER_LEN, FCPS_HEADER_LEN, FcpcFrame, FcpcFrameHeader, FcpsFrame, FcpsFrameHeader,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 64 * 1024;
const FCPS_MAX_MTU: usize = 64 * 1024;
const FCPC_MAX_PAYLOAD: usize = 4 * 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    // ── FCPS header ───────────────────────────────────────────────────────
    // The header has a fixed 114-byte size, so we slice the first 114 bytes.
    // Decoded header → encoded back must be byte-identical because the header
    // encoder writes every field we decoded and there is no padding.
    if data.len() >= FCPS_HEADER_LEN
        && let Ok(header) = FcpsFrameHeader::decode(&data[..FCPS_HEADER_LEN])
    {
        let reencoded = header.encode();

        // Re-decode the re-encoded header: MUST succeed and MUST yield a
        // header that re-encodes to the same bytes (idempotent).
        let redecoded =
            FcpsFrameHeader::decode(&reencoded).expect("re-encoded FCPS header must re-decode");
        assert_eq!(
            reencoded,
            redecoded.encode(),
            "FCPS header round-trip not idempotent"
        );
    }

    // ── FCPS frame ────────────────────────────────────────────────────────
    if let Ok(frame) = FcpsFrame::decode(data, FCPS_MAX_MTU) {
        // `encode` returns `Err(LengthMismatch)` when the header's claimed
        // payload length diverges from the actual symbol payload. A frame
        // that decoded successfully must have matched lengths (decode calls
        // `validate_frame_lengths`), so encode is expected to succeed.
        let reencoded = frame.encode().expect(
            "FcpsFrame that decoded successfully must re-encode — encode refused a valid frame",
        );

        let redecoded = FcpsFrame::decode(&reencoded, FCPS_MAX_MTU)
            .expect("re-encoded FcpsFrame must re-decode");
        assert_eq!(frame, redecoded, "FcpsFrame round-trip lost information");

        // Stronger invariant: once we have stabilized through one full cycle,
        // the encoder is byte-deterministic, so re-encoding again produces
        // identical bytes. Any divergence points at non-deterministic order,
        // stray padding, or uninitialized-memory leakage.
        let reencoded2 = redecoded.encode().expect("second encode must succeed");
        assert_eq!(
            reencoded, reencoded2,
            "FcpsFrame encode is not deterministic across equal inputs"
        );
    }

    // ── FCPC header ───────────────────────────────────────────────────────
    if data.len() >= FCPC_HEADER_LEN
        && let Ok(header) = FcpcFrameHeader::decode(&data[..FCPC_HEADER_LEN])
    {
        let reencoded = header.encode();
        let redecoded =
            FcpcFrameHeader::decode(&reencoded).expect("re-encoded FCPC header must re-decode");
        assert_eq!(
            reencoded,
            redecoded.encode(),
            "FCPC header round-trip not idempotent"
        );
    }

    // ── FCPC frame ────────────────────────────────────────────────────────
    if let Ok(frame) = FcpcFrame::decode_with_limit(data, FCPC_MAX_PAYLOAD) {
        let reencoded = frame.encode();

        // FCPC decode requires `bytes.len() == FCPC_HEADER_LEN + claimed +
        // FCPC_TAG_LEN`. The encoder produces exactly that, so re-decode
        // must succeed.
        let redecoded = FcpcFrame::decode_with_limit(&reencoded, FCPC_MAX_PAYLOAD)
            .expect("re-encoded FcpcFrame must re-decode");
        assert_eq!(frame, redecoded, "FcpcFrame round-trip lost information");

        // And re-encode is byte-deterministic.
        assert_eq!(
            reencoded,
            redecoded.encode(),
            "FcpcFrame encode is not deterministic across equal inputs"
        );
    }
});
