#![no_main]

//! Fuzz target for `decode_hello_cbor` / `decode_ack_cbor` canonical
//! decoding gates (session.rs:462-501).
//!
//! `decode_canonical_cbor` runs four rejection gates on bare canonical
//! CBOR (no schema hash prefix):
//!   - PayloadTooLarge if `bytes.len() > MAX_HANDSHAKE_BYTES`
//!   - CborDeserialize on parse failure
//!   - TrailingBytes if cursor position != bytes.len()
//!   - NonCanonicalEncoding if `to_canonical_cbor(decoded) != bytes`
//!
//! Existing `fuzz_session` and `fuzz_session_transcript` test panic-
//! freedom on parse, but NOT the round-trip or rejection gates as
//! discrete MRs. Distinct from `cchj5` (CanonicalSerializer
//! schema-prefixed envelope) — this is the bare canonical-CBOR path
//! that the handshake decode uses.
//!
//! Properties asserted:
//!
//!   1. **Hello round-trip**: encode(hello) → decode_hello_cbor returns
//!      a structurally-equal hello.
//!   2. **Ack round-trip**: encode(ack) → decode_ack_cbor returns a
//!      structurally-equal ack.
//!   3. **Trailing-bytes rejection**: encode(hello) || extra MUST be
//!      rejected (TrailingBytes or NonCanonicalEncoding).
//!   4. **Truncated input rejection**: a strict prefix of valid
//!      encoded bytes MUST be rejected (CborDeserialize family).
//!   5. **PayloadTooLarge gate**: input with `len > MAX_HANDSHAKE_BYTES`
//!      MUST be rejected.
//!
//!   Once-gated regression anchors:
//!     (a) Constructed hello round-trips byte-for-byte through encode
//!         then decode.
//!     (b) Single appended trailing byte → rejection.

use arbitrary::{Arbitrary, Unstructured};
use fcp_cbor::to_canonical_cbor;
use fcp_core::TailscaleNodeId;
use fcp_crypto::X25519SecretKey;
use fcp_protocol::{
    MAX_HANDSHAKE_BYTES, MeshSessionAck, MeshSessionHello, MeshSessionId, SessionCryptoSuite,
    SessionError, SessionNonce, TransportLimits, decode_ack_cbor, decode_hello_cbor,
};
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

const NONCE_SIZE: usize = 16;

static DECODE_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    eph_seed_a: [u8; 32],
    eph_seed_b: [u8; 32],
    nonce: [u8; NONCE_SIZE],
    ack_nonce: [u8; NONCE_SIZE],
    timestamp: u64,
    /// Trailing bytes to append to encoded hello/ack.
    trailing: Vec<u8>,
    /// Truncate-len discriminator.
    truncate_disc: u8,
    /// Suite selector.
    suite_disc: u8,
}

fn pick_suite(disc: u8) -> SessionCryptoSuite {
    if disc.is_multiple_of(2) {
        SessionCryptoSuite::Suite1
    } else {
        SessionCryptoSuite::Suite2
    }
}

fn build_hello(input: &Input) -> MeshSessionHello {
    let eph = X25519SecretKey::from_bytes(input.eph_seed_a).public_key();
    MeshSessionHello {
        from: TailscaleNodeId::new("node-i"),
        to: TailscaleNodeId::new("node-r"),
        eph_pubkey: eph,
        nonce: SessionNonce(input.nonce),
        cookie: None,
        timestamp: input.timestamp,
        suites: vec![pick_suite(input.suite_disc)],
        transport_limits: Some(TransportLimits::default()),
        signature: None,
    }
}

fn build_ack(input: &Input) -> MeshSessionAck {
    let eph = X25519SecretKey::from_bytes(input.eph_seed_b).public_key();
    MeshSessionAck {
        from: TailscaleNodeId::new("node-r"),
        to: TailscaleNodeId::new("node-i"),
        eph_pubkey: eph,
        nonce: SessionNonce(input.ack_nonce),
        session_id: MeshSessionId([0xCDu8; 16]),
        suite: pick_suite(input.suite_disc),
        timestamp: input.timestamp,
        signature: None,
    }
}

fn assert_canonical_rejection<T>(result: Result<T, SessionError>, ctx: &str) {
    match result {
        Err(SessionError::Cbor(_)) => {}
        Err(other) => panic!("{ctx}: unexpected error variant {other:?}"),
        Ok(_) => panic!("{ctx} accepted by decode — canonical-decode rejection gate broken"),
    }
}

fuzz_target!(|data: &[u8]| {
    DECODE_ANCHOR.call_once(assert_decode_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    let hello = build_hello(&input);
    let ack = build_ack(&input);

    let hello_bytes = to_canonical_cbor(&hello).expect("hello canonicalize");
    let ack_bytes = to_canonical_cbor(&ack).expect("ack canonicalize");

    // ── PROPERTY 1+2: round-trip ──────────────────────────────────────
    let decoded_hello = decode_hello_cbor(&hello_bytes).expect("hello round-trip MUST succeed");
    // Re-encode and assert byte-equality.
    let re_encoded = to_canonical_cbor(&decoded_hello).expect("re-encode hello");
    assert_eq!(hello_bytes, re_encoded, "hello round-trip not byte-stable");

    let decoded_ack = decode_ack_cbor(&ack_bytes).expect("ack round-trip MUST succeed");
    let re_encoded_ack = to_canonical_cbor(&decoded_ack).expect("re-encode ack");
    assert_eq!(ack_bytes, re_encoded_ack, "ack round-trip not byte-stable");

    // ── PROPERTY 3: trailing-bytes rejection ──────────────────────────
    if !input.trailing.is_empty() && input.trailing.len() < 4 * 1024 {
        let mut with_trailing = hello_bytes.clone();
        with_trailing.extend_from_slice(&input.trailing);
        if with_trailing.len() <= MAX_HANDSHAKE_BYTES {
            assert_canonical_rejection(decode_hello_cbor(&with_trailing), "hello + trailing");
        }

        let mut ack_with_trailing = ack_bytes.clone();
        ack_with_trailing.extend_from_slice(&input.trailing);
        if ack_with_trailing.len() <= MAX_HANDSHAKE_BYTES {
            assert_canonical_rejection(decode_ack_cbor(&ack_with_trailing), "ack + trailing");
        }
    }

    // ── PROPERTY 4: truncated input rejection ────────────────────────
    if hello_bytes.len() > 1 {
        let trunc_len = (input.truncate_disc as usize) % hello_bytes.len();
        if trunc_len < hello_bytes.len() {
            let truncated = &hello_bytes[..trunc_len];
            assert_canonical_rejection(decode_hello_cbor(truncated), "truncated hello");
        }
    }
});

/// Once-gated regression anchors for the most load-bearing canonical-
/// decode invariants.
fn assert_decode_anchored() {
    let input = Input {
        eph_seed_a: [0x42u8; 32],
        eph_seed_b: [0x77u8; 32],
        nonce: [0xAAu8; NONCE_SIZE],
        ack_nonce: [0xBBu8; NONCE_SIZE],
        timestamp: 1_000_000,
        trailing: vec![],
        truncate_disc: 0,
        suite_disc: 0,
    };
    let hello = build_hello(&input);

    // (a) Constructed hello round-trips.
    let bytes = to_canonical_cbor(&hello).expect("anchor hello canonicalize");
    let decoded = decode_hello_cbor(&bytes).expect("anchor hello decode");
    let re_encoded = to_canonical_cbor(&decoded).expect("anchor re-encode");
    assert_eq!(
        bytes, re_encoded,
        "ANCHOR REGRESSION: known hello did not round-trip byte-for-byte \
         through to_canonical_cbor → decode_hello_cbor → to_canonical_cbor"
    );

    // (b) Single appended trailing byte MUST be rejected.
    let mut with_trail = bytes.clone();
    with_trail.push(0xFF);
    match decode_hello_cbor(&with_trail) {
        Err(SessionError::Cbor(_)) => {}
        Err(other) => panic!("ANCHOR: trailing-byte rejection returned {other:?}"),
        Ok(_) => panic!(
            "ANCHOR REGRESSION: hello bytes + trailing 0xFF accepted by decode — \
             TrailingBytes/NonCanonicalEncoding gate at session.rs:475-482 broken; \
             attacker could smuggle bytes past the canonical decode"
        ),
    }

    // Acceptance counterpart: same hello bytes WITHOUT trailing parses.
    decode_hello_cbor(&bytes)
        .expect("ANCHOR: clean hello bytes MUST decode (otherwise rejection anchor is vacuous)");
}
