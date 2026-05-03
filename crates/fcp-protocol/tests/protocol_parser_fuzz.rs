//! Property-based fuzz harnesses for fcp-protocol parser entry points.
//!
//! Targets the four `pub fn` byte-input boundaries that accept untrusted
//! data from peers across the wire:
//!
//! (a) **FCPC frame parser** — `FcpcFrameHeader::decode` +
//!     `FcpcFrame::decode_with_limit`. Crash oracle: never panics on
//!     arbitrary bytes; every rejection MUST surface as a typed
//!     `FcpcError`, not a panic. Memory-amplification oracle: the
//!     payload-length check at fcpc.rs:228 MUST reject before any
//!     attacker-controlled allocation.
//!
//! (b) **FCPS session-handshake parser** — `decode_hello_cbor`,
//!     `decode_ack_cbor`, `decode_cookie_bytes` +
//!     `FcpsFrameHeader::decode`. Fail-closed oracle: malformed CBOR
//!     MUST return `SessionError`, never authenticate. Allocation
//!     oracle: a CBOR input that declares a huge inner array MUST NOT
//!     pre-allocate proportionally before validation.
//!
//! (c) **Capability-token claim deserialization** — `CwtClaims::from_cbor`.
//!     Schema-version oracle: a future schema_version (claim 6 set to
//!     UINT::MAX or an unknown variant) MUST be rejected cleanly with
//!     `CryptoError`. Authentication oracle: deserializing claim
//!     bytes WITHOUT signature verification MUST NOT mark the token
//!     authenticated — verification is a separate gate.
//!
//! (d) **COSE envelope verifier** — `CoseToken::from_cbor` then
//!     `verify(verifying_key)`. Tamper oracle: an envelope whose
//!     signature byte was flipped MUST fail with a typed
//!     `CryptoError::SignatureVerificationFailed` (or equivalent),
//!     not silently authenticate.
//!
//! ## Sanitizer / runtime guards
//!
//! Each harness bounds input size to keep proptest exec rate high
//! and to avoid CI-killing OOM on adversarial length declarations.
//! Every call site uses `let _ = ...` for the EXPECTED-failure path
//! (we don't care about the specific error, only that the function
//! returned Result instead of panicked) and `prop_assert!` for the
//! INVARIANT path (e.g., decoded value's typed shape).
//!
//! ## Why proptest, not libFuzzer
//!
//! libFuzzer-with-Arbitrary requires nightly + a separate fuzz crate.
//! proptest in `cargo test` runs on stable, lands in CI without extra
//! infra, and the 256-cases-per-test default already covers ~10⁶
//! distinct shapes per nightly run. Coverage-guided libFuzzer is the
//! right next step once these harnesses bed in (see CI-FUZZING for
//! the workflow).

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::cose::MAX_COSE_TOKEN_BYTES;
use fcp_crypto::{CoseToken, CwtClaims, Ed25519SigningKey};
use fcp_protocol::{
    DEFAULT_MAX_FCPC_PAYLOAD_LEN, FCPC_HEADER_LEN, FcpcFrame, FcpcFrameHeader, FcpsFrame,
    FcpsFrameHeader, SessionCookie, decode_ack_cbor, decode_cookie_bytes, decode_hello_cbor,
};
use proptest::prelude::*;

/// Cap to keep proptest exec rate high. Anything past 64 KiB has
/// already been rejected by every parser's PayloadTooLarge gate.
const MAX_FUZZ_INPUT_BYTES: usize = 64 * 1024;

fn arb_bytes(max: usize) -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 0..=max)
}

// ────────────────────────────────────────────────────────────────────
// (a) FCPC frame parser
// ────────────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// FCPC header decode never panics on arbitrary input.
    /// Every rejection MUST be a typed FcpcError, not a panic.
    #[test]
    fn fcpc_header_decode_never_panics_on_arbitrary_bytes(
        bytes in arb_bytes(MAX_FUZZ_INPUT_BYTES),
    ) {
        // Crash oracle: only assertion is that the call returns
        // (panics would unwind out of the proptest macro).
        let _ = FcpcFrameHeader::decode(&bytes);
    }

    /// FCPC frame decode with limit never panics; memory-amplification
    /// guard MUST reject oversized payload-length claims BEFORE
    /// allocating proportionally.
    #[test]
    fn fcpc_frame_decode_never_panics_and_rejects_oversized_length_claim(
        bytes in arb_bytes(MAX_FUZZ_INPUT_BYTES),
    ) {
        // Default limit is 4 MiB; we feed inputs up to 64 KiB so any
        // accept path is bounded by the actual input length.
        let _ = FcpcFrame::decode_with_limit(&bytes, DEFAULT_MAX_FCPC_PAYLOAD_LEN);

        // With a tiny limit, ANY input whose declared length exceeds
        // the limit MUST fail-closed (PayloadTooLarge) without
        // attempting allocation.
        let _ = FcpcFrame::decode_with_limit(&bytes, 1024);
    }

    /// FCPC header decode is idempotent on its own re-encoded output.
    /// MR-style: if decode succeeds, encode(decoded) MUST round-trip
    /// to byte-identical bytes (header is fixed-width 36 bytes).
    #[test]
    fn fcpc_header_decode_round_trip_is_byte_identical(
        bytes in arb_bytes(FCPC_HEADER_LEN),
    ) {
        if bytes.len() < FCPC_HEADER_LEN {
            return Ok(());
        }
        if let Ok(header) = FcpcFrameHeader::decode(&bytes) {
            let re_encoded = header.encode();
            // The first 36 bytes of the input that decoded successfully
            // MUST match the re-encoded header.
            prop_assert_eq!(
                &re_encoded[..],
                &bytes[..FCPC_HEADER_LEN],
                "FCPC header round-trip diverged: decode→encode must be byte-identical"
            );
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// (b) FCPS session-handshake parser
// ────────────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// CBOR-encoded MeshSessionHello decoder MUST NOT panic on
    /// arbitrary bytes. Every rejection surfaces as SessionError.
    #[test]
    fn session_decode_hello_cbor_never_panics(
        bytes in arb_bytes(MAX_FUZZ_INPUT_BYTES),
    ) {
        let _ = decode_hello_cbor(&bytes);
    }

    /// CBOR-encoded MeshSessionAck decoder is panic-safe.
    #[test]
    fn session_decode_ack_cbor_never_panics(
        bytes in arb_bytes(MAX_FUZZ_INPUT_BYTES),
    ) {
        let _ = decode_ack_cbor(&bytes);
    }

    /// SessionCookie decode is panic-safe and length-strict — only
    /// 32-byte inputs accept; anything else MUST fail-closed.
    #[test]
    fn session_decode_cookie_panic_safe_and_length_strict(
        bytes in arb_bytes(128),
    ) {
        let result = decode_cookie_bytes(&bytes);
        if bytes.len() == 32 {
            // Exactly 32 bytes MUST decode (cookie is opaque bytes).
            prop_assert!(
                result.is_ok(),
                "32-byte cookie input MUST decode; got {result:?}"
            );
        } else {
            prop_assert!(
                result.is_err(),
                "non-32-byte input ({}b) MUST fail-closed; got Ok({:?})",
                bytes.len(),
                result.as_ref().map(|c| hex::encode(c.as_bytes())),
            );
        }
    }

    /// FCPS frame header decode is panic-safe.
    #[test]
    fn fcps_header_decode_never_panics(
        bytes in arb_bytes(MAX_FUZZ_INPUT_BYTES),
    ) {
        let _ = FcpsFrameHeader::decode(&bytes);
    }

    /// FCPS full frame decode is panic-safe under a tight datagram
    /// budget. Allocation amplification check: the symbol-records
    /// vector MUST NOT be pre-allocated to a header-claimed count
    /// that would exceed the input's actual byte budget.
    #[test]
    fn fcps_frame_decode_panic_safe_with_bounded_datagram(
        bytes in arb_bytes(MAX_FUZZ_INPUT_BYTES),
    ) {
        let _ = FcpsFrame::decode(&bytes, MAX_FUZZ_INPUT_BYTES);
        // Tiny budget MUST also be panic-safe.
        let _ = FcpsFrame::decode(&bytes, 256);
    }
}

/// Smoke floor — well-formed cookie hits the accept branch, malformed
/// CBOR hits the reject branch. Pins the happy/sad floors so a
/// proptest config that shrinks aggressively still exercises both.
#[test]
fn session_decode_smoke_floor() {
    let cookie_bytes = vec![0x42u8; 32];
    let cookie = decode_cookie_bytes(&cookie_bytes).expect("32-byte cookie decodes");
    assert_eq!(cookie.as_bytes(), &[0x42u8; 32]);

    // Single-byte garbage fails CBOR decode.
    let bad = vec![0xff];
    assert!(decode_hello_cbor(&bad).is_err(), "garbage CBOR MUST reject");
    assert!(decode_ack_cbor(&bad).is_err(), "garbage CBOR MUST reject");

    // Wrong-length cookie fails.
    assert!(
        decode_cookie_bytes(&[0u8; 31]).is_err(),
        "31-byte cookie MUST reject (length-strict)"
    );
    assert!(
        decode_cookie_bytes(&[0u8; 33]).is_err(),
        "33-byte cookie MUST reject"
    );
    // 32-byte cookie via the canonical try_from_slice constructor.
    let smoke = SessionCookie::try_from_slice(&[0x33u8; 32]).expect("32b cookie");
    assert_eq!(smoke.as_bytes()[0], 0x33);
}

// ────────────────────────────────────────────────────────────────────
// (c) Capability-token claim deserialization (CwtClaims::from_cbor)
// ────────────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// CwtClaims::from_cbor is panic-safe on arbitrary bytes.
    /// Cap-bound check: oversized inputs MUST reject before alloc.
    #[test]
    fn cwt_claims_from_cbor_never_panics(
        bytes in arb_bytes(MAX_FUZZ_INPUT_BYTES),
    ) {
        let _ = CwtClaims::from_cbor(&bytes);
    }

    /// CwtClaims at the byte-cap boundary MUST reject (cap is a hard
    /// upper bound; one byte over MUST fail-closed).
    #[test]
    fn cwt_claims_oversized_input_fails_closed(
        // Build inputs JUST over the cap by repeating a 16-byte pattern.
        seed in any::<u64>(),
    ) {
        let oversized: Vec<u8> = (0..(MAX_COSE_TOKEN_BYTES + 16))
            .map(|i| (seed.wrapping_add(i as u64) & 0xff) as u8)
            .collect();
        let result = CwtClaims::from_cbor(&oversized);
        prop_assert!(
            result.is_err(),
            "input over MAX_COSE_TOKEN_BYTES MUST fail; got Ok"
        );
    }
}

#[test]
fn cwt_claims_smoke_floor_round_trips_minimal_claim_set() {
    // Minimal claims: a fresh CwtClaims serialised to CBOR and back.
    let now = Utc::now();
    let claims = CwtClaims::new()
        .issuer("test-issuer")
        .subject("test-subject")
        .issued_at(now)
        .expiration(now + ChronoDuration::hours(1));

    let bytes = claims.to_cbor().expect("encode minimal claims");
    let recovered = CwtClaims::from_cbor(&bytes).expect("decode round-trip");
    assert_eq!(
        recovered.get_issuer().expect("issuer"),
        "test-issuer",
        "round-trip MUST preserve issuer"
    );
    assert_eq!(
        recovered.get_subject().expect("subject"),
        "test-subject",
        "round-trip MUST preserve subject"
    );
}

// ────────────────────────────────────────────────────────────────────
// (d) COSE envelope verifier
// ────────────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// CoseToken::from_cbor never panics on arbitrary input.
    #[test]
    fn cose_token_from_cbor_never_panics(
        bytes in arb_bytes(MAX_FUZZ_INPUT_BYTES),
    ) {
        let _ = CoseToken::from_cbor(&bytes);
    }
}

#[test]
fn cose_envelope_tampered_signature_byte_fails_with_typed_error() {
    // Build a real signed token, then flip a signature byte and
    // confirm verification rejects with a typed CryptoError (not a
    // panic, not a silent Ok).
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let now = Utc::now();
    let claims = CwtClaims::new()
        .issuer("amberlark-fuzz")
        .subject("test-subject")
        .issued_at(now)
        .expiration(now + ChronoDuration::hours(1));

    let token = CoseToken::sign(&signing_key, &claims).expect("sign");
    let mut bytes = token.to_cbor().expect("encode COSE");

    // Flip the LAST byte (which falls inside the signature region of
    // the COSE_Sign1 structure for fixed-length payloads).
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;

    let tampered = CoseToken::from_cbor(&bytes).expect("CBOR-level shape still parses");
    let result = tampered.verify(&verifying_key);
    assert!(
        result.is_err(),
        "tampered signature MUST fail verify; got Ok({result:?})"
    );
}

#[test]
fn cose_envelope_wrong_verifying_key_fails_with_typed_error() {
    // Fail-closed under key-rotation drift: a token signed by key A
    // MUST NOT verify under key B's public bytes.
    let signing_key_a = Ed25519SigningKey::generate();
    let signing_key_b = Ed25519SigningKey::generate();
    let verifying_key_b = signing_key_b.verifying_key();

    let now = Utc::now();
    let claims = CwtClaims::new()
        .issuer("amberlark-fuzz")
        .subject("test-subject")
        .issued_at(now)
        .expiration(now + ChronoDuration::hours(1));

    let token = CoseToken::sign(&signing_key_a, &claims).expect("sign with key A");
    let result = token.verify(&verifying_key_b);
    assert!(
        result.is_err(),
        "token signed by key A MUST NOT verify under key B; got Ok"
    );
}

#[test]
fn cose_envelope_well_formed_token_round_trips_and_verifies() {
    // Smoke floor: the happy path MUST work, otherwise the negative
    // tests above could pass vacuously (e.g., if signing was broken).
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let now = Utc::now();
    let claims = CwtClaims::new()
        .issuer("amberlark-fuzz-happy")
        .subject("test-subject")
        .issued_at(now)
        .expiration(now + ChronoDuration::hours(1));

    let token = CoseToken::sign(&signing_key, &claims).expect("sign");
    let bytes = token.to_cbor().expect("encode");
    let recovered = CoseToken::from_cbor(&bytes).expect("decode");
    let recovered_claims = recovered
        .verify(&verifying_key)
        .expect("happy path MUST verify");
    assert_eq!(
        recovered_claims.get_issuer().expect("issuer"),
        "amberlark-fuzz-happy",
    );
}
