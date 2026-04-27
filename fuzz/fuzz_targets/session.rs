//! Session handshake fuzz target (br-abnue).
//!
//! Fuzzes the three wire-facing decoders on the session handshake:
//!   - `decode_hello_cbor` (MeshSessionHello, canonical CBOR)
//!   - `decode_ack_cbor`   (MeshSessionAck,   canonical CBOR)
//!   - `decode_cookie_bytes` (SessionCookie, fixed 32-byte slice)
//!
//! Goals:
//!   1. No panics on arbitrary input (crash-resistance).
//!   2. **Semantic round-trip invariants** on accepted structures
//!      (bead j5iby's sibling — br-abnue). The old body only called the
//!      decoders and discarded every Ok; semantic parser regressions
//!      (e.g. a future non-canonical accept-path, or transcript
//!      derivation that becomes nondeterministic) would have survived.

#![no_main]

use fcp_cbor::to_canonical_cbor;
use fcp_protocol::{SESSION_COOKIE_SIZE, decode_ack_cbor, decode_cookie_bytes, decode_hello_cbor};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // ───────────────────────────────────────────────────────────────
    // MeshSessionHello
    // ───────────────────────────────────────────────────────────────
    if let Ok(hello) = decode_hello_cbor(data) {
        // Canonical-CBOR round-trip. `decode_canonical_cbor` in
        // session.rs:452 explicitly re-encodes the decoded value with
        // `to_canonical_cbor` and rejects inputs that don't match, so
        // every accepted input MUST round-trip byte-for-byte. A
        // regression that weakens the canonicality gate (e.g. relaxes
        // from `canonical != bytes` to a semantic-equality check) would
        // allow two distinct on-wire forms to decode to the same hello
        // — that's exactly the parser-malleability class the NORMATIVE
        // canonical gate exists to close.
        let re_canonical = to_canonical_cbor(&hello)
            .expect("canonically-decoded hello must re-serialize as canonical CBOR");
        assert_eq!(
            re_canonical, data,
            "decode_hello_cbor accepted input differs from its canonical re-encoding",
        );

        // Redecode the re-encoded bytes and require structural
        // equality: the public Serialize/Deserialize contract is what
        // every session peer relies on.
        let round_trip =
            decode_hello_cbor(&re_canonical).expect("canonically re-encoded hello must redecode");
        // MeshSessionHello doesn't derive PartialEq, so compare via the
        // canonical byte-projection (the same projection peers use to
        // recognise the structure on the wire).
        let round_trip_bytes =
            to_canonical_cbor(&round_trip).expect("round-tripped hello must re-canonicalize");
        assert_eq!(
            round_trip_bytes, re_canonical,
            "decode(encode(hello)) must be canonically identical to hello",
        );

        // Transcript determinism. `transcript_bytes()` is what the
        // signature is computed over and what `verify()` recomputes —
        // two calls on the same struct MUST produce byte-identical
        // transcripts or every signed hello breaks signature
        // verification after a round-trip through the decoder.
        let t1 = hello
            .transcript_bytes()
            .expect("hello transcript derivation must succeed on an accepted struct");
        let t2 = hello
            .transcript_bytes()
            .expect("hello transcript derivation must be repeatable");
        assert_eq!(
            t1, t2,
            "MeshSessionHello::transcript_bytes must be deterministic",
        );

        // Transcript carries the spec-level domain separation prefix.
        // A regression that dropped or renamed the prefix would silently
        // let an attacker craft a hello whose transcript collides with
        // some other FCP2 message type's transcript.
        assert!(
            t1.starts_with(b"FCP2-HELLO-V1"),
            "hello transcript must begin with FCP2-HELLO-V1 domain separator",
        );
    }

    // ───────────────────────────────────────────────────────────────
    // MeshSessionAck
    // ───────────────────────────────────────────────────────────────
    if let Ok(ack) = decode_ack_cbor(data) {
        let re_canonical = to_canonical_cbor(&ack)
            .expect("canonically-decoded ack must re-serialize as canonical CBOR");
        assert_eq!(
            re_canonical, data,
            "decode_ack_cbor accepted input differs from its canonical re-encoding",
        );

        let round_trip =
            decode_ack_cbor(&re_canonical).expect("canonically re-encoded ack must redecode");
        let round_trip_bytes =
            to_canonical_cbor(&round_trip).expect("round-tripped ack must re-canonicalize");
        assert_eq!(
            round_trip_bytes, re_canonical,
            "decode(encode(ack)) must be canonically identical to ack",
        );
        // Ack's transcript requires a hello; the property we can assert
        // without one is structural canonicality (above). Transcript-
        // determinism is covered by the hello branch; the ack
        // transcript code path reuses the same `append_cbor` helper.
    }

    // ───────────────────────────────────────────────────────────────
    // SessionCookie — fixed 32-byte opaque tag
    // ───────────────────────────────────────────────────────────────
    if let Ok(cookie) = decode_cookie_bytes(data) {
        // Cookies are raw 32-byte opaque tags. Any accepted input
        // MUST be byte-identical to the cookie's internal bytes, and
        // the decoder MUST reject anything other than exactly
        // `SESSION_COOKIE_SIZE` bytes (see session.rs:227). The length
        // assertion catches a regression that starts padding or
        // truncating on the way in — the identity assertion catches
        // any future in-line transformation (e.g. accidental
        // re-hashing).
        assert_eq!(
            data.len(),
            SESSION_COOKIE_SIZE,
            "decode_cookie_bytes accepted input of the wrong length",
        );
        assert_eq!(
            cookie.as_bytes().as_slice(),
            data,
            "decoded cookie bytes must equal the input bytes verbatim",
        );

        // Round-trip: re-decode from the cookie's own serialization.
        let again = decode_cookie_bytes(cookie.as_bytes().as_slice())
            .expect("cookie must decode from its own bytes");
        assert_eq!(
            again.as_bytes(),
            cookie.as_bytes(),
            "decode(cookie.as_bytes()) must equal cookie",
        );
    }
});
