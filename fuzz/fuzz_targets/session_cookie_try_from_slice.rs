#![no_main]

//! Fuzz target for `SessionCookie::try_from_slice` length gate +
//! `decode_cookie_bytes` agreement (session.rs:240-247, 507-509).
//!
//! `SessionCookie::try_from_slice` accepts only 32-byte (`SESSION_COOKIE_SIZE`)
//! input and returns `SessionError::InvalidCookieLength { len }` for
//! anything else, where `len` is the exact rejected length.
//! `decode_cookie_bytes` is a thin wrapper that MUST agree byte-for-byte.
//!
//! NOT covered as a discrete MR: existing `session_cookie_binding`
//! exercises `try_from_slice` only on already-32-byte tampered cookies,
//! never on the rejection path.
//!
//! A regression that:
//!   - accepted a non-32 slice would let stateless-cookie verification
//!     consume an attacker-truncated buffer.
//!   - dropped the rejected `len` from the error would defeat
//!     observability for malformed-cookie debugging.
//!   - made `decode_cookie_bytes` diverge from `try_from_slice` would
//!     create two cookie-parsing APIs with different gates — the
//!     hello-retry cookie path uses `decode_cookie_bytes`.
//!
//! Properties asserted:
//!
//!   1. **Length-32 acceptance**: a 32-byte slice → `Ok(SessionCookie)`
//!      whose `as_bytes()` equals the input verbatim.
//!   2. **Length-not-32 rejection**: any other length → `Err(InvalidCookieLength {
//!      len })` with `len == input.len()`.
//!   3. **Wrapper agreement**: `decode_cookie_bytes(b)` returns the same
//!      `Result` (Ok bytes equal, Err discriminants and len equal) as
//!      `SessionCookie::try_from_slice(b)`.
//!   4. **Round-trip identity**: `try_from_slice(c.as_bytes()) == c`.
//!   5. **JSON serde round-trip** via `bytes32_serde` preserves bytes.
//!   6. **Canonical-CBOR round-trip** via `bytes32_serde` preserves bytes.
//!
//!   Once-gated anchors verify the boundary lengths (0, 1, 31, 32, 33, 64).

use arbitrary::{Arbitrary, Unstructured};
use fcp_cbor::to_canonical_cbor;
use fcp_protocol::{SessionCookie, SessionError, decode_cookie_bytes};
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

const COOKIE_SIZE: usize = 32;

static COOKIE_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    slice: Vec<u8>,
}

const MAX_SLICE: usize = 256;

fuzz_target!(|data: &[u8]| {
    COOKIE_ANCHOR.call_once(assert_cookie_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };
    if input.slice.len() > MAX_SLICE {
        return;
    }

    let result = SessionCookie::try_from_slice(&input.slice);
    let wrapper_result = decode_cookie_bytes(&input.slice);

    // ── PROPERTY 3: wrapper agreement ───────────────────────────────────
    match (&result, &wrapper_result) {
        (Ok(a), Ok(b)) => {
            assert_eq!(
                a.as_bytes(),
                b.as_bytes(),
                "decode_cookie_bytes diverged from try_from_slice on Ok"
            );
        }
        (
            Err(SessionError::InvalidCookieLength { len: la }),
            Err(SessionError::InvalidCookieLength { len: lb }),
        ) => {
            assert_eq!(
                la, lb,
                "decode_cookie_bytes len mismatch with try_from_slice"
            );
        }
        (a, b) => panic!("decode_cookie_bytes / try_from_slice disagree: {a:?} vs {b:?}"),
    }

    match result {
        Ok(cookie) => {
            // ── PROPERTY 1: length-32 → Ok with verbatim bytes ──────────
            assert_eq!(
                input.slice.len(),
                COOKIE_SIZE,
                "try_from_slice accepted len {} (expected 32)",
                input.slice.len()
            );
            assert_eq!(
                cookie.as_bytes().as_slice(),
                input.slice.as_slice(),
                "cookie bytes diverged from input"
            );

            // ── PROPERTY 4: round-trip identity ─────────────────────────
            let again =
                SessionCookie::try_from_slice(cookie.as_bytes()).expect("re-parse 32-byte cookie");
            assert_eq!(again.as_bytes(), cookie.as_bytes(), "round-trip lost bytes");

            // ── PROPERTY 5: JSON round-trip ─────────────────────────────
            let json = serde_json::to_string(&cookie).expect("JSON serialize");
            let from_json: SessionCookie = serde_json::from_str(&json).expect("JSON deserialize");
            assert_eq!(
                from_json.as_bytes(),
                cookie.as_bytes(),
                "JSON round-trip lost bytes"
            );

            // ── PROPERTY 6: CBOR round-trip ─────────────────────────────
            let cbor = to_canonical_cbor(&cookie).expect("CBOR serialize");
            let from_cbor: SessionCookie =
                ciborium::from_reader(&cbor[..]).expect("CBOR deserialize");
            assert_eq!(
                from_cbor.as_bytes(),
                cookie.as_bytes(),
                "CBOR round-trip lost bytes"
            );
        }
        Err(SessionError::InvalidCookieLength { len }) => {
            // ── PROPERTY 2: length-not-32 → Err carrying exact len ──────
            assert_ne!(
                input.slice.len(),
                COOKIE_SIZE,
                "try_from_slice rejected a 32-byte slice"
            );
            assert_eq!(
                len,
                input.slice.len(),
                "InvalidCookieLength carried wrong len: {} vs input {}",
                len,
                input.slice.len()
            );
        }
        Err(other) => panic!(
            "try_from_slice on len={} returned {other:?}; expected Ok or InvalidCookieLength",
            input.slice.len()
        ),
    }
});

/// Once-gated anchors: boundary lengths around the 32-byte gate.
fn assert_cookie_anchored() {
    // (a) Empty slice → InvalidCookieLength { len: 0 }.
    match SessionCookie::try_from_slice(&[]) {
        Err(SessionError::InvalidCookieLength { len: 0 }) => {}
        other => panic!(
            "ANCHOR REGRESSION: empty slice expected InvalidCookieLength{{len:0}}, got {other:?}"
        ),
    }
    match decode_cookie_bytes(&[]) {
        Err(SessionError::InvalidCookieLength { len: 0 }) => {}
        other => panic!("ANCHOR: decode_cookie_bytes empty slice diverged: {other:?}"),
    }

    // (b) 1-byte → InvalidCookieLength { len: 1 }.
    match SessionCookie::try_from_slice(&[0xAB]) {
        Err(SessionError::InvalidCookieLength { len: 1 }) => {}
        other => panic!("ANCHOR: 1-byte slice expected len:1 error, got {other:?}"),
    }

    // (c) 31-byte (off-by-one short) → InvalidCookieLength { len: 31 }.
    let s31 = vec![0u8; 31];
    match SessionCookie::try_from_slice(&s31) {
        Err(SessionError::InvalidCookieLength { len: 31 }) => {}
        other => panic!("ANCHOR REGRESSION: 31-byte slice expected len:31 error, got {other:?}"),
    }

    // (d) 32-byte → Ok with bytes preserved.
    let s32 = (0u8..32u8).collect::<Vec<_>>();
    let cookie = SessionCookie::try_from_slice(&s32).expect("ANCHOR: 32-byte slice must accept");
    assert_eq!(
        cookie.as_bytes().as_slice(),
        s32.as_slice(),
        "ANCHOR: 32-byte cookie bytes diverged"
    );

    // (e) 33-byte (off-by-one long) → InvalidCookieLength { len: 33 }.
    let s33 = vec![0u8; 33];
    match SessionCookie::try_from_slice(&s33) {
        Err(SessionError::InvalidCookieLength { len: 33 }) => {}
        other => panic!("ANCHOR REGRESSION: 33-byte slice expected len:33 error, got {other:?}"),
    }

    // (f) 64-byte (double) → InvalidCookieLength { len: 64 }.
    let s64 = vec![0u8; 64];
    match SessionCookie::try_from_slice(&s64) {
        Err(SessionError::InvalidCookieLength { len: 64 }) => {}
        other => panic!("ANCHOR: 64-byte slice expected len:64 error, got {other:?}"),
    }

    // (g) Wrapper agreement on a known-bad length.
    let s17 = vec![0u8; 17];
    let inner = SessionCookie::try_from_slice(&s17);
    let outer = decode_cookie_bytes(&s17);
    match (&inner, &outer) {
        (
            Err(SessionError::InvalidCookieLength { len: 17 }),
            Err(SessionError::InvalidCookieLength { len: 17 }),
        ) => {}
        _ => panic!(
            "ANCHOR REGRESSION: decode_cookie_bytes / try_from_slice diverged on \
             len-17 slice: {inner:?} vs {outer:?}"
        ),
    }
}
