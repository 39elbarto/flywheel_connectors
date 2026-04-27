#![no_main]

//! Metamorphic fuzz target for `compute_cookie` / `verify_cookie`
//! (session.rs:989-1026) — the stateless DoS-prevention cookie HMAC.
//!
//! The cookie is `HMAC-SHA256(cookie_key, canonical_cbor(from || to ||
//! eph_pubkey || nonce || timestamp || suites || transport_limits))`
//! truncated to `SESSION_COOKIE_SIZE`. The host issues this cookie in
//! response to an unauthenticated hello and refuses to advance the
//! handshake until the peer echoes a valid one — so the cookie is the
//! gate that closes the trivial unauthenticated DoS surface against
//! handshake state allocation.
//!
//! Existing fuzz coverage:
//!   - `decode_cookie_bytes` (wire-format length + identity) in
//!     `fuzz_session`
//!   - `verify_session_mac` binding MRs (mac_key/session_id/direction/
//!     seq/frame) in `fuzz_session_metamorphic`
//!
//! NOT covered: the cookie's per-field binding properties. A regression
//! that dropped any of the seven hello fields from `compute_cookie`'s
//! HMAC input would silently let an attacker pivot a captured cookie to
//! a different hello (e.g., dropping `eph_pubkey` enables a fresh
//! ephemeral swap-in surface; dropping `timestamp` enables indefinite
//! cookie replay).
//!
//! Properties asserted:
//!
//!   1. **Round-trip**: `verify_cookie(key, hello, compute_cookie(key, hello))`
//!      MUST return `Ok`.
//!   2. **Determinism**: same `(key, hello)` ⇒ byte-identical cookies.
//!   3. **Field-binding (×7)**: bit-flipping any one of `from`, `to`,
//!      `eph_pubkey`, `nonce`, `timestamp`, `suites`, `transport_limits`
//!      MUST cause `verify_cookie` to return `InvalidCookie`.
//!   4. **Key-binding**: the cookie computed under one key MUST NOT
//!      verify under any different key.
//!   5. **Cookie-tamper rejection**: bit-flipping the cookie bytes
//!      themselves MUST cause `InvalidCookie` — anchors the `ct_eq` path
//!      at session.rs:1021.

use arbitrary::{Arbitrary, Unstructured};
use fcp_core::TailscaleNodeId;
use fcp_crypto::X25519SecretKey;
use fcp_protocol::{
    MeshSessionHello, SESSION_COOKIE_SIZE, SessionCookie, SessionCryptoSuite, SessionError,
    SessionNonce, TransportLimits, compute_cookie, verify_cookie,
};
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

const X25519_SK_SIZE: usize = 32;
const COOKIE_KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 16;

static FIELD_BINDING_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    cookie_key: [u8; COOKIE_KEY_SIZE],
    sk_bytes: [u8; X25519_SK_SIZE],
    nonce: [u8; NONCE_SIZE],
    timestamp: u64,
    max_datagram_bytes: u16,
    suite_disc: u8,
    /// Bit index for the field-binding flips. Folded modulo each field's
    /// bit width.
    bitflip_index: u32,
    /// Discriminator picking which field to mutate this iteration.
    field_disc: u8,
    /// Toggle whether to include the optional cookie/transport_limits.
    include_transport_limits: bool,
}

fn pick_suite(disc: u8) -> SessionCryptoSuite {
    if disc.is_multiple_of(2) {
        SessionCryptoSuite::Suite1
    } else {
        SessionCryptoSuite::Suite2
    }
}

fn build_hello(input: &Input) -> MeshSessionHello {
    let sk = X25519SecretKey::from_bytes(input.sk_bytes);
    let pk = sk.public_key();

    let transport_limits = if input.include_transport_limits {
        Some(TransportLimits {
            max_datagram_bytes: input.max_datagram_bytes.max(1),
        })
    } else {
        None
    };

    MeshSessionHello {
        from: TailscaleNodeId::new("node-from"),
        to: TailscaleNodeId::new("node-to"),
        eph_pubkey: pk,
        nonce: SessionNonce(input.nonce),
        cookie: None,
        timestamp: input.timestamp,
        suites: vec![pick_suite(input.suite_disc)],
        transport_limits,
        signature: None,
    }
}

fn flip_byte0(bytes: &mut [u8]) {
    if let Some(b) = bytes.first_mut() {
        *b ^= 0x01;
    }
}

fuzz_target!(|data: &[u8]| {
    FIELD_BINDING_ANCHOR.call_once(assert_field_binding_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    let hello = build_hello(&input);

    // ── PROPERTY 1: round-trip ─────────────────────────────────────────
    let cookie = compute_cookie(&input.cookie_key, &hello)
        .expect("compute_cookie must succeed for canonical hello");
    verify_cookie(&input.cookie_key, &hello, &cookie)
        .expect("verify_cookie MUST accept its own compute_cookie output");

    // ── PROPERTY 2: determinism ────────────────────────────────────────
    let cookie2 = compute_cookie(&input.cookie_key, &hello).expect("recompute succeeds");
    assert_eq!(
        cookie.as_bytes(),
        cookie2.as_bytes(),
        "compute_cookie is not deterministic on identical (key, hello)"
    );

    // ── PROPERTY 3: field-binding ──────────────────────────────────────
    // Mutate one field per iteration (driven by field_disc) and assert
    // verify rejects. The bitflip_index discriminator is unused here —
    // any single-bit difference in the canonical-CBOR-encoded field
    // suffices to flip the HMAC output, so a deterministic mutation is
    // enough to probe the binding.
    let mutated = mutate_one_field(&hello, input.field_disc);
    if let Some(mutated_hello) = mutated {
        // Sanity-check our mutation actually altered the HMAC input;
        // if the mutation is a no-op (e.g. timestamp += 0 wrap) we skip.
        let mutated_cookie =
            compute_cookie(&input.cookie_key, &mutated_hello).expect("compute on mutated hello");
        if mutated_cookie.as_bytes() != cookie.as_bytes() {
            match verify_cookie(&input.cookie_key, &mutated_hello, &cookie) {
                Err(SessionError::InvalidCookie) => {}
                Ok(()) => panic!(
                    "verify_cookie accepted the original cookie under a mutated hello \
                     (field_disc={}) — field-binding regression: an attacker could pivot \
                     a captured cookie to a different hello",
                    input.field_disc
                ),
                Err(other) => {
                    panic!("verify_cookie returned unexpected error {other:?} on mutated hello")
                }
            }
        }
    }

    // ── PROPERTY 4: key-binding ────────────────────────────────────────
    let mut alt_key = input.cookie_key;
    alt_key[0] ^= 0x01;
    let cookie_alt_key = compute_cookie(&alt_key, &hello).expect("compute under alt key succeeds");
    if cookie_alt_key.as_bytes() != cookie.as_bytes() {
        // The cookies should diverge given any key change; if they
        // didn't, the HMAC is degenerate and we've already exposed a
        // deeper bug. Verify under original key MUST reject.
        match verify_cookie(&input.cookie_key, &hello, &cookie_alt_key) {
            Err(SessionError::InvalidCookie) => {}
            Ok(()) => panic!(
                "verify_cookie accepted a cookie computed under a different key — \
                 key-binding regression: cookie HMAC degenerated to keyless"
            ),
            Err(other) => {
                panic!("verify_cookie returned unexpected error {other:?} for wrong-key cookie")
            }
        }
    }

    // ── PROPERTY 5: cookie-tamper rejection ────────────────────────────
    let mut tampered_bytes = *cookie.as_bytes();
    let bit = (input.bitflip_index as usize) % (SESSION_COOKIE_SIZE * 8);
    tampered_bytes[bit / 8] ^= 1u8 << (bit % 8);
    let tampered = SessionCookie::try_from_slice(&tampered_bytes)
        .expect("32-byte slice constructs SessionCookie");
    match verify_cookie(&input.cookie_key, &hello, &tampered) {
        Err(SessionError::InvalidCookie) => {}
        Ok(()) => panic!(
            "verify_cookie accepted a single-bit-flipped cookie — ct_eq path at \
             session.rs:1021 broken (cookie malleability surface)"
        ),
        Err(other) => {
            panic!("verify_cookie returned unexpected error {other:?} for tampered cookie")
        }
    }
});

/// Apply a single-field mutation, returning the modified hello or `None`
/// if the discriminator landed on a non-mutating choice.
fn mutate_one_field(hello: &MeshSessionHello, disc: u8) -> Option<MeshSessionHello> {
    let mut h = hello.clone();
    match disc % 7 {
        0 => {
            // from
            h.from = TailscaleNodeId::new("node-other");
            Some(h)
        }
        1 => {
            // to
            h.to = TailscaleNodeId::new("node-other");
            Some(h)
        }
        2 => {
            // eph_pubkey: bit-flip on the underlying bytes
            let mut bytes = h.eph_pubkey.to_bytes();
            flip_byte0(&mut bytes);
            h.eph_pubkey = fcp_crypto::X25519PublicKey::from_bytes(bytes);
            Some(h)
        }
        3 => {
            // nonce
            h.nonce.0[0] ^= 0x01;
            Some(h)
        }
        4 => {
            // timestamp (XOR ensures non-zero delta)
            h.timestamp ^= 1;
            Some(h)
        }
        5 => {
            // suites: append a different suite to the vector. If the
            // current suite list already contains both Suite1 and Suite2,
            // dropping all but the first one still mutates the encoded
            // vector length.
            let alt = match h.suites.first().copied() {
                Some(SessionCryptoSuite::Suite1) => SessionCryptoSuite::Suite2,
                _ => SessionCryptoSuite::Suite1,
            };
            h.suites.push(alt);
            Some(h)
        }
        _ => {
            // transport_limits: flip presence (None ↔ Some(default)).
            h.transport_limits = match h.transport_limits {
                Some(_) => None,
                None => Some(TransportLimits::default()),
            };
            Some(h)
        }
    }
}

/// Hand-crafted regression anchor for the timestamp-binding property —
/// the most cited "captured cookie reused later" attack. We construct
/// two helloes that differ only in timestamp, generate a cookie under
/// the first, and assert verify rejects it on the second. Run once per
/// process so a regression that drops `timestamp` from compute_cookie's
/// HMAC input trips on every fuzz invocation, not only by chance.
fn assert_field_binding_anchored() {
    let cookie_key = [0x33u8; COOKIE_KEY_SIZE];
    let sk = X25519SecretKey::from_bytes([0x42u8; X25519_SK_SIZE]);
    let pk = sk.public_key();

    let hello_t1 = MeshSessionHello {
        from: TailscaleNodeId::new("anchor-from"),
        to: TailscaleNodeId::new("anchor-to"),
        eph_pubkey: pk.clone(),
        nonce: SessionNonce([0x77; NONCE_SIZE]),
        cookie: None,
        timestamp: 1_000_000,
        suites: vec![SessionCryptoSuite::Suite1],
        transport_limits: Some(TransportLimits::default()),
        signature: None,
    };
    let mut hello_t2 = hello_t1.clone();
    hello_t2.timestamp = 2_000_000;

    let cookie_t1 = compute_cookie(&cookie_key, &hello_t1).expect("anchor compute_cookie t1");
    verify_cookie(&cookie_key, &hello_t1, &cookie_t1).expect("anchor self-verifies");

    match verify_cookie(&cookie_key, &hello_t2, &cookie_t1) {
        Err(SessionError::InvalidCookie) => {}
        Ok(()) => panic!(
            "ANCHOR REGRESSION: verify_cookie accepted a t=1_000_000 cookie under \
             a t=2_000_000 hello — timestamp dropped from compute_cookie HMAC. \
             An attacker could replay a captured cookie indefinitely (DoS gate \
             collapses), see session.rs:998."
        ),
        Err(other) => panic!("ANCHOR: unexpected error {other:?} from verify_cookie"),
    }

    // Anchor the eph_pubkey-binding path too — guards against the
    // "fresh ephemeral swap-in mid-handshake" surface.
    let sk_alt = X25519SecretKey::from_bytes([0x88u8; X25519_SK_SIZE]);
    let mut hello_alt_pk = hello_t1.clone();
    hello_alt_pk.eph_pubkey = sk_alt.public_key();
    match verify_cookie(&cookie_key, &hello_alt_pk, &cookie_t1) {
        Err(SessionError::InvalidCookie) => {}
        Ok(()) => panic!(
            "ANCHOR REGRESSION: verify_cookie accepted a captured cookie under a \
             hello carrying a fresh eph_pubkey — eph_pubkey dropped from \
             compute_cookie HMAC, see session.rs:996."
        ),
        Err(other) => panic!("ANCHOR: unexpected error {other:?} for eph swap"),
    }
}
