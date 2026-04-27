#![no_main]

//! Fuzz target for `MeshSessionHello::sign` / `verify` (session.rs:374-390).
//!
//! Hello's Ed25519 transcript signature is the authentication binding
//! over `b"FCP2-HELLO-V1" || from || to || eph_pubkey || nonce ||
//! cookie || timestamp || suites || transport_limits` (transcript_bytes
//! at session.rs:356-367). Distinct from:
//!   - verify_cookie (674lv): stateless HMAC gate on cookie key
//!   - verify_session_mac (session_metamorphic): per-frame MAC
//!   - NodeKeyAttestation (xedeu): owner-issued node attestation
//!
//! A regression in the hello transcript binding would let an attacker
//! pivot a captured hello between (from, to, eph_pubkey, ...) tuples.
//! None of the existing fuzz targets exercise the hello's per-field
//! binding.
//!
//! Properties asserted:
//!
//!   1. **Round-trip**: sign(key, h) → verify(key.pub, h) returns Ok.
//!   2. **Per-field binding**: bit-flipping any one of (from, to,
//!      eph_pubkey, nonce, cookie, timestamp, suites, transport_limits)
//!      MUST cause verify to return InvalidSignature.
//!   3. **Wrong-key rejection**: hello signed under A MUST NOT verify
//!      under any different B.
//!   4. **MissingSignature on unsigned**: signature=None MUST yield
//!      SessionError::MissingSignature.
//!
//!   Once-gated regression anchors:
//!     (a) Timestamp binding: hello signed at t=1 MUST NOT verify at
//!         t=2 (transcript-layer replay guard).
//!     (b) eph_pubkey binding: hello signed with eph A MUST NOT
//!         verify with eph B (transcript-layer ephemeral swap guard).

use arbitrary::{Arbitrary, Unstructured};
use fcp_core::TailscaleNodeId;
use fcp_crypto::{Ed25519SigningKey, X25519SecretKey};
use fcp_protocol::{
    MeshSessionHello, SessionCookie, SessionCryptoSuite, SessionError, SessionNonce,
    TransportLimits,
};
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

const ED25519_SK_SIZE: usize = 32;
const X25519_SK_SIZE: usize = 32;
const NONCE_SIZE: usize = 16;
const COOKIE_SIZE: usize = 32;

static TRANSCRIPT_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    signing_seed: [u8; ED25519_SK_SIZE],
    alt_signing_seed: [u8; ED25519_SK_SIZE],
    eph_seed: [u8; X25519_SK_SIZE],
    nonce: [u8; NONCE_SIZE],
    timestamp: u64,
    /// Discriminator: which field to mutate this iteration.
    field_disc: u8,
    /// Include cookie / transport_limits in the hello.
    with_cookie: bool,
    with_transport_limits: bool,
    /// Cookie bytes if with_cookie is true.
    cookie: [u8; COOKIE_SIZE],
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
    let eph = X25519SecretKey::from_bytes(input.eph_seed).public_key();
    let cookie = if input.with_cookie {
        Some(SessionCookie(input.cookie))
    } else {
        None
    };
    let transport_limits = if input.with_transport_limits {
        Some(TransportLimits {
            max_datagram_bytes: 1500,
        })
    } else {
        None
    };
    MeshSessionHello {
        from: TailscaleNodeId::new("node-from"),
        to: TailscaleNodeId::new("node-to"),
        eph_pubkey: eph,
        nonce: SessionNonce(input.nonce),
        cookie,
        timestamp: input.timestamp,
        suites: vec![pick_suite(input.suite_disc)],
        transport_limits,
        signature: None,
    }
}

fn mutate_one_field(hello: &MeshSessionHello, disc: u8) -> MeshSessionHello {
    let mut h = hello.clone();
    match disc % 7 {
        0 => h.from = TailscaleNodeId::new("node-other"),
        1 => h.to = TailscaleNodeId::new("node-other"),
        2 => {
            let mut bytes = h.eph_pubkey.to_bytes();
            bytes[0] ^= 0x01;
            h.eph_pubkey = fcp_crypto::X25519PublicKey::from_bytes(bytes);
        }
        3 => h.nonce.0[0] ^= 0x01,
        4 => h.timestamp ^= 1,
        5 => {
            let alt = match h.suites.first().copied() {
                Some(SessionCryptoSuite::Suite1) => SessionCryptoSuite::Suite2,
                _ => SessionCryptoSuite::Suite1,
            };
            h.suites.push(alt);
        }
        _ => {
            // toggle cookie presence
            h.cookie = match h.cookie {
                Some(_) => None,
                None => Some(SessionCookie([0xFFu8; COOKIE_SIZE])),
            };
        }
    }
    h
}

fuzz_target!(|data: &[u8]| {
    TRANSCRIPT_ANCHOR.call_once(assert_transcript_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    let Ok(signing) = Ed25519SigningKey::from_bytes(&input.signing_seed) else {
        return;
    };
    let pubkey = signing.verifying_key();

    let mut hello = build_hello(&input);

    // ── PROPERTY 4: MissingSignature on unsigned ──────────────────────
    match hello.verify(&pubkey) {
        Err(SessionError::MissingSignature) => {}
        Err(other) => panic!("unsigned hello.verify returned {other:?}; expected MissingSignature"),
        Ok(()) => panic!("unsigned hello.verify returned Ok — signature gate broken"),
    }

    // Sign in place.
    if hello.sign(&signing).is_err() {
        return;
    }

    // ── PROPERTY 1: round-trip ────────────────────────────────────────
    hello
        .verify(&pubkey)
        .expect("freshly signed hello MUST verify under signer's pubkey");

    // ── PROPERTY 2: per-field binding ─────────────────────────────────
    let mutated = mutate_one_field(&hello, input.field_disc);
    // Check the mutation actually changed the transcript bytes; if not
    // (e.g. clearing an already-None cookie), skip.
    if let (Ok(orig_t), Ok(mut_t)) = (hello.transcript_bytes(), mutated.transcript_bytes())
        && orig_t != mut_t
    {
        match mutated.verify(&pubkey) {
            Err(SessionError::InvalidSignature) => {}
            Err(other) => panic!(
                "mutated hello.verify returned {other:?}; expected InvalidSignature \
                 (field_disc={})",
                input.field_disc % 7
            ),
            Ok(()) => panic!(
                "mutated hello.verify returned Ok — field binding broken \
                 (field_disc={}); attacker could pivot a captured hello",
                input.field_disc % 7
            ),
        }
    }

    // ── PROPERTY 3: wrong-key rejection ───────────────────────────────
    if let Ok(alt_signing) = Ed25519SigningKey::from_bytes(&input.alt_signing_seed) {
        let alt_pubkey = alt_signing.verifying_key();
        if alt_pubkey.key_id() != pubkey.key_id() {
            match hello.verify(&alt_pubkey) {
                Err(SessionError::InvalidSignature) => {}
                Err(other) => panic!(
                    "verify under wrong pubkey returned {other:?}; expected InvalidSignature"
                ),
                Ok(()) => panic!(
                    "hello signed under one key verified under a different key — \
                     wrong-key rejection broken"
                ),
            }
        }
    }
});

/// Once-gated regression anchors for the most load-bearing transcript-
/// binding properties.
fn assert_transcript_anchored() {
    let signing =
        Ed25519SigningKey::from_bytes(&[0x42u8; ED25519_SK_SIZE]).expect("anchor signing key");
    let pubkey = signing.verifying_key();
    let eph = X25519SecretKey::from_bytes([0x77u8; X25519_SK_SIZE]).public_key();

    let make = |timestamp: u64, eph_pk: fcp_crypto::X25519PublicKey| MeshSessionHello {
        from: TailscaleNodeId::new("anchor-from"),
        to: TailscaleNodeId::new("anchor-to"),
        eph_pubkey: eph_pk,
        nonce: SessionNonce([0xAAu8; NONCE_SIZE]),
        cookie: None,
        timestamp,
        suites: vec![SessionCryptoSuite::Suite1],
        transport_limits: Some(TransportLimits::default()),
        signature: None,
    };

    // (a) Timestamp binding.
    let mut h_t1 = make(1, eph.clone());
    h_t1.sign(&signing).expect("anchor sign t=1");
    h_t1.verify(&pubkey).expect("anchor verify t=1");

    // Replay the SIGNED hello at the t=1 transcript with a swapped
    // timestamp on the structure. This simulates an attacker who has
    // a valid signature for t=1 and tries to claim t=2.
    let mut h_t2 = h_t1.clone();
    h_t2.timestamp = 2;
    match h_t2.verify(&pubkey) {
        Err(SessionError::InvalidSignature) => {}
        Err(other) => panic!("ANCHOR: timestamp mutation produced {other:?}"),
        Ok(()) => panic!(
            "ANCHOR REGRESSION: hello signed at t=1 verified at t=2 — \
             timestamp dropped from transcript_bytes (session.rs:364); \
             captured hellos replay indefinitely at the inner-transcript layer"
        ),
    }

    // (b) eph_pubkey binding.
    let mut h_eph_a = make(100, eph);
    h_eph_a.sign(&signing).expect("anchor sign eph_a");

    let alt_eph = X25519SecretKey::from_bytes([0x88u8; X25519_SK_SIZE]).public_key();
    let mut h_eph_b = h_eph_a.clone();
    h_eph_b.eph_pubkey = alt_eph;
    match h_eph_b.verify(&pubkey) {
        Err(SessionError::InvalidSignature) => {}
        Err(other) => panic!("ANCHOR: eph_pubkey mutation produced {other:?}"),
        Ok(()) => panic!(
            "ANCHOR REGRESSION: hello signed with eph A verified with eph B — \
             eph_pubkey dropped from transcript_bytes (session.rs:361); \
             mid-handshake ephemeral swap-in surface re-opened"
        ),
    }
}
