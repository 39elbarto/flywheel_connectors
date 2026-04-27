#![no_main]

//! Fuzz target for `fcp_crypto::x25519` — the Diffie-Hellman primitive.
//!
//! X25519 DH is the basis for:
//!   - mesh-session key derivation (`fcp_protocol::session::derive_session_keys`)
//!   - HPKE encapsulation (`fcp_crypto::hpke_seal`)
//!   - any wire-supplied `X25519PublicKey` arriving via serde
//!
//! The implementation guards against the documented small-subgroup
//! attack: `diffie_hellman` rejects when the resulting shared secret
//! is the all-zero point (x25519.rs:79-91), which a malicious peer
//! could otherwise force by sending a low-order public key (the
//! attacker would then know the shared secret in advance).
//!
//! Properties asserted:
//!
//!   1. `X25519SecretKey::from_bytes` and `X25519PublicKey::from_bytes`
//!      are total over arbitrary 32-byte inputs.
//!   2. `X25519PublicKey::try_from_slice` rejects every slice whose
//!      length is not exactly `X25519_PUBLIC_KEY_SIZE`.
//!   3. **DH symmetry**: `sk_a.diffie_hellman(&pk_b)` ==
//!      `sk_b.diffie_hellman(&pk_a)` for any non-degenerate (a, b).
//!      This is the foundational property both peers rely on to
//!      derive matching session keys.
//!   4. **Pubkey serialization round-trip**: a public key constructed
//!      from `pk.to_bytes()` reconstitutes to a key with the same
//!      bytes (and therefore the same key_id).
//!   5. **Low-order rejection anchor**: known low-order public-key
//!      bytes (RFC 7748 §6.1) MUST cause `diffie_hellman` to return
//!      `InvalidPublicKey`. Once-per-process anchor.

use arbitrary::{Arbitrary, Unstructured};
use fcp_crypto::{X25519PublicKey, X25519SecretKey};
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

const X25519_KEY_SIZE: usize = 32;

static LOW_ORDER_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    sk_a_bytes: [u8; X25519_KEY_SIZE],
    sk_b_bytes: [u8; X25519_KEY_SIZE],
    /// Arbitrary slice for the wrong-length rejection check.
    arbitrary_slice: Vec<u8>,
}

fuzz_target!(|data: &[u8]| {
    LOW_ORDER_ANCHOR.call_once(assert_low_order_rejection);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    // ── PROPERTY 1: from_bytes is total ─────────────────────────────────
    let sk_a = X25519SecretKey::from_bytes(input.sk_a_bytes);
    let sk_b = X25519SecretKey::from_bytes(input.sk_b_bytes);
    let pk_a = sk_a.public_key();
    let pk_b = sk_b.public_key();

    // Direct pubkey construction must also be total.
    let direct_pk = X25519PublicKey::from_bytes(input.sk_a_bytes);
    assert_eq!(
        direct_pk.to_bytes(),
        input.sk_a_bytes,
        "X25519PublicKey::from_bytes must preserve its input bytes"
    );

    // ── PROPERTY 2: try_from_slice length gate ──────────────────────────
    let slice_len = input.arbitrary_slice.len();
    let result = X25519PublicKey::try_from_slice(&input.arbitrary_slice);
    if slice_len == X25519_KEY_SIZE {
        let pk = result.expect("32-byte slice MUST be accepted");
        assert_eq!(pk.to_bytes().as_slice(), input.arbitrary_slice.as_slice());
    } else {
        assert!(
            result.is_err(),
            "non-32-byte slice (len={slice_len}) MUST be rejected"
        );
    }

    // ── PROPERTY 3: DH symmetry ─────────────────────────────────────────
    // Both peers MUST derive the same shared secret. If both DH calls
    // succeed, their byte representations are equal. If one fails (e.g.
    // because a peer's key is low-order and produces an all-zero share),
    // the OTHER direction MUST also fail — the symmetry of the rejection
    // matters too: a peer that can derive a "valid" shared secret from
    // a key the implementation rejects on the other side is a bypass
    // surface.
    let ab = sk_a.diffie_hellman(&pk_b);
    let ba = sk_b.diffie_hellman(&pk_a);
    match (ab, ba) {
        (Ok(s_ab), Ok(s_ba)) => {
            assert_eq!(
                s_ab.as_bytes(),
                s_ba.as_bytes(),
                "X25519 DH must be symmetric: sk_a·pk_b == sk_b·pk_a"
            );
        }
        (Err(_), Err(_)) => {
            // Both directions agree on rejection — fine.
        }
        (Ok(_), Err(_)) | (Err(_), Ok(_)) => {
            panic!(
                "asymmetric DH outcome: one direction succeeded while the \
                 other rejected — implies asymmetric handling of low-order \
                 inputs (subgroup-attack defense bypass)"
            );
        }
    }

    // ── PROPERTY 4: pubkey serialization round-trip ────────────────────
    let pk_a_bytes = pk_a.to_bytes();
    let pk_a_again = X25519PublicKey::from_bytes(pk_a_bytes);
    assert_eq!(
        pk_a.to_bytes(),
        pk_a_again.to_bytes(),
        "X25519PublicKey round-trip via to_bytes/from_bytes must be identity"
    );
    assert_eq!(
        pk_a.key_id(),
        pk_a_again.key_id(),
        "round-tripped X25519PublicKey must have the same key_id"
    );
});

/// Anchor that the documented low-order points trip the zero-share guard.
/// Run once per process via `Once`.
///
/// Source: RFC 7748 §6.1 lists the low-order public keys whose DH output
/// is the identity (all-zero) regardless of the secret key. The five
/// canonical bit patterns include:
///   - all-zero point
///   - the order-2 point at the small-subgroup
///   - the order-4 point
///
/// The full list is implementation-detail; we assert the all-zero
/// canonical attacker key here as a regression anchor for the guard.
fn assert_low_order_rejection() {
    let zero_pk = X25519PublicKey::from_bytes([0u8; 32]);
    let arbitrary_sk = X25519SecretKey::from_bytes([7u8; 32]);
    let result = arbitrary_sk.diffie_hellman(&zero_pk);
    assert!(
        result.is_err(),
        "diffie_hellman MUST reject the all-zero peer pubkey \
         (subgroup-confinement attack — x25519.rs:79-91)"
    );

    // Anchor that a non-low-order DH succeeds, otherwise the rejection
    // assertion above is uninformative (the implementation could be
    // rejecting everything).
    let sk_a = X25519SecretKey::from_bytes([1u8; 32]);
    let sk_b = X25519SecretKey::from_bytes([2u8; 32]);
    let _ = sk_a.diffie_hellman(&sk_b.public_key()).expect(
        "non-degenerate DH MUST succeed; if this trips the guard \
                 has become over-restrictive and the regression catalog is unsound",
    );
}
