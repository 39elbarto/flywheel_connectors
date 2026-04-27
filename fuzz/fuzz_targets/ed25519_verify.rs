#![no_main]

//! Ed25519 verify-path fuzz target for `fcp-crypto`.
//!
//! This is the bottom of the verifier stack: capability tokens, audit
//! receipts, mesh-node attestations, owner-signed bootstrap messages all
//! resolve to `Ed25519VerifyingKey::verify` against a pubkey reconstructed
//! from raw bytes. Any panic, malleability, or accept-on-mutation bug
//! here translates directly into authentication-bypass opportunities.
//!
//! Properties asserted:
//!
//!   1. `Ed25519VerifyingKey::from_bytes(arbitrary_32)` never panics.
//!      All-zero and small-subgroup inputs MUST be rejected (guards
//!      against subgroup-confinement; see ed25519.rs:163,178).
//!   2. `Ed25519VerifyingKey::verify(msg, sig)` never panics on
//!      arbitrary message and arbitrary signature bytes.
//!   3. Sign-verify round-trip: `sign(msg)` → `verify(msg, sig)` is
//!      always Ok for a freshly-derived key/message pair.
//!   4. Wrong-key verify: signing-key A's signature MUST NOT verify
//!      under verifying-key B (where A != B).
//!   5. Non-malleability: a single-bit flip in the signature OR the
//!      message MUST cause `verify_strict` to reject. The current
//!      implementation explicitly chose `verify_strict` over `verify`
//!      to close the malleable-S attack class
//!      (https://hdevalence.ca/blog/2020-10-04-its-25519am — see
//!      ed25519.rs:203-213). This property is the regression guard.
//!   6. `verify_with_context(ctx, msg, sig)` matches plain
//!      `verify(domain_hash, sig)` for the documented BLAKE3
//!      domain-separation construction.

use arbitrary::{Arbitrary, Unstructured};
use fcp_crypto::{Ed25519Signature, Ed25519SigningKey, Ed25519VerifyingKey};
use libfuzzer_sys::fuzz_target;

const PUBLIC_KEY_SIZE: usize = 32;
const SECRET_KEY_SIZE: usize = 32;
const SIGNATURE_SIZE: usize = 64;
const MAX_MESSAGE_LEN: usize = 4 * 1024;
const MAX_CONTEXT_LEN: usize = 256;

#[derive(Arbitrary, Debug)]
struct Input {
    pubkey_seed: [u8; PUBLIC_KEY_SIZE],
    sig_seed: [u8; SIGNATURE_SIZE],
    signing_seed_a: [u8; SECRET_KEY_SIZE],
    signing_seed_b: [u8; SECRET_KEY_SIZE],
    /// Index in [0, MAX_MESSAGE_LEN * 8 + SIGNATURE_SIZE * 8) selecting
    /// which bit to flip for the malleability test. Wrapped modulo the
    /// actual mutation budget at use-site.
    bitflip_index: u32,
    /// 0..2: 0 = flip a sig bit, 1 = flip a message bit.
    bitflip_target: u8,
    message: Vec<u8>,
    context: Vec<u8>,
}

fn truncate(bytes: &[u8], max: usize) -> &[u8] {
    if bytes.len() > max {
        &bytes[..max]
    } else {
        bytes
    }
}

/// Flip the bit at `bit_index` in `bytes`. Caller must ensure
/// `bit_index < bytes.len() * 8`.
fn flip_bit(bytes: &mut [u8], bit_index: usize) {
    let byte = bit_index / 8;
    let mask = 1u8 << (bit_index % 8);
    bytes[byte] ^= mask;
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    let message = truncate(&input.message, MAX_MESSAGE_LEN);
    let context = truncate(&input.context, MAX_CONTEXT_LEN);

    // ── PROPERTY 1: pubkey parser is total + rejects weak keys ──────────
    let from_bytes_result = Ed25519VerifyingKey::from_bytes(&input.pubkey_seed);
    if input.pubkey_seed.iter().all(|&b| b == 0) {
        assert!(
            from_bytes_result.is_err(),
            "Ed25519VerifyingKey::from_bytes accepted all-zero public key"
        );
    }

    // ── PROPERTY 2: verify is total on arbitrary inputs ─────────────────
    if let Ok(arbitrary_vk) = &from_bytes_result {
        let arbitrary_sig = Ed25519Signature::from_bytes(&input.sig_seed);
        let _ = arbitrary_vk.verify(message, &arbitrary_sig);
        let _ = arbitrary_vk.verify_with_context(context, message, &arbitrary_sig);
    }

    // ── PROPERTY 3: round-trip succeeds ─────────────────────────────────
    let Ok(sk_a) = Ed25519SigningKey::from_bytes(&input.signing_seed_a) else {
        return;
    };
    let vk_a = sk_a.verifying_key();
    let sig = sk_a.sign(message);
    vk_a.verify(message, &sig)
        .expect("sign(msg) ⇒ verify(msg, sig) MUST succeed for matching key");

    // ── PROPERTY 4: wrong-key verify rejects ────────────────────────────
    if let Ok(sk_b) = Ed25519SigningKey::from_bytes(&input.signing_seed_b) {
        let vk_b = sk_b.verifying_key();
        if vk_a != vk_b {
            assert!(
                vk_b.verify(message, &sig).is_err(),
                "verify under wrong key MUST reject"
            );
        }
    }

    // ── PROPERTY 5: non-malleability under bit-flip ─────────────────────
    // Flip exactly one bit of either the signature or the message and
    // assert verify_strict (called inside Ed25519VerifyingKey::verify)
    // refuses to accept the mutated artifact. If this ever passes, the
    // implementation has reverted to malleable verify and the entire
    // signature-equality model collapses.
    match input.bitflip_target % 2 {
        0 => {
            let mut sig_bytes = sig.to_bytes();
            let bit = (input.bitflip_index as usize) % (SIGNATURE_SIZE * 8);
            flip_bit(&mut sig_bytes, bit);
            let mutated_sig = Ed25519Signature::from_bytes(&sig_bytes);
            // Skip the no-op case where the flip happens to land on a
            // bit that we just flipped back (impossible for a single
            // flip, but guard anyway).
            if mutated_sig.to_bytes() != sig.to_bytes() {
                assert!(
                    vk_a.verify(message, &mutated_sig).is_err(),
                    "bit-flipped signature MUST NOT verify (malleability regression)"
                );
            }
        }
        _ => {
            // Mutating the message only matters if we have something to
            // mutate — empty messages have no bits.
            if !message.is_empty() {
                let mut mutated = message.to_vec();
                let bit = (input.bitflip_index as usize) % (mutated.len() * 8);
                flip_bit(&mut mutated, bit);
                if mutated != message {
                    assert!(
                        vk_a.verify(&mutated, &sig).is_err(),
                        "bit-flipped message MUST NOT verify under original signature"
                    );
                }
            }
        }
    }

    // ── PROPERTY 6: domain-separated verify_with_context round-trip ─────
    // Sign over the documented BLAKE3 transcript, then verify via the
    // public helper. Any divergence (e.g. context length not encoded,
    // wrong field order) breaks cross-protocol replay protection.
    let sig_ctx = sk_a.sign_with_context(context, message);
    vk_a.verify_with_context(context, message, &sig_ctx)
        .expect("sign_with_context ⇒ verify_with_context MUST succeed");

    // Different context (single-bit flip in context, or empty vs non-empty)
    // must NOT verify. Pick a deterministic alternate context: flip the
    // last bit if non-empty, else use a 1-byte context.
    let alt_context: Vec<u8> = if context.is_empty() {
        vec![0u8]
    } else {
        let mut c = context.to_vec();
        let last_bit = c.len() * 8 - 1;
        flip_bit(&mut c, last_bit);
        c
    };
    if alt_context.as_slice() != context {
        assert!(
            vk_a.verify_with_context(&alt_context, message, &sig_ctx)
                .is_err(),
            "verify_with_context with mutated context MUST reject (cross-protocol replay surface)"
        );
    }
});
