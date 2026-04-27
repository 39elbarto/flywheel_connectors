//! br-9seey: fuzz target for the lower-level
//! `fcp_protocol::symbol_envelope::{decrypt_symbol, derive_sender_subkey,
//! encrypt_symbol}` API.
//!
//! Distinct from `raptorq_envelope_decrypt.rs`, which fuzzes the
//! `fcp_raptorq::SymbolEnvelope::decrypt` *wrapper* (envelope-aware
//! struct + zone_key_id matching gate). This target hits the raw
//! AEAD primitives that the wrapper composes — `decrypt_symbol` takes
//! attacker-controlled ciphertext + auth_tag bytes directly with a
//! caller-supplied `SymbolContext`, and `derive_sender_subkey`
//! consumes a `TailscaleNodeId` whose bytes feed an HKDF-Info field
//! prefixed by a length-prefix that historically has been a fuzzer
//! magnet.
//!
//! Properties exercised:
//!   1. Identity round-trip: encrypt_symbol + decrypt_symbol on the
//!      same key + ctx must round-trip the original plaintext.
//!   2. Tampered ciphertext: any single bit flip in the ciphertext or
//!      auth_tag MUST surface as `SymbolEnvelopeError::DecryptFailed`,
//!      never silently accept and never panic.
//!   3. Wrong subkey: feeding a different sender subkey (e.g. derived
//!      from a different sender_node_id) MUST fail authentication.
//!   4. derive_sender_subkey: the documented `# Panics` clause says
//!      HKDF expansion never panics for the 32-byte output. The
//!      attacker controls `sender_node_id` (length-prefixed in the
//!      Info field), so we exercise the construction across a wide
//!      range of node-id strings to confirm the panic-free invariant.

#![no_main]

use arbitrary::Arbitrary;
use fcp_core::{ObjectId, TailscaleNodeId, ZoneIdHash, ZoneKeyId};
use fcp_crypto::AeadKey;
use fcp_protocol::{
    AUTH_TAG_SIZE, SymbolContext, SymbolEnvelopeError, ZoneKeyAlgorithm, decrypt_symbol,
    derive_sender_subkey, encrypt_symbol,
};
use libfuzzer_sys::fuzz_target;

const MAX_PLAINTEXT_LEN: usize = 4096;

#[derive(Arbitrary, Clone, Copy, Debug)]
enum AlgorithmChoice {
    ChaCha20Poly1305,
    XChaCha20Poly1305,
}

impl AlgorithmChoice {
    const fn to_zone_key_algorithm(self) -> ZoneKeyAlgorithm {
        match self {
            Self::ChaCha20Poly1305 => ZoneKeyAlgorithm::ChaCha20Poly1305,
            Self::XChaCha20Poly1305 => ZoneKeyAlgorithm::XChaCha20Poly1305,
        }
    }
}

#[derive(Arbitrary, Clone, Copy, Debug, PartialEq, Eq)]
enum MutationKind {
    /// No tampering — must round-trip cleanly.
    Identity,
    /// Flip one bit in the ciphertext payload.
    CiphertextBitflip,
    /// Truncate the ciphertext by one byte.
    CiphertextTruncate,
    /// Flip one bit in the auth tag.
    AuthTagBitflip,
    /// Decrypt with a sender subkey derived from a DIFFERENT sender_node_id.
    /// Tests that subkey derivation actually binds the sender identity.
    WrongSenderId,
    /// Decrypt with a totally different zone key.
    WrongZoneKey,
}

#[derive(Arbitrary, Debug)]
struct EnvelopeFuzzInput<'a> {
    zone_key_seed: [u8; 32],
    /// Caller-supplied `TailscaleNodeId` bytes — fed through `try_new`
    /// so canonicalization caps apply (length 1..=128, ASCII only).
    /// On rejection we fall back to a deterministic test node id.
    sender_node_id: &'a str,
    object_id: [u8; 32],
    zone_id_hash: [u8; 32],
    zone_key_id: [u8; 8],
    epoch_id: u64,
    sender_instance_id: u64,
    frame_seq: u64,
    esi: u32,
    k: u16,
    algorithm: AlgorithmChoice,
    mutation: MutationKind,
    mutation_index: u16,
    plaintext_len: u16,
    plaintext_fill: u8,
}

fn build_plaintext(input: &EnvelopeFuzzInput<'_>) -> Vec<u8> {
    let len = usize::from(input.plaintext_len).min(MAX_PLAINTEXT_LEN);
    (0..len)
        .map(|i| {
            input
                .plaintext_fill
                .wrapping_add(u8::try_from(i & 0xFF).unwrap_or(0))
        })
        .collect()
}

fn sender_node_id_or_default(raw: &str) -> TailscaleNodeId {
    TailscaleNodeId::try_new(raw).unwrap_or_else(|_| TailscaleNodeId::new("fuzz-sender-default"))
}

fn build_context(input: &EnvelopeFuzzInput<'_>, sender: &TailscaleNodeId) -> SymbolContext {
    SymbolContext {
        object_id: ObjectId::from_bytes(input.object_id),
        esi: input.esi,
        k: input.k.max(1),
        zone_id_hash: ZoneIdHash::from_bytes(input.zone_id_hash),
        zone_key_id: ZoneKeyId::from_bytes(input.zone_key_id),
        epoch_id: input.epoch_id,
        sender_node_id: sender.clone(),
        sender_instance_id: input.sender_instance_id,
        frame_seq: input.frame_seq,
    }
}

fn flip_bit_in_vec(buf: &mut Vec<u8>, mutation_index: usize) {
    if buf.is_empty() {
        buf.push(1u8.rotate_left((mutation_index % 8) as u32));
        return;
    }
    let byte_offset = mutation_index % buf.len();
    let bit_mask = 1u8.rotate_left((mutation_index % 8) as u32);
    buf[byte_offset] ^= bit_mask;
}

fn flip_bit_in_array(buf: &mut [u8; AUTH_TAG_SIZE], mutation_index: usize) {
    let byte_offset = mutation_index % buf.len();
    let bit_mask = 1u8.rotate_left((mutation_index % 8) as u32);
    buf[byte_offset] ^= bit_mask;
}

fuzz_target!(|input: EnvelopeFuzzInput<'_>| {
    let sender = sender_node_id_or_default(input.sender_node_id);
    let zone_key = AeadKey::from_bytes(input.zone_key_seed);
    let algorithm = input.algorithm.to_zone_key_algorithm();
    let ctx = build_context(&input, &sender);
    let plaintext = build_plaintext(&input);

    // Property 4: derive_sender_subkey must never panic on any
    // attacker-controlled sender_node_id (the # Panics docstring at
    // symbol_envelope.rs:100 says HKDF expansion is infallible for
    // 32-byte output; this fuzzer pins that invariant).
    let _subkey = derive_sender_subkey(
        &zone_key,
        &ctx.zone_key_id,
        &ctx.sender_node_id,
        ctx.sender_instance_id,
    );

    let (mut ciphertext, mut auth_tag) =
        match encrypt_symbol(&zone_key, algorithm, &ctx, &plaintext) {
            Ok(pair) => pair,
            // Encryption failure on a freshly-derived key is unexpected;
            // tolerate but bail out so we don't conflate with decrypt
            // bugs.
            Err(_) => return,
        };

    let mutation_index = usize::from(input.mutation_index);
    let mut decrypt_zone_key = zone_key;
    let mut decrypt_ctx = ctx.clone();

    match input.mutation {
        MutationKind::Identity => {}
        MutationKind::CiphertextBitflip => {
            flip_bit_in_vec(&mut ciphertext, mutation_index);
        }
        MutationKind::CiphertextTruncate => {
            if ciphertext.is_empty() {
                ciphertext.push(0xAA);
            } else {
                ciphertext.truncate(ciphertext.len().saturating_sub(1));
            }
        }
        MutationKind::AuthTagBitflip => {
            flip_bit_in_array(&mut auth_tag, mutation_index);
        }
        MutationKind::WrongSenderId => {
            // Replace sender_node_id with a derivation-distinct id so
            // the per-sender subkey derived inside decrypt_symbol
            // differs from the one used to encrypt.
            decrypt_ctx.sender_node_id =
                TailscaleNodeId::new(&format!("fuzz-other-{:08x}", mutation_index));
        }
        MutationKind::WrongZoneKey => {
            let mut wrong = input.zone_key_seed;
            // Bit-flip one byte to derive a distinct AeadKey.
            wrong[mutation_index % wrong.len()] ^= 0x5A;
            decrypt_zone_key = AeadKey::from_bytes(wrong);
        }
    }

    let result = decrypt_symbol(
        &decrypt_zone_key,
        algorithm,
        &decrypt_ctx,
        &ciphertext,
        &auth_tag,
    );

    match input.mutation {
        MutationKind::Identity => {
            // Property 1: identity round-trip restores the plaintext.
            let recovered = result.expect("identity round-trip must succeed");
            assert_eq!(
                recovered, plaintext,
                "identity round-trip must preserve plaintext"
            );
        }
        // Properties 2 + 3: tampered inputs MUST surface DecryptFailed.
        // CiphertextTooShort is also acceptable on truncation since
        // the chacha20poly1305 layer rejects sub-tag-length inputs.
        _ => {
            assert!(
                matches!(
                    result,
                    Err(SymbolEnvelopeError::DecryptFailed)
                        | Err(SymbolEnvelopeError::CiphertextTooShort { .. })
                ),
                "tampered decrypt must fail authentication, got {result:?}"
            );
        }
    }
});
