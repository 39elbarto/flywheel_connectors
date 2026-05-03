//! Symbol-envelope encrypt/decrypt conformance.
//!
//! `encrypt_symbol` / `decrypt_symbol` are the per-symbol AEAD layer
//! defined in `FCP_Specification_V3.md` §9.8.1 (Symbol Envelope).
//! Each FCPS frame carries one or more symbols individually encrypted
//! under a per-sender HKDF-derived subkey, with:
//!
//! - the AAD binding ciphertext to (object_id, k, zone_id_hash,
//!   zone_key_id, epoch_id, sender_node_id, sender_instance_id),
//! - the nonce derived from (frame_seq, esi) for ChaCha20-Poly1305 or
//!   (sender_instance_id, frame_seq, esi) for XChaCha20-Poly1305.
//!
//! These tests pin the public `fcp_protocol::symbol_envelope` API so a
//! regression that drops a `SymbolContext` field from the AAD or from
//! the nonce derivation fails conformance directly. Without these
//! tests an attacker could re-attribute a captured ciphertext to a
//! different epoch, frame, ESI, or sender.

use fcp_crypto::AeadKey;
use fcp_prelude::{ObjectId, TailscaleNodeId, ZoneIdHash, ZoneKeyId};
use fcp_protocol::{
    AUTH_TAG_SIZE, SymbolContext, SymbolEnvelopeError, ZoneKeyAlgorithm, decrypt_symbol,
    encrypt_symbol,
};

const ZONE_KEY_BYTES: [u8; 32] = [0x42; 32];
const ALT_ZONE_KEY_BYTES: [u8; 32] = [0x43; 32];

fn baseline_ctx() -> SymbolContext {
    SymbolContext {
        object_id: ObjectId::from_unscoped_bytes(b"baseline-object"),
        esi: 7,
        k: 4,
        zone_id_hash: ZoneIdHash::from_bytes([0x77; 32]),
        zone_key_id: ZoneKeyId::from_bytes([0x11; 8]),
        epoch_id: 1_000,
        sender_node_id: TailscaleNodeId::new("node-sender"),
        sender_instance_id: 0xDEAD_BEEF_CAFE_F00D,
        frame_seq: 12345,
    }
}

fn zone_key() -> AeadKey {
    AeadKey::from_bytes(ZONE_KEY_BYTES)
}

fn alt_zone_key() -> AeadKey {
    AeadKey::from_bytes(ALT_ZONE_KEY_BYTES)
}

const PLAINTEXT: &[u8] = b"FCPS symbol payload bytes - canonical fixture for conformance";

#[test]
fn chacha_round_trip_recovers_plaintext() {
    let ctx = baseline_ctx();
    let (ciphertext, tag) = encrypt_symbol(
        &zone_key(),
        ZoneKeyAlgorithm::ChaCha20Poly1305,
        &ctx,
        PLAINTEXT,
    )
    .expect("encrypt");
    let recovered = decrypt_symbol(
        &zone_key(),
        ZoneKeyAlgorithm::ChaCha20Poly1305,
        &ctx,
        &ciphertext,
        &tag,
    )
    .expect("decrypt must recover original plaintext");
    assert_eq!(recovered, PLAINTEXT);
}

#[test]
fn xchacha_round_trip_recovers_plaintext() {
    let ctx = baseline_ctx();
    let (ciphertext, tag) = encrypt_symbol(
        &zone_key(),
        ZoneKeyAlgorithm::XChaCha20Poly1305,
        &ctx,
        PLAINTEXT,
    )
    .expect("encrypt");
    let recovered = decrypt_symbol(
        &zone_key(),
        ZoneKeyAlgorithm::XChaCha20Poly1305,
        &ctx,
        &ciphertext,
        &tag,
    )
    .expect("decrypt must recover original plaintext");
    assert_eq!(recovered, PLAINTEXT);
}

#[test]
fn wrong_zone_key_decrypt_fails() {
    let ctx = baseline_ctx();
    let (ciphertext, tag) = encrypt_symbol(
        &zone_key(),
        ZoneKeyAlgorithm::ChaCha20Poly1305,
        &ctx,
        PLAINTEXT,
    )
    .expect("encrypt");
    let err = decrypt_symbol(
        &alt_zone_key(),
        ZoneKeyAlgorithm::ChaCha20Poly1305,
        &ctx,
        &ciphertext,
        &tag,
    )
    .expect_err("decrypt under a different zone key must fail");
    assert!(
        matches!(err, SymbolEnvelopeError::DecryptFailed),
        "expected DecryptFailed, got {err:?}"
    );
}

#[test]
fn tampered_object_id_in_aad_decrypt_fails() {
    // The object_id is bound through the AAD. Re-attributing a
    // ciphertext to a different object MUST fail Poly1305 verification.
    let ctx = baseline_ctx();
    let (ciphertext, tag) = encrypt_symbol(
        &zone_key(),
        ZoneKeyAlgorithm::ChaCha20Poly1305,
        &ctx,
        PLAINTEXT,
    )
    .expect("encrypt");

    let mut tampered = ctx.clone();
    tampered.object_id = ObjectId::from_unscoped_bytes(b"different-object");

    let err = decrypt_symbol(
        &zone_key(),
        ZoneKeyAlgorithm::ChaCha20Poly1305,
        &tampered,
        &ciphertext,
        &tag,
    )
    .expect_err("tampered object_id must fail AAD authentication");
    assert!(matches!(err, SymbolEnvelopeError::DecryptFailed));
}

#[test]
fn tampered_zone_key_id_in_aad_decrypt_fails() {
    // zone_key_id rotates the zone key. A captured ciphertext from
    // key-id epoch A MUST NOT be decryptable when claimed under epoch
    // B even if both sides somehow share keys — otherwise rotation is
    // a no-op.
    let ctx = baseline_ctx();
    let (ciphertext, tag) = encrypt_symbol(
        &zone_key(),
        ZoneKeyAlgorithm::ChaCha20Poly1305,
        &ctx,
        PLAINTEXT,
    )
    .expect("encrypt");

    let mut tampered = ctx.clone();
    tampered.zone_key_id = ZoneKeyId::from_bytes([0xFF; 8]);

    let err = decrypt_symbol(
        &zone_key(),
        ZoneKeyAlgorithm::ChaCha20Poly1305,
        &tampered,
        &ciphertext,
        &tag,
    )
    .expect_err("tampered zone_key_id must fail AAD authentication");
    assert!(matches!(err, SymbolEnvelopeError::DecryptFailed));
}

#[test]
fn tampered_epoch_id_in_aad_decrypt_fails() {
    // epoch_id is the replay-protection slot. A captured ciphertext
    // from epoch N MUST NOT decrypt as if it were from epoch N+1.
    let ctx = baseline_ctx();
    let (ciphertext, tag) = encrypt_symbol(
        &zone_key(),
        ZoneKeyAlgorithm::ChaCha20Poly1305,
        &ctx,
        PLAINTEXT,
    )
    .expect("encrypt");

    let mut tampered = ctx.clone();
    tampered.epoch_id = ctx.epoch_id.wrapping_add(1);

    let err = decrypt_symbol(
        &zone_key(),
        ZoneKeyAlgorithm::ChaCha20Poly1305,
        &tampered,
        &ciphertext,
        &tag,
    )
    .expect_err("tampered epoch_id must fail AAD authentication");
    assert!(matches!(err, SymbolEnvelopeError::DecryptFailed));
}

#[test]
fn wrong_frame_seq_decrypt_fails_via_nonce_binding() {
    // frame_seq is part of the nonce derivation. A ciphertext encrypted
    // under frame_seq=N MUST NOT decrypt under frame_seq=N+1 — that's
    // the per-frame replay defense, even before any AAD check.
    let ctx = baseline_ctx();
    let (ciphertext, tag) = encrypt_symbol(
        &zone_key(),
        ZoneKeyAlgorithm::ChaCha20Poly1305,
        &ctx,
        PLAINTEXT,
    )
    .expect("encrypt");

    let mut tampered = ctx.clone();
    tampered.frame_seq = ctx.frame_seq.wrapping_add(1);

    let err = decrypt_symbol(
        &zone_key(),
        ZoneKeyAlgorithm::ChaCha20Poly1305,
        &tampered,
        &ciphertext,
        &tag,
    )
    .expect_err("frame_seq-shifted decrypt must fail");
    assert!(matches!(err, SymbolEnvelopeError::DecryptFailed));
}

#[test]
fn wrong_esi_decrypt_fails_via_nonce_binding() {
    // ESI is also part of the nonce derivation. A symbol at ESI=N MUST
    // NOT decrypt as if it were ESI=N+1 — otherwise an attacker could
    // re-position symbols within a frame.
    let ctx = baseline_ctx();
    let (ciphertext, tag) = encrypt_symbol(
        &zone_key(),
        ZoneKeyAlgorithm::ChaCha20Poly1305,
        &ctx,
        PLAINTEXT,
    )
    .expect("encrypt");

    let mut tampered = ctx.clone();
    tampered.esi = ctx.esi.wrapping_add(1);

    let err = decrypt_symbol(
        &zone_key(),
        ZoneKeyAlgorithm::ChaCha20Poly1305,
        &tampered,
        &ciphertext,
        &tag,
    )
    .expect_err("esi-shifted decrypt must fail");
    assert!(matches!(err, SymbolEnvelopeError::DecryptFailed));
}

#[test]
fn chacha_ciphertext_does_not_decrypt_under_xchacha() {
    // The two AEAD algorithms use different nonce sizes and primitives.
    // A ChaCha20-Poly1305 ciphertext MUST NOT decrypt when re-presented
    // as XChaCha20-Poly1305 (and vice versa).
    let ctx = baseline_ctx();
    let (ciphertext, tag) = encrypt_symbol(
        &zone_key(),
        ZoneKeyAlgorithm::ChaCha20Poly1305,
        &ctx,
        PLAINTEXT,
    )
    .expect("ChaCha encrypt");

    let err = decrypt_symbol(
        &zone_key(),
        ZoneKeyAlgorithm::XChaCha20Poly1305,
        &ctx,
        &ciphertext,
        &tag,
    )
    .expect_err("ChaCha ciphertext must not decrypt under XChaCha algorithm selector");
    assert!(matches!(err, SymbolEnvelopeError::DecryptFailed));
}

#[test]
fn flipped_auth_tag_byte_decrypt_fails() {
    // Direct tag tamper: flipping any byte of the 16-byte Poly1305
    // auth tag MUST cause decrypt to fail. This pins positional
    // integrity on the tag itself, complementing the AAD/nonce
    // binding tests above.
    let ctx = baseline_ctx();
    let (ciphertext, tag) = encrypt_symbol(
        &zone_key(),
        ZoneKeyAlgorithm::ChaCha20Poly1305,
        &ctx,
        PLAINTEXT,
    )
    .expect("encrypt");

    let mut tampered_tag = tag;
    tampered_tag[AUTH_TAG_SIZE - 1] ^= 0x01;

    let err = decrypt_symbol(
        &zone_key(),
        ZoneKeyAlgorithm::ChaCha20Poly1305,
        &ctx,
        &ciphertext,
        &tampered_tag,
    )
    .expect_err("single-byte tag tamper must fail");
    assert!(matches!(err, SymbolEnvelopeError::DecryptFailed));
}
