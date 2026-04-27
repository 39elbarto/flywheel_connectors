//! `fcp_raptorq::SymbolEnvelope` round-trip + binding conformance.
//!
//! `fcp-raptorq` carries a higher-level `SymbolEnvelope` type that
//! wraps the AEAD primitive in a self-describing struct (object_id,
//! esi, k, zone_id, zone_key_id, epoch_id, source_id,
//! sender_instance_id, frame_seq, data, auth_tag). This is distinct
//! from the lower-level `fcp-protocol` envelope pinned in
//! br-2qkn0 — fcp-raptorq's variant adds a structured
//! `ZoneKeyIdMismatch` fast-fail returned BEFORE the AEAD primitive
//! when the caller-supplied `zone_key_id` does not match the
//! envelope's own `zone_key_id`.
//!
//! The fast-fail is a documented contract: callers can distinguish
//! "wrong key id" (a routing / rotation mistake) from "tampered
//! ciphertext" (a security signal) without leaking timing
//! information against the AEAD primitive. These tests pin both
//! that fast-fail behaviour AND the AAD/nonce binding for every
//! identity-mixed field.

use fcp_core::{ObjectId, ZoneId, ZoneKey, ZoneKeyAlgorithm, ZoneKeyId};
use fcp_raptorq::{SymbolEnvelope, SymbolEnvelopeError};
use fcp_tailscale::NodeId;

const ZONE_KEY_BYTES: [u8; 32] = [0x42; 32];
const ALT_ZONE_KEY_BYTES: [u8; 32] = [0x43; 32];

fn zone_key() -> ZoneKey {
    ZoneKey::from_bytes(ZONE_KEY_BYTES)
}

fn alt_zone_key() -> ZoneKey {
    ZoneKey::from_bytes(ALT_ZONE_KEY_BYTES)
}

const PLAINTEXT: &[u8] = b"FCP raptorq symbol payload - canonical fixture for conformance";

fn baseline_envelope(algorithm: ZoneKeyAlgorithm) -> SymbolEnvelope {
    SymbolEnvelope::encrypt(
        ObjectId::from_bytes([0x11; 32]),
        7,                              // esi
        4,                              // k
        PLAINTEXT,
        ZoneId::work(),
        ZoneKeyId::from_bytes([0x22; 8]),
        1_000,                          // epoch_id
        NodeId::new("node-source"),
        0xDEAD_BEEF_CAFE_F00D,          // sender_instance_id
        12_345,                         // frame_seq
        &zone_key(),
        algorithm,
    )
    .expect("baseline encrypt")
}

#[test]
fn chacha_round_trip_recovers_plaintext() {
    let env = baseline_envelope(ZoneKeyAlgorithm::ChaCha20Poly1305);
    let recovered = env
        .decrypt(
            &zone_key(),
            ZoneKeyAlgorithm::ChaCha20Poly1305,
            ZoneKeyId::from_bytes([0x22; 8]),
        )
        .expect("decrypt must recover plaintext");
    assert_eq!(recovered, PLAINTEXT);
}

#[test]
fn xchacha_round_trip_recovers_plaintext() {
    let env = baseline_envelope(ZoneKeyAlgorithm::XChaCha20Poly1305);
    let recovered = env
        .decrypt(
            &zone_key(),
            ZoneKeyAlgorithm::XChaCha20Poly1305,
            ZoneKeyId::from_bytes([0x22; 8]),
        )
        .expect("decrypt must recover plaintext");
    assert_eq!(recovered, PLAINTEXT);
}

#[test]
fn zone_key_id_mismatch_fast_fails_before_aead() {
    // The structured ZoneKeyIdMismatch is returned BEFORE the AEAD
    // primitive runs, so callers can distinguish a routing/rotation
    // mistake from a tampered ciphertext. This test pins the
    // fast-fail behaviour AND the structured payload (expected vs
    // found ids).
    let env = baseline_envelope(ZoneKeyAlgorithm::ChaCha20Poly1305);
    let wrong_kid = ZoneKeyId::from_bytes([0xFF; 8]);
    let envelope_kid = ZoneKeyId::from_bytes([0x22; 8]);

    let err = env
        .decrypt(&zone_key(), ZoneKeyAlgorithm::ChaCha20Poly1305, wrong_kid)
        .expect_err("zone_key_id mismatch must fast-fail");
    match err {
        SymbolEnvelopeError::ZoneKeyIdMismatch { expected, found } => {
            assert_eq!(
                expected, wrong_kid,
                "ZoneKeyIdMismatch.expected must report the caller-supplied id"
            );
            assert_eq!(
                found, envelope_kid,
                "ZoneKeyIdMismatch.found must report the envelope's own id"
            );
        }
        other => panic!("expected ZoneKeyIdMismatch, got {other:?}"),
    }
}

#[test]
fn wrong_zone_key_decrypt_fails_via_aead() {
    // When zone_key_id matches but the underlying zone_key is wrong,
    // the AEAD primitive must reject — this is the security-signal
    // path, distinct from ZoneKeyIdMismatch.
    let env = baseline_envelope(ZoneKeyAlgorithm::ChaCha20Poly1305);
    let err = env
        .decrypt(
            &alt_zone_key(),
            ZoneKeyAlgorithm::ChaCha20Poly1305,
            ZoneKeyId::from_bytes([0x22; 8]),
        )
        .expect_err("decrypt under a different zone key must fail");
    assert!(
        matches!(err, SymbolEnvelopeError::DecryptFailed),
        "expected DecryptFailed (NOT ZoneKeyIdMismatch), got {err:?}"
    );
}

#[test]
fn tampered_ciphertext_decrypt_fails() {
    let mut env = baseline_envelope(ZoneKeyAlgorithm::ChaCha20Poly1305);
    if let Some(byte) = env.data.first_mut() {
        *byte ^= 0x01;
    } else {
        panic!("fixture ciphertext is unexpectedly empty");
    }
    let err = env
        .decrypt(
            &zone_key(),
            ZoneKeyAlgorithm::ChaCha20Poly1305,
            ZoneKeyId::from_bytes([0x22; 8]),
        )
        .expect_err("tampered ciphertext must fail authentication");
    assert!(matches!(err, SymbolEnvelopeError::DecryptFailed));
}

#[test]
fn flipped_auth_tag_byte_decrypt_fails() {
    let mut env = baseline_envelope(ZoneKeyAlgorithm::ChaCha20Poly1305);
    env.auth_tag[0] ^= 0x01;
    let err = env
        .decrypt(
            &zone_key(),
            ZoneKeyAlgorithm::ChaCha20Poly1305,
            ZoneKeyId::from_bytes([0x22; 8]),
        )
        .expect_err("auth_tag tamper must fail authentication");
    assert!(matches!(err, SymbolEnvelopeError::DecryptFailed));
}

#[test]
fn tampered_object_id_in_aad_decrypt_fails() {
    let mut env = baseline_envelope(ZoneKeyAlgorithm::ChaCha20Poly1305);
    env.object_id = ObjectId::from_bytes([0x99; 32]);
    let err = env
        .decrypt(
            &zone_key(),
            ZoneKeyAlgorithm::ChaCha20Poly1305,
            ZoneKeyId::from_bytes([0x22; 8]),
        )
        .expect_err("object_id is part of the AAD; tamper must fail");
    assert!(matches!(err, SymbolEnvelopeError::DecryptFailed));
}

#[test]
fn tampered_epoch_id_in_aad_decrypt_fails() {
    let mut env = baseline_envelope(ZoneKeyAlgorithm::ChaCha20Poly1305);
    env.epoch_id = env.epoch_id.wrapping_add(1);
    let err = env
        .decrypt(
            &zone_key(),
            ZoneKeyAlgorithm::ChaCha20Poly1305,
            ZoneKeyId::from_bytes([0x22; 8]),
        )
        .expect_err("epoch_id is part of the AAD; cross-epoch replay defense");
    assert!(matches!(err, SymbolEnvelopeError::DecryptFailed));
}

#[test]
fn tampered_source_id_decrypt_fails() {
    // source_id flows into the per-sender subkey derivation. An
    // attacker who rewrites it after the fact must fail decryption.
    let mut env = baseline_envelope(ZoneKeyAlgorithm::ChaCha20Poly1305);
    env.source_id = NodeId::new("node-attacker");
    let err = env
        .decrypt(
            &zone_key(),
            ZoneKeyAlgorithm::ChaCha20Poly1305,
            ZoneKeyId::from_bytes([0x22; 8]),
        )
        .expect_err("source_id binding must reject post-encrypt rewrite");
    assert!(matches!(err, SymbolEnvelopeError::DecryptFailed));
}

#[test]
fn tampered_sender_instance_id_decrypt_fails() {
    // sender_instance_id binds to the subkey AND (under XChaCha) to
    // the nonce. Either path must reject a post-encrypt rewrite.
    let mut env = baseline_envelope(ZoneKeyAlgorithm::ChaCha20Poly1305);
    env.sender_instance_id = env.sender_instance_id.wrapping_add(1);
    let err = env
        .decrypt(
            &zone_key(),
            ZoneKeyAlgorithm::ChaCha20Poly1305,
            ZoneKeyId::from_bytes([0x22; 8]),
        )
        .expect_err("sender_instance_id binding must reject post-encrypt rewrite");
    assert!(matches!(err, SymbolEnvelopeError::DecryptFailed));
}

#[test]
fn tampered_frame_seq_decrypt_fails_via_nonce() {
    // frame_seq is part of the nonce derivation. Replaying at a
    // shifted seq must fail.
    let mut env = baseline_envelope(ZoneKeyAlgorithm::ChaCha20Poly1305);
    env.frame_seq = env.frame_seq.wrapping_add(1);
    let err = env
        .decrypt(
            &zone_key(),
            ZoneKeyAlgorithm::ChaCha20Poly1305,
            ZoneKeyId::from_bytes([0x22; 8]),
        )
        .expect_err("frame_seq nonce-binding must reject post-encrypt rewrite");
    assert!(matches!(err, SymbolEnvelopeError::DecryptFailed));
}

#[test]
fn tampered_esi_decrypt_fails_via_nonce() {
    let mut env = baseline_envelope(ZoneKeyAlgorithm::ChaCha20Poly1305);
    env.esi = env.esi.wrapping_add(1);
    let err = env
        .decrypt(
            &zone_key(),
            ZoneKeyAlgorithm::ChaCha20Poly1305,
            ZoneKeyId::from_bytes([0x22; 8]),
        )
        .expect_err("esi nonce-binding must reject post-encrypt rewrite");
    assert!(matches!(err, SymbolEnvelopeError::DecryptFailed));
}

#[test]
fn chacha_envelope_does_not_decrypt_under_xchacha_selector() {
    // The two algorithms use different nonce sizes and primitives.
    // Re-presenting a ChaCha envelope as XChaCha must fail.
    let env = baseline_envelope(ZoneKeyAlgorithm::ChaCha20Poly1305);
    let err = env
        .decrypt(
            &zone_key(),
            ZoneKeyAlgorithm::XChaCha20Poly1305,
            ZoneKeyId::from_bytes([0x22; 8]),
        )
        .expect_err("algorithm cross-decrypt must fail");
    assert!(matches!(err, SymbolEnvelopeError::DecryptFailed));
}
