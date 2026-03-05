//! `SymbolEnvelope` encryption and decryption for FCPS frames.
//!
//! Implements the per-symbol AEAD encryption layer defined in `FCP_Specification_V2.md`.
//!
//! # Encryption Model
//!
//! Each symbol in an FCPS frame is encrypted individually using zone keys:
//!
//! 1. **Subkey derivation**: Per-sender subkeys are derived from the zone key using HKDF
//! 2. **Nonce derivation**: Deterministic nonces from (`sender_instance_id`, `frame_seq`, ESI)
//! 3. **AAD binding**: Fixed 86-byte AAD binds ciphertext to object/zone/epoch context
//! 4. **AEAD**: ChaCha20-Poly1305 (12-byte nonce) or XChaCha20-Poly1305 (24-byte nonce)
//!
//! # Wire Format Integration
//!
//! Encrypted symbols are carried in `SymbolRecord` structs within `FcpsFrame`:
//! - `SymbolRecord.data`: encrypted symbol data
//! - `SymbolRecord.auth_tag`: 16-byte Poly1305 tag
//!
//! The nonce is NOT transmitted; it's derived deterministically from frame fields.

use fcp_core::{ObjectId, TailscaleNodeId, ZoneIdHash, ZoneKeyId};
use fcp_crypto::{
    AeadKey, ChaCha20Nonce, ChaCha20Poly1305Cipher, XChaCha20Nonce, XChaCha20Poly1305Cipher,
    hkdf_sha256_array,
};
use thiserror::Error;

/// Authentication tag size (Poly1305: 16 bytes).
pub const AUTH_TAG_SIZE: usize = 16;

/// AAD size for symbol encryption (NORMATIVE: 86 bytes).
pub const SYMBOL_AAD_SIZE: usize = 86;

/// `SymbolEnvelope` errors.
#[derive(Debug, Error)]
pub enum SymbolEnvelopeError {
    #[error("AEAD encryption failed")]
    EncryptFailed,

    #[error("AEAD decryption failed (authentication or key mismatch)")]
    DecryptFailed,

    #[error("ciphertext too short (len {len}, need at least {min} for tag)")]
    CiphertextTooShort { len: usize, min: usize },
}

/// Zone key algorithm selector (NORMATIVE).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ZoneKeyAlgorithm {
    /// ChaCha20-Poly1305 with 12-byte nonce (default).
    #[default]
    ChaCha20Poly1305,
    /// XChaCha20-Poly1305 with 24-byte nonce (extended nonce variant).
    XChaCha20Poly1305,
}

/// Encryption context for a symbol envelope.
///
/// Contains all the fields needed to derive nonces and construct AAD.
#[derive(Debug, Clone)]
pub struct SymbolContext {
    /// Content-addressed object ID (32 bytes).
    pub object_id: ObjectId,
    /// Encoding Symbol ID.
    pub esi: u32,
    /// Source symbols needed for reconstruction (K).
    pub k: u16,
    /// Zone ID hash (32 bytes).
    pub zone_id_hash: ZoneIdHash,
    /// Zone key ID for rotation (8 bytes).
    pub zone_key_id: ZoneKeyId,
    /// Epoch ID for replay protection.
    pub epoch_id: u64,
    /// Sender node ID (Tailscale node ID).
    pub sender_node_id: TailscaleNodeId,
    /// Sender instance ID (random u64 at process startup).
    pub sender_instance_id: u64,
    /// Per-sender monotonic frame sequence number.
    pub frame_seq: u64,
}

/// Derive a per-sender subkey from the zone key (NORMATIVE).
///
/// Uses HKDF-SHA256 with:
/// - Salt: `zone_key_id` (8 bytes)
/// - IKM: `zone_key` bytes
/// - Info: "FCP2-SENDER-KEY-V1" || `sender_node_id` || `sender_instance_id_le`
///
/// # Arguments
///
/// * `zone_key` - The zone encryption key
/// * `zone_key_id` - Zone key identifier (8 bytes)
/// * `sender_node_id` - Sender node identifier
/// * `sender_instance_id` - Unique sender instance identifier
///
/// # Panics
///
/// Panics if HKDF expansion fails (should never happen for 32-byte output).
#[must_use]
pub fn derive_sender_subkey(
    zone_key: &AeadKey,
    zone_key_id: &ZoneKeyId,
    sender_node_id: &TailscaleNodeId,
    sender_instance_id: u64,
) -> AeadKey {
    let mut info = Vec::with_capacity(22 + sender_node_id.as_str().len() + 12);
    info.extend_from_slice(b"FCP2-SENDER-KEY-V1");

    let sender_bytes = sender_node_id.as_str().as_bytes();
    info.extend_from_slice(
        &u32::try_from(sender_bytes.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    info.extend_from_slice(sender_bytes);

    info.extend_from_slice(&sender_instance_id.to_le_bytes());

    let subkey_bytes: [u8; 32] =
        hkdf_sha256_array(Some(zone_key_id.as_bytes()), zone_key.as_bytes(), &info)
            .expect("HKDF expansion failed");
    AeadKey::from_bytes(subkey_bytes)
}

/// Derive a 12-byte `ChaCha20` nonce (NORMATIVE for ChaCha20-Poly1305).
///
/// Layout:
/// - Bytes 0-7: `frame_seq` (u64 LE)
/// - Bytes 8-11: ESI (u32 LE)
///
/// # Arguments
///
/// * `frame_seq` - Per-sender monotonic frame sequence number
/// * `esi` - Encoding Symbol ID
#[must_use]
pub fn derive_nonce12(frame_seq: u64, esi: u32) -> ChaCha20Nonce {
    let mut nonce = [0u8; 12];
    nonce[0..8].copy_from_slice(&frame_seq.to_le_bytes());
    nonce[8..12].copy_from_slice(&esi.to_le_bytes());
    ChaCha20Nonce::from_bytes(nonce)
}

/// Derive a 24-byte `XChaCha20` nonce (NORMATIVE for XChaCha20-Poly1305).
///
/// Layout:
/// - Bytes 0-7: `sender_instance_id` (u64 LE)
/// - Bytes 8-15: `frame_seq` (u64 LE)
/// - Bytes 16-19: ESI (u32 LE)
/// - Bytes 20-23: zero padding
///
/// # Arguments
///
/// * `sender_instance_id` - Unique sender instance identifier
/// * `frame_seq` - Per-sender monotonic frame sequence number
/// * `esi` - Encoding Symbol ID
#[must_use]
pub fn derive_nonce24(sender_instance_id: u64, frame_seq: u64, esi: u32) -> XChaCha20Nonce {
    let mut nonce = [0u8; 24];
    nonce[0..8].copy_from_slice(&sender_instance_id.to_le_bytes());
    nonce[8..16].copy_from_slice(&frame_seq.to_le_bytes());
    nonce[16..20].copy_from_slice(&esi.to_le_bytes());
    // Bytes 20-23 remain zero
    XChaCha20Nonce::from_bytes(nonce)
}

/// Build the Additional Authenticated Data (AAD) for symbol encryption (NORMATIVE).
///
/// Fixed 86-byte structure:
/// - Bytes 0-31: `object_id` (32 bytes)
/// - Bytes 32-35: ESI (u32 LE)
/// - Bytes 36-37: K (u16 LE)
/// - Bytes 38-69: `zone_id_hash` (32 bytes)
/// - Bytes 70-77: `zone_key_id` (8 bytes)
/// - Bytes 78-85: `epoch_id` (u64 LE)
///
/// # Arguments
///
/// * `ctx` - Symbol encryption context
#[must_use]
pub fn build_symbol_aad(ctx: &SymbolContext) -> [u8; SYMBOL_AAD_SIZE] {
    let mut aad = [0u8; SYMBOL_AAD_SIZE];

    aad[0..32].copy_from_slice(ctx.object_id.as_bytes());
    aad[32..36].copy_from_slice(&ctx.esi.to_le_bytes());
    aad[36..38].copy_from_slice(&ctx.k.to_le_bytes());
    aad[38..70].copy_from_slice(ctx.zone_id_hash.as_bytes());
    aad[70..78].copy_from_slice(ctx.zone_key_id.as_bytes());
    aad[78..86].copy_from_slice(&ctx.epoch_id.to_le_bytes());

    aad
}

/// Encrypt a symbol payload using zone key (NORMATIVE).
///
/// Returns (ciphertext, `auth_tag`) suitable for `SymbolRecord`.
///
/// # Arguments
///
/// * `zone_key` - Zone encryption key (will be used to derive sender subkey)
/// * `algorithm` - AEAD algorithm to use
/// * `ctx` - Symbol encryption context
/// * `plaintext` - Raw symbol data to encrypt
///
/// # Errors
///
/// Returns `SymbolEnvelopeError::EncryptFailed` if AEAD encryption fails.
pub fn encrypt_symbol(
    zone_key: &AeadKey,
    algorithm: ZoneKeyAlgorithm,
    ctx: &SymbolContext,
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; AUTH_TAG_SIZE]), SymbolEnvelopeError> {
    let sender_key = derive_sender_subkey(
        zone_key,
        &ctx.zone_key_id,
        &ctx.sender_node_id,
        ctx.sender_instance_id,
    );
    let aad = build_symbol_aad(ctx);

    let ciphertext_with_tag = match algorithm {
        ZoneKeyAlgorithm::ChaCha20Poly1305 => {
            let nonce = derive_nonce12(ctx.frame_seq, ctx.esi);
            let cipher = ChaCha20Poly1305Cipher::new(&sender_key);
            cipher
                .encrypt(&nonce, plaintext, &aad)
                .map_err(|_| SymbolEnvelopeError::EncryptFailed)?
        }
        ZoneKeyAlgorithm::XChaCha20Poly1305 => {
            let nonce = derive_nonce24(ctx.sender_instance_id, ctx.frame_seq, ctx.esi);
            let cipher = XChaCha20Poly1305Cipher::new(&sender_key);
            cipher
                .encrypt(&nonce, plaintext, &aad)
                .map_err(|_| SymbolEnvelopeError::EncryptFailed)?
        }
    };

    // Split ciphertext and tag (chacha20poly1305 crate appends tag)
    if ciphertext_with_tag.len() < AUTH_TAG_SIZE {
        return Err(SymbolEnvelopeError::EncryptFailed);
    }

    let tag_offset = ciphertext_with_tag.len() - AUTH_TAG_SIZE;
    let ciphertext = ciphertext_with_tag[..tag_offset].to_vec();
    let mut auth_tag = [0u8; AUTH_TAG_SIZE];
    auth_tag.copy_from_slice(&ciphertext_with_tag[tag_offset..]);

    Ok((ciphertext, auth_tag))
}

/// Decrypt a symbol payload using zone key (NORMATIVE).
///
/// # Arguments
///
/// * `zone_key` - Zone encryption key (will be used to derive sender subkey)
/// * `algorithm` - AEAD algorithm to use
/// * `ctx` - Symbol encryption context
/// * `ciphertext` - Encrypted symbol data
/// * `auth_tag` - Authentication tag from `SymbolRecord`
///
/// # Errors
///
/// Returns `SymbolEnvelopeError::DecryptFailed` if AEAD decryption fails
/// (wrong key, corrupted ciphertext, or AAD mismatch).
pub fn decrypt_symbol(
    zone_key: &AeadKey,
    algorithm: ZoneKeyAlgorithm,
    ctx: &SymbolContext,
    ciphertext: &[u8],
    auth_tag: &[u8; AUTH_TAG_SIZE],
) -> Result<Vec<u8>, SymbolEnvelopeError> {
    let sender_key = derive_sender_subkey(
        zone_key,
        &ctx.zone_key_id,
        &ctx.sender_node_id,
        ctx.sender_instance_id,
    );
    let aad = build_symbol_aad(ctx);

    // Reconstruct ciphertext || tag for the AEAD crate
    let mut ciphertext_with_tag = Vec::with_capacity(ciphertext.len() + AUTH_TAG_SIZE);
    ciphertext_with_tag.extend_from_slice(ciphertext);
    ciphertext_with_tag.extend_from_slice(auth_tag);

    match algorithm {
        ZoneKeyAlgorithm::ChaCha20Poly1305 => {
            let nonce = derive_nonce12(ctx.frame_seq, ctx.esi);
            let cipher = ChaCha20Poly1305Cipher::new(&sender_key);
            cipher
                .decrypt(&nonce, &ciphertext_with_tag, &aad)
                .map_err(|_| SymbolEnvelopeError::DecryptFailed)
        }
        ZoneKeyAlgorithm::XChaCha20Poly1305 => {
            let nonce = derive_nonce24(ctx.sender_instance_id, ctx.frame_seq, ctx.esi);
            let cipher = XChaCha20Poly1305Cipher::new(&sender_key);
            cipher
                .decrypt(&nonce, &ciphertext_with_tag, &aad)
                .map_err(|_| SymbolEnvelopeError::DecryptFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_context() -> SymbolContext {
        SymbolContext {
            object_id: ObjectId::from_bytes([0x11; 32]),
            esi: 42,
            k: 10,
            zone_id_hash: ZoneIdHash::from_bytes([0x22; 32]),
            zone_key_id: ZoneKeyId::from_bytes([0x33; 8]),
            epoch_id: 1000,
            sender_node_id: TailscaleNodeId::new("node-test"),
            sender_instance_id: 0xDEAD_BEEF_CAFE_BABE,
            frame_seq: 123,
        }
    }

    #[test]
    fn subkey_derivation_deterministic() {
        let zone_key = AeadKey::from_bytes([0xAA; 32]);
        let zone_key_id = ZoneKeyId::from_bytes([0x10; 8]);
        let sender_node_id = TailscaleNodeId::new("node-a");
        let sender_instance_id = 12345u64;

        let subkey1 =
            derive_sender_subkey(&zone_key, &zone_key_id, &sender_node_id, sender_instance_id);
        let subkey2 =
            derive_sender_subkey(&zone_key, &zone_key_id, &sender_node_id, sender_instance_id);

        assert_eq!(subkey1.as_bytes(), subkey2.as_bytes());
    }

    #[test]
    fn subkey_derivation_unique_per_sender() {
        let zone_key = AeadKey::from_bytes([0xAA; 32]);
        let zone_key_id = ZoneKeyId::from_bytes([0x10; 8]);
        let sender_node_id = TailscaleNodeId::new("node-a");

        let subkey1 = derive_sender_subkey(&zone_key, &zone_key_id, &sender_node_id, 1);
        let subkey2 = derive_sender_subkey(&zone_key, &zone_key_id, &sender_node_id, 2);

        assert_ne!(subkey1.as_bytes(), subkey2.as_bytes());
    }

    #[test]
    fn nonce12_structure() {
        let nonce = derive_nonce12(0x0102_0304_0506_0708, 0x0A0B_0C0D);
        let bytes = nonce.as_bytes();

        // frame_seq in first 8 bytes (LE)
        assert_eq!(
            &bytes[0..8],
            &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );
        // ESI in last 4 bytes (LE)
        assert_eq!(&bytes[8..12], &[0x0D, 0x0C, 0x0B, 0x0A]);
    }

    #[test]
    fn nonce24_structure() {
        let nonce = derive_nonce24(0x0102_0304_0506_0708, 0x1112_1314_1516_1718, 0x2122_2324);
        let bytes = nonce.as_bytes();

        // sender_instance_id in first 8 bytes (LE)
        assert_eq!(
            &bytes[0..8],
            &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );
        // frame_seq in next 8 bytes (LE)
        assert_eq!(
            &bytes[8..16],
            &[0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11]
        );
        // ESI in next 4 bytes (LE)
        assert_eq!(&bytes[16..20], &[0x24, 0x23, 0x22, 0x21]);
        // Zero padding
        assert_eq!(&bytes[20..24], &[0, 0, 0, 0]);
    }

    #[test]
    fn aad_structure() {
        let ctx = test_context();
        let aad = build_symbol_aad(&ctx);

        assert_eq!(aad.len(), SYMBOL_AAD_SIZE);

        // object_id
        assert_eq!(&aad[0..32], &[0x11; 32]);
        // ESI = 42
        assert_eq!(&aad[32..36], &42u32.to_le_bytes());
        // K = 10
        assert_eq!(&aad[36..38], &10u16.to_le_bytes());
        // zone_id_hash
        assert_eq!(&aad[38..70], &[0x22; 32]);
        // zone_key_id
        assert_eq!(&aad[70..78], &[0x33; 8]);
        // epoch_id = 1000
        assert_eq!(&aad[78..86], &1000u64.to_le_bytes());
    }

    #[test]
    fn chacha20_encrypt_decrypt_roundtrip() {
        let zone_key = AeadKey::generate();
        let ctx = test_context();
        let plaintext = b"test symbol data for encryption";

        let (ciphertext, auth_tag) = encrypt_symbol(
            &zone_key,
            ZoneKeyAlgorithm::ChaCha20Poly1305,
            &ctx,
            plaintext,
        )
        .unwrap();

        assert_eq!(ciphertext.len(), plaintext.len());

        let decrypted = decrypt_symbol(
            &zone_key,
            ZoneKeyAlgorithm::ChaCha20Poly1305,
            &ctx,
            &ciphertext,
            &auth_tag,
        )
        .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn xchacha20_encrypt_decrypt_roundtrip() {
        let zone_key = AeadKey::generate();
        let ctx = test_context();
        let plaintext = b"test symbol data for xchacha encryption";

        let (ciphertext, auth_tag) = encrypt_symbol(
            &zone_key,
            ZoneKeyAlgorithm::XChaCha20Poly1305,
            &ctx,
            plaintext,
        )
        .unwrap();

        assert_eq!(ciphertext.len(), plaintext.len());

        let decrypted = decrypt_symbol(
            &zone_key,
            ZoneKeyAlgorithm::XChaCha20Poly1305,
            &ctx,
            &ciphertext,
            &auth_tag,
        )
        .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_zone_key_fails() {
        let zone_key1 = AeadKey::generate();
        let zone_key2 = AeadKey::generate();
        let ctx = test_context();
        let plaintext = b"secret data";

        let (ciphertext, auth_tag) = encrypt_symbol(
            &zone_key1,
            ZoneKeyAlgorithm::ChaCha20Poly1305,
            &ctx,
            plaintext,
        )
        .unwrap();

        let result = decrypt_symbol(
            &zone_key2,
            ZoneKeyAlgorithm::ChaCha20Poly1305,
            &ctx,
            &ciphertext,
            &auth_tag,
        );

        assert!(matches!(result, Err(SymbolEnvelopeError::DecryptFailed)));
    }

    #[test]
    fn wrong_context_fails() {
        let zone_key = AeadKey::generate();
        let ctx1 = test_context();
        let mut ctx2 = test_context();
        ctx2.esi = 999; // Different ESI

        let plaintext = b"secret data";

        let (ciphertext, auth_tag) = encrypt_symbol(
            &zone_key,
            ZoneKeyAlgorithm::ChaCha20Poly1305,
            &ctx1,
            plaintext,
        )
        .unwrap();

        let result = decrypt_symbol(
            &zone_key,
            ZoneKeyAlgorithm::ChaCha20Poly1305,
            &ctx2,
            &ciphertext,
            &auth_tag,
        );

        assert!(matches!(result, Err(SymbolEnvelopeError::DecryptFailed)));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let zone_key = AeadKey::generate();
        let ctx = test_context();
        let plaintext = b"secret data";

        let (mut ciphertext, auth_tag) = encrypt_symbol(
            &zone_key,
            ZoneKeyAlgorithm::ChaCha20Poly1305,
            &ctx,
            plaintext,
        )
        .unwrap();

        ciphertext[0] ^= 0xFF; // Tamper

        let result = decrypt_symbol(
            &zone_key,
            ZoneKeyAlgorithm::ChaCha20Poly1305,
            &ctx,
            &ciphertext,
            &auth_tag,
        );

        assert!(matches!(result, Err(SymbolEnvelopeError::DecryptFailed)));
    }

    #[test]
    fn tampered_tag_fails() {
        let zone_key = AeadKey::generate();
        let ctx = test_context();
        let plaintext = b"secret data";

        let (ciphertext, mut auth_tag) = encrypt_symbol(
            &zone_key,
            ZoneKeyAlgorithm::ChaCha20Poly1305,
            &ctx,
            plaintext,
        )
        .unwrap();

        auth_tag[0] ^= 0xFF; // Tamper

        let result = decrypt_symbol(
            &zone_key,
            ZoneKeyAlgorithm::ChaCha20Poly1305,
            &ctx,
            &ciphertext,
            &auth_tag,
        );

        assert!(matches!(result, Err(SymbolEnvelopeError::DecryptFailed)));
    }

    #[test]
    fn empty_plaintext() {
        let zone_key = AeadKey::generate();
        let ctx = test_context();
        let plaintext: &[u8] = b"";

        let (ciphertext, auth_tag) = encrypt_symbol(
            &zone_key,
            ZoneKeyAlgorithm::ChaCha20Poly1305,
            &ctx,
            plaintext,
        )
        .unwrap();

        assert!(ciphertext.is_empty());

        let decrypted = decrypt_symbol(
            &zone_key,
            ZoneKeyAlgorithm::ChaCha20Poly1305,
            &ctx,
            &ciphertext,
            &auth_tag,
        )
        .unwrap();

        assert!(decrypted.is_empty());
    }

    #[test]
    fn large_payload() {
        let zone_key = AeadKey::generate();
        let ctx = test_context();
        let plaintext = vec![0xABu8; 1024]; // Default symbol size

        let (ciphertext, auth_tag) = encrypt_symbol(
            &zone_key,
            ZoneKeyAlgorithm::ChaCha20Poly1305,
            &ctx,
            &plaintext,
        )
        .unwrap();

        let decrypted = decrypt_symbol(
            &zone_key,
            ZoneKeyAlgorithm::ChaCha20Poly1305,
            &ctx,
            &ciphertext,
            &auth_tag,
        )
        .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    // ── Batch 2: SunnyMoose test expansion ──

    #[test]
    fn different_esi_same_frame_different_ciphertext() {
        let zone_key = AeadKey::generate();
        let mut first = test_context();
        first.esi = 0;
        let mut second = test_context();
        second.esi = 1;
        let plaintext = b"same data for different ESIs";

        let (encrypted_first, _) = encrypt_symbol(
            &zone_key,
            ZoneKeyAlgorithm::ChaCha20Poly1305,
            &first,
            plaintext,
        )
        .unwrap();
        let (encrypted_second, _) = encrypt_symbol(
            &zone_key,
            ZoneKeyAlgorithm::ChaCha20Poly1305,
            &second,
            plaintext,
        )
        .unwrap();
        assert_ne!(
            encrypted_first, encrypted_second,
            "different ESIs should yield different ciphertext"
        );
    }

    #[test]
    fn different_epoch_fails_decrypt() {
        // epoch_id is bound via AAD, so encrypting with one epoch and
        // decrypting with another must fail authentication
        let zone_key = AeadKey::generate();
        let mut ctx_enc = test_context();
        ctx_enc.epoch_id = 1;
        let mut ctx_dec = test_context();
        ctx_dec.epoch_id = 2;
        let plaintext = b"epoch transition test";

        let (ciphertext, auth_tag) = encrypt_symbol(
            &zone_key,
            ZoneKeyAlgorithm::ChaCha20Poly1305,
            &ctx_enc,
            plaintext,
        )
        .unwrap();
        let result = decrypt_symbol(
            &zone_key,
            ZoneKeyAlgorithm::ChaCha20Poly1305,
            &ctx_dec,
            &ciphertext,
            &auth_tag,
        );
        assert!(matches!(result, Err(SymbolEnvelopeError::DecryptFailed)));
    }

    #[test]
    fn wrong_zone_key_id_context_fails() {
        let zone_key = AeadKey::generate();
        let ctx = test_context();
        let plaintext = b"zone key id check";

        let (ciphertext, auth_tag) = encrypt_symbol(
            &zone_key,
            ZoneKeyAlgorithm::ChaCha20Poly1305,
            &ctx,
            plaintext,
        )
        .unwrap();

        let mut wrong_ctx = test_context();
        wrong_ctx.zone_key_id = ZoneKeyId::from_bytes([0xFF; 8]);
        let result = decrypt_symbol(
            &zone_key,
            ZoneKeyAlgorithm::ChaCha20Poly1305,
            &wrong_ctx,
            &ciphertext,
            &auth_tag,
        );
        assert!(matches!(result, Err(SymbolEnvelopeError::DecryptFailed)));
    }

    #[test]
    fn subkey_unique_per_node() {
        let zone_key = AeadKey::from_bytes([0xCC; 32]);
        let zone_key_id = ZoneKeyId::from_bytes([0x10; 8]);
        let subkey_a =
            derive_sender_subkey(&zone_key, &zone_key_id, &TailscaleNodeId::new("node-x"), 1);
        let subkey_b =
            derive_sender_subkey(&zone_key, &zone_key_id, &TailscaleNodeId::new("node-y"), 1);
        assert_ne!(subkey_a.as_bytes(), subkey_b.as_bytes());
    }

    #[test]
    fn xchacha20_wrong_key_fails() {
        let zone_key = AeadKey::generate();
        let wrong_key = AeadKey::generate();
        let ctx = test_context();
        let plaintext = b"xchacha wrong key";

        let (ciphertext, auth_tag) = encrypt_symbol(
            &zone_key,
            ZoneKeyAlgorithm::XChaCha20Poly1305,
            &ctx,
            plaintext,
        )
        .unwrap();

        let result = decrypt_symbol(
            &wrong_key,
            ZoneKeyAlgorithm::XChaCha20Poly1305,
            &ctx,
            &ciphertext,
            &auth_tag,
        );
        assert!(matches!(result, Err(SymbolEnvelopeError::DecryptFailed)));
    }

    #[test]
    fn algorithm_default_is_chacha20() {
        let algo = ZoneKeyAlgorithm::default();
        assert_eq!(algo, ZoneKeyAlgorithm::ChaCha20Poly1305);
    }

    #[test]
    fn error_display_messages() {
        assert_eq!(
            SymbolEnvelopeError::EncryptFailed.to_string(),
            "AEAD encryption failed"
        );
        assert_eq!(
            SymbolEnvelopeError::DecryptFailed.to_string(),
            "AEAD decryption failed (authentication or key mismatch)"
        );
        let ct_err = SymbolEnvelopeError::CiphertextTooShort { len: 5, min: 16 };
        assert_eq!(
            ct_err.to_string(),
            "ciphertext too short (len 5, need at least 16 for tag)"
        );
    }

    #[test]
    fn aad_includes_all_context_fields() {
        // Verify AAD binds all relevant fields by checking that changing any
        // context field produces a different AAD
        let base = test_context();
        let base_aad = build_symbol_aad(&base);

        // Change object_id
        let mut c = test_context();
        c.object_id = ObjectId::from_bytes([0xFF; 32]);
        assert_ne!(build_symbol_aad(&c), base_aad, "object_id should be bound");

        // Change k
        let mut c = test_context();
        c.k = 999;
        assert_ne!(build_symbol_aad(&c), base_aad, "k should be bound");

        // Change zone_id_hash
        let mut c = test_context();
        c.zone_id_hash = ZoneIdHash::from_bytes([0xFF; 32]);
        assert_ne!(
            build_symbol_aad(&c),
            base_aad,
            "zone_id_hash should be bound"
        );

        // Change epoch_id
        let mut c = test_context();
        c.epoch_id = 9999;
        assert_ne!(build_symbol_aad(&c), base_aad, "epoch_id should be bound");
    }
}
