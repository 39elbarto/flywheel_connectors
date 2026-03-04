//! Universal transmission unit (NORMATIVE).
//!
//! Based on FCP Specification Section 4.1.

use fcp_core::{ObjectId, ZoneId, ZoneKey, ZoneKeyAlgorithm, ZoneKeyId};
use fcp_crypto::{
    AeadKey, ChaCha20Nonce, ChaCha20Poly1305Cipher, XChaCha20Nonce, XChaCha20Poly1305Cipher,
    hkdf_sha256_array,
};
use fcp_tailscale::NodeId;
use serde::{Deserialize, Serialize};
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

    #[error("zone_key_id mismatch (expected {expected:?}, found {found:?})")]
    ZoneKeyIdMismatch {
        expected: ZoneKeyId,
        found: ZoneKeyId,
    },
}

/// Full symbol envelope with encryption (NORMATIVE).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SymbolEnvelope {
    /// Content address of complete object
    pub object_id: ObjectId,

    /// Encoding Symbol ID
    pub esi: u32,

    /// Source symbols needed (K)
    pub k: u16,

    /// Symbol payload (encrypted)
    pub data: Vec<u8>,

    /// Zone for key derivation
    pub zone_id: ZoneId,

    /// Zone key ID (for key rotation - enables deterministic decryption)
    pub zone_key_id: ZoneKeyId,

    /// Epoch for replay protection
    pub epoch_id: u64,

    /// Source node that produced this ciphertext (NORMATIVE)
    pub source_id: NodeId,

    /// Sender instance identifier (NORMATIVE)
    /// Random u64 chosen by the sender at startup for this (`zone_id`, `zone_key_id`) lifetime.
    pub sender_instance_id: u64,

    /// Monotonic frame sequence chosen by source (NORMATIVE)
    /// Monotonicity scope is (`zone_id`, `zone_key_id`, `source_id`, `sender_instance_id`).
    pub frame_seq: u64,

    /// AEAD authentication tag
    pub auth_tag: [u8; 16],
}

impl SymbolEnvelope {
    /// Encrypt a symbol payload into a `SymbolEnvelope` (NORMATIVE).
    ///
    /// # Errors
    ///
    /// Returns [`SymbolEnvelopeError::EncryptFailed`] if AEAD encryption fails.
    #[allow(clippy::too_many_arguments)] // All parameters required for envelope construction
    pub fn encrypt(
        object_id: ObjectId,
        esi: u32,
        k: u16,
        plaintext: &[u8],
        zone_id: ZoneId,
        zone_key_id: ZoneKeyId,
        epoch_id: u64,
        source_id: NodeId,
        sender_instance_id: u64,
        frame_seq: u64,
        zone_key: &ZoneKey,
        algorithm: ZoneKeyAlgorithm,
    ) -> Result<Self, SymbolEnvelopeError> {
        let envelope = Self {
            object_id,
            esi,
            k,
            data: Vec::new(),
            zone_id,
            zone_key_id,
            epoch_id,
            source_id,
            sender_instance_id,
            frame_seq,
            auth_tag: [0u8; AUTH_TAG_SIZE],
        };

        let (ciphertext, auth_tag) =
            encrypt_symbol_payload(zone_key, algorithm, &envelope, plaintext)?;

        Ok(Self {
            data: ciphertext,
            auth_tag,
            ..envelope
        })
    }

    /// Decrypt a `SymbolEnvelope` into plaintext (NORMATIVE).
    ///
    /// # Errors
    ///
    /// Returns [`SymbolEnvelopeError::ZoneKeyIdMismatch`] if the provided `zone_key_id`
    /// does not match the envelope. Returns [`SymbolEnvelopeError::DecryptFailed`] if
    /// decryption fails.
    pub fn decrypt(
        &self,
        zone_key: &ZoneKey,
        algorithm: ZoneKeyAlgorithm,
        zone_key_id: ZoneKeyId,
    ) -> Result<Vec<u8>, SymbolEnvelopeError> {
        if self.zone_key_id != zone_key_id {
            return Err(SymbolEnvelopeError::ZoneKeyIdMismatch {
                expected: zone_key_id,
                found: self.zone_key_id,
            });
        }

        decrypt_symbol_payload(zone_key, algorithm, self, &self.data, &self.auth_tag)
    }
}

/// Derive ChaCha20-Poly1305 nonce (12 bytes) deterministically (NORMATIVE).
///
/// nonce12 = `frame_seq_le` || `esi_le`
#[must_use]
#[allow(dead_code)]
pub fn derive_nonce12(frame_seq: u64, esi: u32) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0..8].copy_from_slice(&frame_seq.to_le_bytes());
    nonce[8..12].copy_from_slice(&esi.to_le_bytes());
    nonce
}

/// Derive XChaCha20-Poly1305 nonce (24 bytes) deterministically (NORMATIVE).
///
/// nonce24 = `sender_instance_id_le` || `frame_seq_le` || `esi_le` || `0u32`
#[must_use]
#[allow(dead_code)]
pub fn derive_nonce24(sender_instance_id: u64, frame_seq: u64, esi: u32) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    nonce[0..8].copy_from_slice(&sender_instance_id.to_le_bytes());
    nonce[8..16].copy_from_slice(&frame_seq.to_le_bytes());
    nonce[16..20].copy_from_slice(&esi.to_le_bytes());
    nonce[20..24].copy_from_slice(&0u32.to_le_bytes());
    nonce
}

/// Derive a per-sender subkey from the zone key (NORMATIVE).
///
/// Uses HKDF-SHA256 with:
/// - Salt: `zone_key_id` (8 bytes)
/// - IKM: `zone_key` bytes
/// - Info: "FCP2-SENDER-KEY-V1" || `sender_node_id` || `sender_instance_id_le`
#[must_use]
#[allow(clippy::trivially_copy_pass_by_ref)] // API consistency with other crates
pub fn derive_sender_subkey(
    zone_key: &ZoneKey,
    zone_key_id: &ZoneKeyId,
    sender_node_id: &NodeId,
    sender_instance_id: u64,
) -> AeadKey {
    let mut info = Vec::with_capacity(22 + sender_node_id.as_str().len() + 12);
    info.extend_from_slice(b"FCP2-SENDER-KEY-V1");
    
    let sender_bytes = sender_node_id.as_str().as_bytes();
    info.extend_from_slice(&(sender_bytes.len() as u32).to_le_bytes());
    info.extend_from_slice(sender_bytes);
    
    info.extend_from_slice(&sender_instance_id.to_le_bytes());

    let subkey_bytes: [u8; 32] =
        hkdf_sha256_array(Some(zone_key_id.as_bytes()), zone_key.as_bytes(), &info)
            .expect("HKDF expansion failed");
    AeadKey::from_bytes(subkey_bytes)
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
#[must_use]
pub fn build_symbol_aad(envelope: &SymbolEnvelope) -> [u8; SYMBOL_AAD_SIZE] {
    let mut aad = [0u8; SYMBOL_AAD_SIZE];

    aad[0..32].copy_from_slice(envelope.object_id.as_bytes());
    aad[32..36].copy_from_slice(&envelope.esi.to_le_bytes());
    aad[36..38].copy_from_slice(&envelope.k.to_le_bytes());
    aad[38..70].copy_from_slice(envelope.zone_id.hash().as_bytes());
    aad[70..78].copy_from_slice(envelope.zone_key_id.as_bytes());
    aad[78..86].copy_from_slice(&envelope.epoch_id.to_le_bytes());

    aad
}

fn encrypt_symbol_payload(
    zone_key: &ZoneKey,
    algorithm: ZoneKeyAlgorithm,
    envelope: &SymbolEnvelope,
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; AUTH_TAG_SIZE]), SymbolEnvelopeError> {
    let sender_key = derive_sender_subkey(
        zone_key,
        &envelope.zone_key_id,
        &envelope.source_id,
        envelope.sender_instance_id,
    );
    let aad = build_symbol_aad(envelope);

    let ciphertext_with_tag = match algorithm {
        ZoneKeyAlgorithm::ChaCha20Poly1305 => {
            let nonce = ChaCha20Nonce::from_bytes(derive_nonce12(envelope.frame_seq, envelope.esi));
            let cipher = ChaCha20Poly1305Cipher::new(&sender_key);
            cipher
                .encrypt(&nonce, plaintext, &aad)
                .map_err(|_| SymbolEnvelopeError::EncryptFailed)?
        }
        ZoneKeyAlgorithm::XChaCha20Poly1305 => {
            let nonce = XChaCha20Nonce::from_bytes(derive_nonce24(
                envelope.sender_instance_id,
                envelope.frame_seq,
                envelope.esi,
            ));
            let cipher = XChaCha20Poly1305Cipher::new(&sender_key);
            cipher
                .encrypt(&nonce, plaintext, &aad)
                .map_err(|_| SymbolEnvelopeError::EncryptFailed)?
        }
    };

    let tag_offset = ciphertext_with_tag.len().saturating_sub(AUTH_TAG_SIZE);
    if ciphertext_with_tag.len() < AUTH_TAG_SIZE {
        return Err(SymbolEnvelopeError::EncryptFailed);
    }
    let ciphertext = ciphertext_with_tag[..tag_offset].to_vec();
    let mut auth_tag = [0u8; AUTH_TAG_SIZE];
    auth_tag.copy_from_slice(&ciphertext_with_tag[tag_offset..]);

    Ok((ciphertext, auth_tag))
}

fn decrypt_symbol_payload(
    zone_key: &ZoneKey,
    algorithm: ZoneKeyAlgorithm,
    envelope: &SymbolEnvelope,
    ciphertext: &[u8],
    auth_tag: &[u8; AUTH_TAG_SIZE],
) -> Result<Vec<u8>, SymbolEnvelopeError> {
    let sender_key = derive_sender_subkey(
        zone_key,
        &envelope.zone_key_id,
        &envelope.source_id,
        envelope.sender_instance_id,
    );
    let aad = build_symbol_aad(envelope);

    let mut ciphertext_with_tag = Vec::with_capacity(ciphertext.len() + AUTH_TAG_SIZE);
    ciphertext_with_tag.extend_from_slice(ciphertext);
    ciphertext_with_tag.extend_from_slice(auth_tag);

    match algorithm {
        ZoneKeyAlgorithm::ChaCha20Poly1305 => {
            let nonce = ChaCha20Nonce::from_bytes(derive_nonce12(envelope.frame_seq, envelope.esi));
            let cipher = ChaCha20Poly1305Cipher::new(&sender_key);
            cipher
                .decrypt(&nonce, &ciphertext_with_tag, &aad)
                .map_err(|_| SymbolEnvelopeError::DecryptFailed)
        }
        ZoneKeyAlgorithm::XChaCha20Poly1305 => {
            let nonce = XChaCha20Nonce::from_bytes(derive_nonce24(
                envelope.sender_instance_id,
                envelope.frame_seq,
                envelope.esi,
            ));
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

    fn test_envelope() -> SymbolEnvelope {
        SymbolEnvelope {
            object_id: ObjectId::from_bytes([0x11; 32]),
            esi: 42,
            k: 10,
            data: Vec::new(),
            zone_id: "z:work".parse().unwrap(),
            zone_key_id: ZoneKeyId::from_bytes([0x33; 8]),
            epoch_id: 1000,
            source_id: NodeId::new("node-test"),
            sender_instance_id: 0xDEAD_BEEF_CAFE_BABE,
            frame_seq: 123,
            auth_tag: [0u8; AUTH_TAG_SIZE],
        }
    }

    #[test]
    fn test_derive_nonce12_golden_vector() {
        // Spec Example or hypothetical values
        let frame_seq = 0x0102_0304_0506_0708;
        let esi = 0x0A0B_0C0D;

        let nonce = derive_nonce12(frame_seq, esi);

        let mut expected = [0u8; 12];
        expected[0..8].copy_from_slice(&frame_seq.to_le_bytes());
        expected[8..12].copy_from_slice(&esi.to_le_bytes());

        assert_eq!(nonce, expected);
    }

    #[test]
    fn test_derive_nonce24_golden_vector() {
        let sender_instance = 0x1122_3344_5566_7788;
        let frame_seq = 0x0102_0304_0506_0708;
        let esi = 0x0A0B_0C0D;

        let nonce = derive_nonce24(sender_instance, frame_seq, esi);

        let mut expected = [0u8; 24];
        expected[0..8].copy_from_slice(&sender_instance.to_le_bytes());
        expected[8..16].copy_from_slice(&frame_seq.to_le_bytes());
        expected[16..20].copy_from_slice(&esi.to_le_bytes());
        expected[20..24].copy_from_slice(&0u32.to_le_bytes());

        assert_eq!(nonce, expected);
    }

    #[test]
    fn aad_structure() {
        let envelope = test_envelope();
        let aad = build_symbol_aad(&envelope);

        assert_eq!(aad.len(), SYMBOL_AAD_SIZE);
        assert_eq!(&aad[0..32], &[0x11; 32]);
        assert_eq!(&aad[32..36], &42u32.to_le_bytes());
        assert_eq!(&aad[36..38], &10u16.to_le_bytes());
        assert_eq!(&aad[38..70], envelope.zone_id.hash().as_bytes());
        assert_eq!(&aad[70..78], envelope.zone_key_id.as_bytes());
        assert_eq!(&aad[78..86], &1000u64.to_le_bytes());
    }

    #[test]
    fn chacha20_encrypt_decrypt_roundtrip() {
        let zone_key = ZoneKey::from_bytes([0xAA; 32]);
        let mut envelope = test_envelope();
        let plaintext = b"test symbol data for encryption";

        let (ciphertext, auth_tag) = encrypt_symbol_payload(
            &zone_key,
            ZoneKeyAlgorithm::ChaCha20Poly1305,
            &envelope,
            plaintext,
        )
        .unwrap();

        envelope.data = ciphertext;
        envelope.auth_tag = auth_tag;

        let decrypted = envelope
            .decrypt(
                &zone_key,
                ZoneKeyAlgorithm::ChaCha20Poly1305,
                envelope.zone_key_id,
            )
            .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn xchacha20_encrypt_decrypt_roundtrip() {
        let zone_key = ZoneKey::from_bytes([0xBB; 32]);
        let mut envelope = test_envelope();
        let plaintext = b"test symbol data for xchacha encryption";

        let (ciphertext, auth_tag) = encrypt_symbol_payload(
            &zone_key,
            ZoneKeyAlgorithm::XChaCha20Poly1305,
            &envelope,
            plaintext,
        )
        .unwrap();

        envelope.data = ciphertext;
        envelope.auth_tag = auth_tag;

        let decrypted = envelope
            .decrypt(
                &zone_key,
                ZoneKeyAlgorithm::XChaCha20Poly1305,
                envelope.zone_key_id,
            )
            .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_zone_key_id_fails() {
        let zone_key = ZoneKey::from_bytes([0xAA; 32]);
        let mut envelope = test_envelope();
        let plaintext = b"secret data";

        let (ciphertext, auth_tag) = encrypt_symbol_payload(
            &zone_key,
            ZoneKeyAlgorithm::ChaCha20Poly1305,
            &envelope,
            plaintext,
        )
        .unwrap();

        envelope.data = ciphertext;
        envelope.auth_tag = auth_tag;

        let wrong_id = ZoneKeyId::from_bytes([0x44; 8]);
        let result = envelope.decrypt(&zone_key, ZoneKeyAlgorithm::ChaCha20Poly1305, wrong_id);

        assert!(matches!(
            result,
            Err(SymbolEnvelopeError::ZoneKeyIdMismatch { .. })
        ));
    }
}
