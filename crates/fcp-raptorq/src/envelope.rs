//! Universal transmission unit (NORMATIVE).
//!
//! Based on FCP Specification Section 4.1.

use fcp_crypto::{
    AeadKey, ChaCha20Nonce, ChaCha20Poly1305Cipher, XChaCha20Nonce, XChaCha20Poly1305Cipher,
    hkdf_sha256_array,
};
use fcp_prelude::{ObjectId, ZoneId, ZoneKey, ZoneKeyAlgorithm, ZoneKeyId};
use fcp_tailscale::NodeId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Authentication tag size (Poly1305: 16 bytes).
pub const AUTH_TAG_SIZE: usize = 16;

/// AAD size for symbol encryption (NORMATIVE: 86 bytes).
pub const SYMBOL_AAD_SIZE: usize = 86;

/// `SymbolEnvelope` errors.
#[derive(Debug, Error, PartialEq, Eq)]
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

/// Plain `RaptorQ` symbol frame used by higher-level object protocols.
///
/// `SymbolEnvelope` is the encrypted FCPS transmission unit. This type is the
/// canonical, serializable inner frame for protocols that need to describe or
/// test a symbol stream before choosing transport encryption. `object_id`
/// identifies the object being reconstructed, `oti` pins the expected decoder
/// parameters, and `(esi, data)` is the raw encoding symbol accepted by
/// [`crate::RaptorQDecoder::add_symbol`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RaptorQSymbolFrame {
    /// Content address of the complete object represented by this stream.
    pub object_id: ObjectId,
    /// Transmission information required to initialize a decoder.
    pub oti: crate::ObjectTransmissionInformation,
    /// Encoding Symbol ID.
    pub esi: u32,
    /// Raw symbol payload.
    pub data: Vec<u8>,
}

impl RaptorQSymbolFrame {
    /// Build a raw symbol frame.
    #[must_use]
    pub const fn new(
        object_id: ObjectId,
        oti: crate::ObjectTransmissionInformation,
        esi: u32,
        data: Vec<u8>,
    ) -> Self {
        Self {
            object_id,
            oti,
            esi,
            data,
        }
    }

    /// Return the symbol payload length.
    #[must_use]
    pub fn symbol_len(&self) -> usize {
        self.data.len()
    }

    /// Whether the frame payload is the expected fixed symbol size.
    #[must_use]
    pub fn has_expected_symbol_size(&self) -> bool {
        self.data.len() == usize::from(self.oti.symbol_size())
    }
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

    #[test]
    fn wrong_zone_key_fails_decryption() {
        let zone_key = ZoneKey::from_bytes([0xAA; 32]);
        let wrong_key = ZoneKey::from_bytes([0xBB; 32]);
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

        let result = envelope.decrypt(
            &wrong_key,
            ZoneKeyAlgorithm::ChaCha20Poly1305,
            envelope.zone_key_id,
        );
        assert!(matches!(result, Err(SymbolEnvelopeError::DecryptFailed)));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let zone_key = ZoneKey::from_bytes([0xAA; 32]);
        let mut envelope = test_envelope();
        let plaintext = b"secret data";

        let (mut ciphertext, auth_tag) = encrypt_symbol_payload(
            &zone_key,
            ZoneKeyAlgorithm::ChaCha20Poly1305,
            &envelope,
            plaintext,
        )
        .unwrap();

        ciphertext[0] ^= 0xFF; // flip bits
        envelope.data = ciphertext;
        envelope.auth_tag = auth_tag;

        let result = envelope.decrypt(
            &zone_key,
            ZoneKeyAlgorithm::ChaCha20Poly1305,
            envelope.zone_key_id,
        );
        assert!(matches!(result, Err(SymbolEnvelopeError::DecryptFailed)));
    }

    #[test]
    fn tampered_auth_tag_fails() {
        let zone_key = ZoneKey::from_bytes([0xAA; 32]);
        let mut envelope = test_envelope();
        let plaintext = b"secret data";

        let (ciphertext, mut auth_tag) = encrypt_symbol_payload(
            &zone_key,
            ZoneKeyAlgorithm::ChaCha20Poly1305,
            &envelope,
            plaintext,
        )
        .unwrap();

        auth_tag[0] ^= 0xFF;
        envelope.data = ciphertext;
        envelope.auth_tag = auth_tag;

        let result = envelope.decrypt(
            &zone_key,
            ZoneKeyAlgorithm::ChaCha20Poly1305,
            envelope.zone_key_id,
        );
        assert!(matches!(result, Err(SymbolEnvelopeError::DecryptFailed)));
    }

    #[test]
    fn empty_plaintext_roundtrip() {
        let zone_key = ZoneKey::from_bytes([0xCC; 32]);
        let envelope = test_envelope();
        let plaintext = b"";

        let encrypted = SymbolEnvelope::encrypt(
            envelope.object_id,
            envelope.esi,
            envelope.k,
            plaintext,
            envelope.zone_id.clone(),
            envelope.zone_key_id,
            envelope.epoch_id,
            envelope.source_id.clone(),
            envelope.sender_instance_id,
            envelope.frame_seq,
            &zone_key,
            ZoneKeyAlgorithm::ChaCha20Poly1305,
        )
        .unwrap();

        let decrypted = encrypted
            .decrypt(
                &zone_key,
                ZoneKeyAlgorithm::ChaCha20Poly1305,
                encrypted.zone_key_id,
            )
            .unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn large_plaintext_roundtrip() {
        let zone_key = ZoneKey::from_bytes([0xDD; 32]);
        let envelope = test_envelope();
        let plaintext = vec![0x42u8; 65536]; // 64 KiB

        let encrypted = SymbolEnvelope::encrypt(
            envelope.object_id,
            envelope.esi,
            envelope.k,
            &plaintext,
            envelope.zone_id.clone(),
            envelope.zone_key_id,
            envelope.epoch_id,
            envelope.source_id.clone(),
            envelope.sender_instance_id,
            envelope.frame_seq,
            &zone_key,
            ZoneKeyAlgorithm::XChaCha20Poly1305,
        )
        .unwrap();

        let decrypted = encrypted
            .decrypt(
                &zone_key,
                ZoneKeyAlgorithm::XChaCha20Poly1305,
                encrypted.zone_key_id,
            )
            .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn nonce12_zero_inputs() {
        let nonce = derive_nonce12(0, 0);
        assert_eq!(nonce, [0u8; 12]);
    }

    #[test]
    fn nonce24_zero_inputs() {
        let nonce = derive_nonce24(0, 0, 0);
        assert_eq!(nonce, [0u8; 24]);
    }

    #[test]
    fn nonce12_different_frame_seq() {
        let n1 = derive_nonce12(1, 42);
        let n2 = derive_nonce12(2, 42);
        assert_ne!(n1, n2);
    }

    #[test]
    fn nonce12_different_esi() {
        let n1 = derive_nonce12(100, 1);
        let n2 = derive_nonce12(100, 2);
        assert_ne!(n1, n2);
    }

    #[test]
    fn nonce24_different_sender_instance() {
        let n1 = derive_nonce24(1, 100, 42);
        let n2 = derive_nonce24(2, 100, 42);
        assert_ne!(n1, n2);
    }

    #[test]
    fn sender_subkey_deterministic() {
        let zone_key = ZoneKey::from_bytes([0xAA; 32]);
        let zone_key_id = ZoneKeyId::from_bytes([0x33; 8]);
        let node_id = NodeId::new("node-test");
        let instance = 0xDEAD;

        let k1 = derive_sender_subkey(&zone_key, &zone_key_id, &node_id, instance);
        let k2 = derive_sender_subkey(&zone_key, &zone_key_id, &node_id, instance);
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn sender_subkey_differs_by_node() {
        let zone_key = ZoneKey::from_bytes([0xAA; 32]);
        let zone_key_id = ZoneKeyId::from_bytes([0x33; 8]);
        let n1 = NodeId::new("node-a");
        let n2 = NodeId::new("node-b");

        let k1 = derive_sender_subkey(&zone_key, &zone_key_id, &n1, 1);
        let k2 = derive_sender_subkey(&zone_key, &zone_key_id, &n2, 1);
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn sender_subkey_differs_by_instance() {
        let zone_key = ZoneKey::from_bytes([0xAA; 32]);
        let zone_key_id = ZoneKeyId::from_bytes([0x33; 8]);
        let node_id = NodeId::new("node-test");

        let k1 = derive_sender_subkey(&zone_key, &zone_key_id, &node_id, 1);
        let k2 = derive_sender_subkey(&zone_key, &zone_key_id, &node_id, 2);
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn aad_deterministic() {
        let envelope = test_envelope();
        let aad1 = build_symbol_aad(&envelope);
        let aad2 = build_symbol_aad(&envelope);
        assert_eq!(aad1, aad2);
    }

    #[test]
    fn constants_correct() {
        assert_eq!(AUTH_TAG_SIZE, 16);
        assert_eq!(SYMBOL_AAD_SIZE, 86);
    }

    #[test]
    fn envelope_error_display() {
        let e = SymbolEnvelopeError::EncryptFailed;
        assert_eq!(e.to_string(), "AEAD encryption failed");

        let e = SymbolEnvelopeError::DecryptFailed;
        assert_eq!(
            e.to_string(),
            "AEAD decryption failed (authentication or key mismatch)"
        );

        let e = SymbolEnvelopeError::ZoneKeyIdMismatch {
            expected: ZoneKeyId::from_bytes([1; 8]),
            found: ZoneKeyId::from_bytes([2; 8]),
        };
        assert!(e.to_string().contains("zone_key_id mismatch"));
    }

    #[test]
    fn envelope_clone() {
        let envelope = test_envelope();
        let cloned = envelope.clone();
        assert_eq!(cloned.esi, envelope.esi);
        assert_eq!(cloned.k, envelope.k);
        assert_eq!(cloned.epoch_id, envelope.epoch_id);
        assert_eq!(cloned.frame_seq, envelope.frame_seq);
        assert_eq!(cloned.auth_tag, envelope.auth_tag);
    }

    #[test]
    fn envelope_debug() {
        let envelope = test_envelope();
        let debug = format!("{envelope:?}");
        assert!(debug.contains("SymbolEnvelope"));
    }

    #[test]
    fn encrypt_api_roundtrip() {
        let zone_key = ZoneKey::from_bytes([0xEE; 32]);
        let base = test_envelope();
        let plaintext = b"encrypt API test";

        let encrypted = SymbolEnvelope::encrypt(
            base.object_id,
            base.esi,
            base.k,
            plaintext,
            base.zone_id.clone(),
            base.zone_key_id,
            base.epoch_id,
            base.source_id.clone(),
            base.sender_instance_id,
            base.frame_seq,
            &zone_key,
            ZoneKeyAlgorithm::ChaCha20Poly1305,
        )
        .unwrap();

        assert_eq!(encrypted.esi, base.esi);
        assert_eq!(encrypted.k, base.k);
        assert!(!encrypted.data.is_empty());
        assert_ne!(encrypted.auth_tag, [0u8; 16]);

        let decrypted = encrypted
            .decrypt(
                &zone_key,
                ZoneKeyAlgorithm::ChaCha20Poly1305,
                encrypted.zone_key_id,
            )
            .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn cross_algorithm_decrypt_fails() {
        let zone_key = ZoneKey::from_bytes([0xFF; 32]);
        let base = test_envelope();
        let plaintext = b"cross algo test";

        let encrypted = SymbolEnvelope::encrypt(
            base.object_id,
            base.esi,
            base.k,
            plaintext,
            base.zone_id.clone(),
            base.zone_key_id,
            base.epoch_id,
            base.source_id.clone(),
            base.sender_instance_id,
            base.frame_seq,
            &zone_key,
            ZoneKeyAlgorithm::ChaCha20Poly1305,
        )
        .unwrap();

        // Try decrypting with XChaCha20 instead of ChaCha20
        let result = encrypted.decrypt(
            &zone_key,
            ZoneKeyAlgorithm::XChaCha20Poly1305,
            encrypted.zone_key_id,
        );
        assert!(matches!(result, Err(SymbolEnvelopeError::DecryptFailed)));
    }

    #[test]
    fn xchacha20_encrypt_api_roundtrip() {
        let zone_key = ZoneKey::from_bytes([0x77; 32]);
        let base = test_envelope();
        let plaintext = b"xchacha20 api test";

        let encrypted = SymbolEnvelope::encrypt(
            base.object_id,
            base.esi,
            base.k,
            plaintext,
            base.zone_id.clone(),
            base.zone_key_id,
            base.epoch_id,
            base.source_id.clone(),
            base.sender_instance_id,
            base.frame_seq,
            &zone_key,
            ZoneKeyAlgorithm::XChaCha20Poly1305,
        )
        .unwrap();

        let decrypted = encrypted
            .decrypt(
                &zone_key,
                ZoneKeyAlgorithm::XChaCha20Poly1305,
                encrypted.zone_key_id,
            )
            .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn zone_key_id_mismatch_contains_ids() {
        let expected = ZoneKeyId::from_bytes([0x11; 8]);
        let found = ZoneKeyId::from_bytes([0x22; 8]);
        let e = SymbolEnvelopeError::ZoneKeyIdMismatch { expected, found };
        assert_eq!(
            e,
            SymbolEnvelopeError::ZoneKeyIdMismatch { expected, found }
        );
    }

    // ── sender subkey isolation ──

    #[test]
    fn sender_subkey_differs_by_zone_key() {
        let k1 = ZoneKey::from_bytes([0xAA; 32]);
        let k2 = ZoneKey::from_bytes([0xBB; 32]);
        let zone_key_id = ZoneKeyId::from_bytes([0x33; 8]);
        let node_id = NodeId::new("node-test");

        let sk1 = derive_sender_subkey(&k1, &zone_key_id, &node_id, 1);
        let sk2 = derive_sender_subkey(&k2, &zone_key_id, &node_id, 1);
        assert_ne!(sk1.as_bytes(), sk2.as_bytes());
    }

    #[test]
    fn sender_subkey_differs_by_zone_key_id() {
        let zone_key = ZoneKey::from_bytes([0xAA; 32]);
        let id1 = ZoneKeyId::from_bytes([0x01; 8]);
        let id2 = ZoneKeyId::from_bytes([0x02; 8]);
        let node_id = NodeId::new("node-test");

        let sk1 = derive_sender_subkey(&zone_key, &id1, &node_id, 1);
        let sk2 = derive_sender_subkey(&zone_key, &id2, &node_id, 1);
        assert_ne!(sk1.as_bytes(), sk2.as_bytes());
    }

    // ── nonce24 additional variations ──

    #[test]
    fn nonce24_different_frame_seq() {
        let n1 = derive_nonce24(100, 1, 42);
        let n2 = derive_nonce24(100, 2, 42);
        assert_ne!(n1, n2);
    }

    #[test]
    fn nonce24_different_esi() {
        let n1 = derive_nonce24(100, 50, 1);
        let n2 = derive_nonce24(100, 50, 2);
        assert_ne!(n1, n2);
    }

    // ── AAD field sensitivity ──

    #[test]
    fn aad_changes_with_esi() {
        let e1 = test_envelope();
        let mut e2 = test_envelope();
        e2.esi = 99;
        assert_ne!(build_symbol_aad(&e1), build_symbol_aad(&e2));
    }

    #[test]
    fn aad_changes_with_k() {
        let e1 = test_envelope();
        let mut e2 = test_envelope();
        e2.k = 20;
        assert_ne!(build_symbol_aad(&e1), build_symbol_aad(&e2));
    }

    #[test]
    fn aad_changes_with_epoch() {
        let e1 = test_envelope();
        let mut e2 = test_envelope();
        e2.epoch_id = 9999;
        assert_ne!(build_symbol_aad(&e1), build_symbol_aad(&e2));
    }

    // ── serde roundtrip ──

    #[test]
    fn envelope_serde_roundtrip() {
        let zone_key = ZoneKey::from_bytes([0xCC; 32]);
        let base = test_envelope();
        let encrypted = SymbolEnvelope::encrypt(
            base.object_id,
            base.esi,
            base.k,
            b"serde test",
            base.zone_id.clone(),
            base.zone_key_id,
            base.epoch_id,
            base.source_id.clone(),
            base.sender_instance_id,
            base.frame_seq,
            &zone_key,
            ZoneKeyAlgorithm::ChaCha20Poly1305,
        )
        .unwrap();

        let json = serde_json::to_string(&encrypted).unwrap();
        let decoded: SymbolEnvelope = serde_json::from_str(&json).unwrap();

        let decrypted = decoded
            .decrypt(
                &zone_key,
                ZoneKeyAlgorithm::ChaCha20Poly1305,
                decoded.zone_key_id,
            )
            .unwrap();
        assert_eq!(decrypted, b"serde test");
    }

    // ── tampered metadata causes auth failure ──

    #[test]
    fn tampered_epoch_causes_decrypt_failure() {
        let zone_key = ZoneKey::from_bytes([0xAA; 32]);
        let base = test_envelope();
        let mut encrypted = SymbolEnvelope::encrypt(
            base.object_id,
            base.esi,
            base.k,
            b"epoch tamper test",
            base.zone_id.clone(),
            base.zone_key_id,
            base.epoch_id,
            base.source_id.clone(),
            base.sender_instance_id,
            base.frame_seq,
            &zone_key,
            ZoneKeyAlgorithm::ChaCha20Poly1305,
        )
        .unwrap();

        encrypted.epoch_id = 9999; // tamper with AAD-bound field
        let result = encrypted.decrypt(
            &zone_key,
            ZoneKeyAlgorithm::ChaCha20Poly1305,
            encrypted.zone_key_id,
        );
        assert!(matches!(result, Err(SymbolEnvelopeError::DecryptFailed)));
    }

    #[test]
    fn tampered_esi_causes_decrypt_failure() {
        let zone_key = ZoneKey::from_bytes([0xAA; 32]);
        let base = test_envelope();
        let mut encrypted = SymbolEnvelope::encrypt(
            base.object_id,
            base.esi,
            base.k,
            b"esi tamper test",
            base.zone_id.clone(),
            base.zone_key_id,
            base.epoch_id,
            base.source_id.clone(),
            base.sender_instance_id,
            base.frame_seq,
            &zone_key,
            ZoneKeyAlgorithm::XChaCha20Poly1305,
        )
        .unwrap();

        encrypted.esi = 999; // tamper: changes both AAD and nonce
        let result = encrypted.decrypt(
            &zone_key,
            ZoneKeyAlgorithm::XChaCha20Poly1305,
            encrypted.zone_key_id,
        );
        assert!(matches!(result, Err(SymbolEnvelopeError::DecryptFailed)));
    }

    // ── Additional envelope tests ─────────────────────────────────────────

    #[test]
    fn nonce12_max_values() {
        let nonce = derive_nonce12(u64::MAX, u32::MAX);
        assert_eq!(&nonce[0..8], &u64::MAX.to_le_bytes());
        assert_eq!(&nonce[8..12], &u32::MAX.to_le_bytes());
    }

    #[test]
    fn nonce24_max_values() {
        let nonce = derive_nonce24(u64::MAX, u64::MAX, u32::MAX);
        assert_eq!(&nonce[0..8], &u64::MAX.to_le_bytes());
        assert_eq!(&nonce[8..16], &u64::MAX.to_le_bytes());
        assert_eq!(&nonce[16..20], &u32::MAX.to_le_bytes());
        assert_eq!(&nonce[20..24], &0u32.to_le_bytes());
    }

    #[test]
    fn nonce12_deterministic() {
        let n1 = derive_nonce12(42, 7);
        let n2 = derive_nonce12(42, 7);
        assert_eq!(n1, n2);
    }

    #[test]
    fn nonce24_deterministic() {
        let n1 = derive_nonce24(100, 42, 7);
        let n2 = derive_nonce24(100, 42, 7);
        assert_eq!(n1, n2);
    }

    #[test]
    fn aad_changes_with_object_id() {
        let e1 = test_envelope();
        let mut e2 = test_envelope();
        e2.object_id = ObjectId::from_bytes([0x22; 32]);
        assert_ne!(build_symbol_aad(&e1), build_symbol_aad(&e2));
    }

    #[test]
    fn aad_changes_with_zone_key_id() {
        let e1 = test_envelope();
        let mut e2 = test_envelope();
        e2.zone_key_id = ZoneKeyId::from_bytes([0x44; 8]);
        assert_ne!(build_symbol_aad(&e1), build_symbol_aad(&e2));
    }

    #[test]
    fn aad_same_envelope_same_aad() {
        let envelope = test_envelope();
        let a1 = build_symbol_aad(&envelope);
        let a2 = build_symbol_aad(&envelope);
        assert_eq!(a1, a2);
    }

    #[test]
    fn envelope_clone_preserves_all_fields() {
        let zone_key = ZoneKey::from_bytes([0xEE; 32]);
        let base = test_envelope();
        let encrypted = SymbolEnvelope::encrypt(
            base.object_id,
            base.esi,
            base.k,
            b"clone test data",
            base.zone_id.clone(),
            base.zone_key_id,
            base.epoch_id,
            base.source_id.clone(),
            base.sender_instance_id,
            base.frame_seq,
            &zone_key,
            ZoneKeyAlgorithm::ChaCha20Poly1305,
        )
        .unwrap();

        let cloned = encrypted.clone();
        assert_eq!(cloned.object_id, encrypted.object_id);
        assert_eq!(cloned.esi, encrypted.esi);
        assert_eq!(cloned.k, encrypted.k);
        assert_eq!(cloned.data, encrypted.data);
        assert_eq!(cloned.zone_key_id, encrypted.zone_key_id);
        assert_eq!(cloned.epoch_id, encrypted.epoch_id);
        assert_eq!(cloned.sender_instance_id, encrypted.sender_instance_id);
        assert_eq!(cloned.frame_seq, encrypted.frame_seq);
        assert_eq!(cloned.auth_tag, encrypted.auth_tag);
    }

    #[test]
    fn sender_subkey_with_empty_node_id() {
        let zone_key = ZoneKey::from_bytes([0xAA; 32]);
        let zone_key_id = ZoneKeyId::from_bytes([0x33; 8]);
        let node_id = NodeId::new("");

        let k1 = derive_sender_subkey(&zone_key, &zone_key_id, &node_id, 1);
        let k2 = derive_sender_subkey(&zone_key, &zone_key_id, &node_id, 1);
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn sender_subkey_zero_instance_id() {
        let zone_key = ZoneKey::from_bytes([0xAA; 32]);
        let zone_key_id = ZoneKeyId::from_bytes([0x33; 8]);
        let node_id = NodeId::new("node-test");

        let k = derive_sender_subkey(&zone_key, &zone_key_id, &node_id, 0);
        assert!(!k.as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn sender_subkey_max_instance_id() {
        let zone_key = ZoneKey::from_bytes([0xAA; 32]);
        let zone_key_id = ZoneKeyId::from_bytes([0x33; 8]);
        let node_id = NodeId::new("node-test");

        let k = derive_sender_subkey(&zone_key, &zone_key_id, &node_id, u64::MAX);
        assert!(!k.as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn envelope_error_debug_format() {
        let e = SymbolEnvelopeError::EncryptFailed;
        let debug = format!("{e:?}");
        assert!(debug.contains("EncryptFailed"));

        let e = SymbolEnvelopeError::DecryptFailed;
        let debug = format!("{e:?}");
        assert!(debug.contains("DecryptFailed"));
    }

    #[test]
    fn tampered_k_causes_decrypt_failure() {
        let zone_key = ZoneKey::from_bytes([0xAA; 32]);
        let base = test_envelope();
        let mut encrypted = SymbolEnvelope::encrypt(
            base.object_id,
            base.esi,
            base.k,
            b"k tamper test",
            base.zone_id.clone(),
            base.zone_key_id,
            base.epoch_id,
            base.source_id.clone(),
            base.sender_instance_id,
            base.frame_seq,
            &zone_key,
            ZoneKeyAlgorithm::ChaCha20Poly1305,
        )
        .unwrap();

        encrypted.k = 999; // tamper with AAD-bound field
        let result = encrypted.decrypt(
            &zone_key,
            ZoneKeyAlgorithm::ChaCha20Poly1305,
            encrypted.zone_key_id,
        );
        assert!(matches!(result, Err(SymbolEnvelopeError::DecryptFailed)));
    }

    #[test]
    fn different_frame_seq_produces_different_ciphertext() {
        let zone_key = ZoneKey::from_bytes([0xAA; 32]);
        let base = test_envelope();
        let plaintext = b"frame seq test";

        let enc1 = SymbolEnvelope::encrypt(
            base.object_id,
            base.esi,
            base.k,
            plaintext,
            base.zone_id.clone(),
            base.zone_key_id,
            base.epoch_id,
            base.source_id.clone(),
            base.sender_instance_id,
            1, // frame_seq = 1
            &zone_key,
            ZoneKeyAlgorithm::ChaCha20Poly1305,
        )
        .unwrap();

        let enc2 = SymbolEnvelope::encrypt(
            base.object_id,
            base.esi,
            base.k,
            plaintext,
            base.zone_id.clone(),
            base.zone_key_id,
            base.epoch_id,
            base.source_id.clone(),
            base.sender_instance_id,
            2, // frame_seq = 2
            &zone_key,
            ZoneKeyAlgorithm::ChaCha20Poly1305,
        )
        .unwrap();

        assert_ne!(enc1.data, enc2.data);
    }

    // ── Additional envelope tests ─────────────────────────────────────────

    #[test]
    fn aad_size_is_86_bytes() {
        let envelope = test_envelope();
        let aad = build_symbol_aad(&envelope);
        assert_eq!(aad.len(), 86);
    }

    #[test]
    fn nonce12_different_inputs_produce_different_nonces() {
        let n1 = derive_nonce12(1, 1);
        let n2 = derive_nonce12(1, 2);
        let n3 = derive_nonce12(2, 1);
        assert_ne!(n1, n2);
        assert_ne!(n1, n3);
        assert_ne!(n2, n3);
    }

    #[test]
    fn nonce24_trailing_four_bytes_are_zero() {
        let nonce = derive_nonce24(42, 99, 7);
        assert_eq!(&nonce[20..24], &[0, 0, 0, 0]);
    }

    #[test]
    fn envelope_encrypt_deterministic() {
        let zone_key = ZoneKey::from_bytes([0xAA; 32]);
        let base = test_envelope();
        let plaintext = b"determinism test";

        let enc1 = SymbolEnvelope::encrypt(
            base.object_id,
            base.esi,
            base.k,
            plaintext,
            base.zone_id.clone(),
            base.zone_key_id,
            base.epoch_id,
            base.source_id.clone(),
            base.sender_instance_id,
            base.frame_seq,
            &zone_key,
            ZoneKeyAlgorithm::ChaCha20Poly1305,
        )
        .unwrap();

        let enc2 = SymbolEnvelope::encrypt(
            base.object_id,
            base.esi,
            base.k,
            plaintext,
            base.zone_id.clone(),
            base.zone_key_id,
            base.epoch_id,
            base.source_id.clone(),
            base.sender_instance_id,
            base.frame_seq,
            &zone_key,
            ZoneKeyAlgorithm::ChaCha20Poly1305,
        )
        .unwrap();

        assert_eq!(enc1.data, enc2.data);
        assert_eq!(enc1.auth_tag, enc2.auth_tag);
    }

    #[test]
    fn envelope_xchacha20_deterministic() {
        let zone_key = ZoneKey::from_bytes([0xBB; 32]);
        let base = test_envelope();
        let plaintext = b"xchacha determinism";

        let enc1 = SymbolEnvelope::encrypt(
            base.object_id,
            base.esi,
            base.k,
            plaintext,
            base.zone_id.clone(),
            base.zone_key_id,
            base.epoch_id,
            base.source_id.clone(),
            base.sender_instance_id,
            base.frame_seq,
            &zone_key,
            ZoneKeyAlgorithm::XChaCha20Poly1305,
        )
        .unwrap();

        let enc2 = SymbolEnvelope::encrypt(
            base.object_id,
            base.esi,
            base.k,
            plaintext,
            base.zone_id.clone(),
            base.zone_key_id,
            base.epoch_id,
            base.source_id.clone(),
            base.sender_instance_id,
            base.frame_seq,
            &zone_key,
            ZoneKeyAlgorithm::XChaCha20Poly1305,
        )
        .unwrap();

        assert_eq!(enc1.data, enc2.data);
        assert_eq!(enc1.auth_tag, enc2.auth_tag);
    }

    #[test]
    fn different_esi_produces_different_ciphertext() {
        let zone_key = ZoneKey::from_bytes([0xCC; 32]);
        let base = test_envelope();
        let plaintext = b"esi difference test";

        let enc1 = SymbolEnvelope::encrypt(
            base.object_id,
            1, // esi = 1
            base.k,
            plaintext,
            base.zone_id.clone(),
            base.zone_key_id,
            base.epoch_id,
            base.source_id.clone(),
            base.sender_instance_id,
            base.frame_seq,
            &zone_key,
            ZoneKeyAlgorithm::ChaCha20Poly1305,
        )
        .unwrap();

        let enc2 = SymbolEnvelope::encrypt(
            base.object_id,
            2, // esi = 2
            base.k,
            plaintext,
            base.zone_id.clone(),
            base.zone_key_id,
            base.epoch_id,
            base.source_id.clone(),
            base.sender_instance_id,
            base.frame_seq,
            &zone_key,
            ZoneKeyAlgorithm::ChaCha20Poly1305,
        )
        .unwrap();

        assert_ne!(enc1.data, enc2.data);
    }

    #[test]
    fn sender_subkey_with_long_node_id() {
        let zone_key = ZoneKey::from_bytes([0xAA; 32]);
        let zone_key_id = ZoneKeyId::from_bytes([0x33; 8]);
        let long_id = NodeId::new("a".repeat(1000));

        let k = derive_sender_subkey(&zone_key, &zone_key_id, &long_id, 1);
        // Should produce a valid non-zero key
        assert!(!k.as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn envelope_serde_preserves_all_fields() {
        let envelope = test_envelope();
        let json = serde_json::to_string(&envelope).unwrap();
        let decoded: SymbolEnvelope = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.object_id, envelope.object_id);
        assert_eq!(decoded.esi, envelope.esi);
        assert_eq!(decoded.k, envelope.k);
        assert_eq!(decoded.data, envelope.data);
        assert_eq!(decoded.zone_key_id, envelope.zone_key_id);
        assert_eq!(decoded.epoch_id, envelope.epoch_id);
        assert_eq!(decoded.sender_instance_id, envelope.sender_instance_id);
        assert_eq!(decoded.frame_seq, envelope.frame_seq);
        assert_eq!(decoded.auth_tag, envelope.auth_tag);
    }

    #[test]
    fn envelope_error_is_std_error() {
        fn assert_error<E: std::error::Error>(_: &E) {}
        assert_error(&SymbolEnvelopeError::EncryptFailed);
        assert_error(&SymbolEnvelopeError::DecryptFailed);
        assert_error(&SymbolEnvelopeError::ZoneKeyIdMismatch {
            expected: ZoneKeyId::from_bytes([0; 8]),
            found: ZoneKeyId::from_bytes([1; 8]),
        });
    }

    #[test]
    fn tampered_object_id_causes_decrypt_failure() {
        let zone_key = ZoneKey::from_bytes([0xAA; 32]);
        let base = test_envelope();
        let mut encrypted = SymbolEnvelope::encrypt(
            base.object_id,
            base.esi,
            base.k,
            b"object id tamper test",
            base.zone_id.clone(),
            base.zone_key_id,
            base.epoch_id,
            base.source_id.clone(),
            base.sender_instance_id,
            base.frame_seq,
            &zone_key,
            ZoneKeyAlgorithm::ChaCha20Poly1305,
        )
        .unwrap();

        encrypted.object_id = ObjectId::from_bytes([0x99; 32]); // tamper
        let result = encrypted.decrypt(
            &zone_key,
            ZoneKeyAlgorithm::ChaCha20Poly1305,
            encrypted.zone_key_id,
        );
        assert!(matches!(result, Err(SymbolEnvelopeError::DecryptFailed)));
    }

    #[test]
    fn one_byte_plaintext_roundtrip() {
        let zone_key = ZoneKey::from_bytes([0xDD; 32]);
        let base = test_envelope();

        let encrypted = SymbolEnvelope::encrypt(
            base.object_id,
            base.esi,
            base.k,
            &[0x42],
            base.zone_id.clone(),
            base.zone_key_id,
            base.epoch_id,
            base.source_id.clone(),
            base.sender_instance_id,
            base.frame_seq,
            &zone_key,
            ZoneKeyAlgorithm::XChaCha20Poly1305,
        )
        .unwrap();

        let decrypted = encrypted
            .decrypt(
                &zone_key,
                ZoneKeyAlgorithm::XChaCha20Poly1305,
                encrypted.zone_key_id,
            )
            .unwrap();
        assert_eq!(decrypted, vec![0x42]);
    }
}
