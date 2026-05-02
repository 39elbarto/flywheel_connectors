//! Owner-key migration primitives for the V3 to V4 post-quantum transition.
//!
//! This module intentionally does not implement ML-DSA. It defines the stable
//! FCP-facing trait and byte-envelope types that future provider work must
//! satisfy when wiring FIPS 204 ML-DSA-65 into owner-key ceremonies.

use serde::{Deserialize, Serialize};

use crate::ed25519::Ed25519Signature;
use crate::error::{CryptoError, CryptoResult};
use crate::kid::KeyId;

/// ML-DSA-65 public key length in bytes (FIPS 204).
pub const ML_DSA_65_PUBLIC_KEY_SIZE: usize = 1_952;

/// ML-DSA-65 secret key length in bytes (FIPS 204).
pub const ML_DSA_65_SECRET_KEY_SIZE: usize = 4_032;

/// ML-DSA-65 signature length in bytes (FIPS 204).
pub const ML_DSA_65_SIGNATURE_SIZE: usize = 3_309;

/// Domain separator for V3 to V4 owner-key migration transcripts.
pub const OWNER_KEY_MIGRATION_DOMAIN: &[u8] = b"FCP-OWNER-KEY-MIGRATION-V1";

/// Schema identifier for owner-key migration attestations.
pub const OWNER_KEY_MIGRATION_ATTESTATION_SCHEMA: &str = "fcp.owner-key-migration.v1";

/// Owner-key algorithms recognized by the migration plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OwnerKeyAlgorithm {
    /// Current V3 owner-key algorithm.
    Ed25519,
    /// FIPS 204 ML-DSA-65, the standardized Dilithium-3 successor.
    MlDsa65,
    /// Transition state where owner objects carry both signatures.
    Ed25519MlDsa65Hybrid,
}

/// Opaque ML-DSA-65 verifying key bytes.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MlDsa65VerifyingKeyBytes(#[serde(with = "serde_bytes")] Vec<u8>);

impl MlDsa65VerifyingKeyBytes {
    /// Construct a public-key wrapper after enforcing the FIPS 204 byte length.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKeyLength`] when the provided byte string
    /// is not exactly [`ML_DSA_65_PUBLIC_KEY_SIZE`] bytes long.
    pub fn try_from_bytes(bytes: impl Into<Vec<u8>>) -> CryptoResult<Self> {
        let bytes = bytes.into();
        if bytes.len() != ML_DSA_65_PUBLIC_KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: ML_DSA_65_PUBLIC_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        Ok(Self(bytes))
    }

    /// Borrow the encoded ML-DSA-65 public key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Derive the FCP key identifier for this public key.
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        KeyId::derive_from_public_key(&self.0)
    }

    /// Consume the wrapper and return the encoded key bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl std::fmt::Debug for MlDsa65VerifyingKeyBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlDsa65VerifyingKeyBytes")
            .field("len", &self.0.len())
            .field("kid", &self.key_id())
            .finish()
    }
}

/// Opaque ML-DSA-65 signature bytes.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MlDsa65SignatureBytes(#[serde(with = "serde_bytes")] Vec<u8>);

impl MlDsa65SignatureBytes {
    /// Construct a signature wrapper after enforcing the FIPS 204 byte length.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidSignatureLength`] when the provided byte
    /// string is not exactly [`ML_DSA_65_SIGNATURE_SIZE`] bytes long.
    pub fn try_from_bytes(bytes: impl Into<Vec<u8>>) -> CryptoResult<Self> {
        let bytes = bytes.into();
        if bytes.len() != ML_DSA_65_SIGNATURE_SIZE {
            return Err(CryptoError::InvalidSignatureLength {
                expected: ML_DSA_65_SIGNATURE_SIZE,
                actual: bytes.len(),
            });
        }
        Ok(Self(bytes))
    }

    /// Borrow the encoded ML-DSA-65 signature bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consume the wrapper and return the encoded signature bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl std::fmt::Debug for MlDsa65SignatureBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlDsa65SignatureBytes")
            .field("len", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// Key identifiers for a hybrid owner-key signer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridOwnerKeyIds {
    /// V3 Ed25519 owner key identifier.
    pub ed25519: KeyId,
    /// V4 ML-DSA-65 owner key identifier.
    pub ml_dsa_65: KeyId,
}

/// Hybrid owner signature over one canonical owner transcript.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridOwnerSignature {
    /// V3 Ed25519 signature.
    pub ed25519: Ed25519Signature,
    /// V4 ML-DSA-65 signature.
    pub ml_dsa_65: MlDsa65SignatureBytes,
}

/// Unsigned transcript for the V3 to V4 owner-key migration attestation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerKeyMigrationTranscript {
    /// Schema identifier; must be [`OWNER_KEY_MIGRATION_ATTESTATION_SCHEMA`].
    pub schema: String,
    /// KID of the prior V3 Ed25519 owner key.
    pub prior_v3_kid: KeyId,
    /// KID of the new V4 ML-DSA-65 owner key.
    pub new_v4_kid: KeyId,
    /// BLAKE3-256 hash of the last trusted V3 attestation object.
    pub prior_v3_attestation_hash: [u8; 32],
    /// BLAKE3-256 hash of the new V4 attestation object.
    pub new_v4_attestation_hash: [u8; 32],
    /// Monotonic migration epoch for replay prevention.
    pub migration_epoch: u64,
    /// Earliest Unix timestamp at which the migration may be accepted.
    pub not_before_unix: u64,
    /// Latest Unix timestamp at which the migration may be accepted.
    pub not_after_unix: u64,
}

impl OwnerKeyMigrationTranscript {
    /// Construct a migration transcript with the canonical schema string.
    #[must_use]
    pub fn new(
        prior_v3_kid: KeyId,
        new_v4_kid: KeyId,
        prior_v3_attestation_hash: [u8; 32],
        new_v4_attestation_hash: [u8; 32],
        migration_epoch: u64,
        not_before_unix: u64,
        not_after_unix: u64,
    ) -> Self {
        Self {
            schema: OWNER_KEY_MIGRATION_ATTESTATION_SCHEMA.to_string(),
            prior_v3_kid,
            new_v4_kid,
            prior_v3_attestation_hash,
            new_v4_attestation_hash,
            migration_epoch,
            not_before_unix,
            not_after_unix,
        }
    }

    /// Deterministic bytes that both Ed25519 and ML-DSA-65 sign.
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(128);
        bytes.extend_from_slice(OWNER_KEY_MIGRATION_DOMAIN);
        append_len_prefixed(&mut bytes, self.schema.as_bytes());
        bytes.extend_from_slice(self.prior_v3_kid.as_slice());
        bytes.extend_from_slice(self.new_v4_kid.as_slice());
        bytes.extend_from_slice(&self.prior_v3_attestation_hash);
        bytes.extend_from_slice(&self.new_v4_attestation_hash);
        bytes.extend_from_slice(&self.migration_epoch.to_le_bytes());
        bytes.extend_from_slice(&self.not_before_unix.to_le_bytes());
        bytes.extend_from_slice(&self.not_after_unix.to_le_bytes());
        bytes
    }
}

/// Cross-signed owner-key migration attestation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerKeyMigrationAttestation {
    /// Canonical migration transcript signed by both owner keys.
    pub transcript: OwnerKeyMigrationTranscript,
    /// Signature by the prior V3 Ed25519 owner key.
    pub signed_with_v3: Ed25519Signature,
    /// Signature by the new V4 ML-DSA-65 owner key.
    pub signed_with_v4: MlDsa65SignatureBytes,
}

impl OwnerKeyMigrationAttestation {
    /// Construct a cross-signed migration attestation envelope.
    #[must_use]
    pub fn new(
        transcript: OwnerKeyMigrationTranscript,
        signed_with_v3: Ed25519Signature,
        signed_with_v4: MlDsa65SignatureBytes,
    ) -> Self {
        Self {
            transcript,
            signed_with_v3,
            signed_with_v4,
        }
    }
}

/// Trait implemented by V3 to V4 hybrid owner-key signers.
///
/// Implementations must sign exactly [`OwnerKeyMigrationTranscript::signing_bytes`]
/// or another caller-supplied canonical owner-object transcript with both the
/// V3 Ed25519 owner key and the V4 ML-DSA-65 owner key.
pub trait HybridOwnerSigner {
    /// Return both owner key identifiers used by this signer.
    fn hybrid_owner_key_ids(&self) -> HybridOwnerKeyIds;

    /// Sign canonical owner-object bytes with both owner keys.
    ///
    /// # Errors
    ///
    /// Returns an error when either signature operation fails. Callers must
    /// treat partial signing as a failed ceremony and publish no attestation.
    fn sign_hybrid_owner(&self, transcript: &[u8]) -> CryptoResult<HybridOwnerSignature>;
}

fn append_len_prefixed(out: &mut Vec<u8>, value: &[u8]) {
    let len = u32::try_from(value.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed25519::SIGNATURE_SIZE;

    fn signature_bytes(byte: u8) -> MlDsa65SignatureBytes {
        MlDsa65SignatureBytes::try_from_bytes(vec![byte; ML_DSA_65_SIGNATURE_SIZE])
            .expect("test signature length is valid")
    }

    #[test]
    fn ml_dsa_65_public_key_length_is_enforced() {
        let key = MlDsa65VerifyingKeyBytes::try_from_bytes(vec![0xA5; ML_DSA_65_PUBLIC_KEY_SIZE])
            .expect("valid ML-DSA-65 public key length");
        assert_eq!(key.as_bytes().len(), ML_DSA_65_PUBLIC_KEY_SIZE);

        let err = MlDsa65VerifyingKeyBytes::try_from_bytes(vec![0xA5; 32])
            .expect_err("short key must fail");
        assert!(matches!(
            err,
            CryptoError::InvalidKeyLength {
                expected: ML_DSA_65_PUBLIC_KEY_SIZE,
                actual: 32
            }
        ));
    }

    #[test]
    fn ml_dsa_65_signature_length_is_enforced() {
        let signature = signature_bytes(0x5A);
        assert_eq!(signature.as_bytes().len(), ML_DSA_65_SIGNATURE_SIZE);

        let err = MlDsa65SignatureBytes::try_from_bytes(vec![0x5A; SIGNATURE_SIZE])
            .expect_err("Ed25519-sized signature must fail");
        assert!(matches!(
            err,
            CryptoError::InvalidSignatureLength {
                expected: ML_DSA_65_SIGNATURE_SIZE,
                actual: SIGNATURE_SIZE
            }
        ));
    }

    #[test]
    fn migration_transcript_signing_bytes_are_stable_and_domain_separated() {
        let transcript = OwnerKeyMigrationTranscript::new(
            KeyId::from_bytes([1; 8]),
            KeyId::from_bytes([2; 8]),
            [3; 32],
            [4; 32],
            7,
            100,
            200,
        );
        let bytes = transcript.signing_bytes();
        assert!(bytes.starts_with(OWNER_KEY_MIGRATION_DOMAIN));
        assert_eq!(bytes, transcript.signing_bytes());
    }

    #[test]
    fn migration_transcript_signing_bytes_change_with_new_key() {
        let base = OwnerKeyMigrationTranscript::new(
            KeyId::from_bytes([1; 8]),
            KeyId::from_bytes([2; 8]),
            [3; 32],
            [4; 32],
            7,
            100,
            200,
        );
        let changed = OwnerKeyMigrationTranscript::new(
            KeyId::from_bytes([1; 8]),
            KeyId::from_bytes([9; 8]),
            [3; 32],
            [4; 32],
            7,
            100,
            200,
        );
        assert_ne!(base.signing_bytes(), changed.signing_bytes());
    }

    #[test]
    fn attestation_signatures_are_not_part_of_transcript_bytes() {
        let transcript = OwnerKeyMigrationTranscript::new(
            KeyId::from_bytes([1; 8]),
            KeyId::from_bytes([2; 8]),
            [3; 32],
            [4; 32],
            7,
            100,
            200,
        );
        let ed25519_a = Ed25519Signature::from_bytes(&[0x11; SIGNATURE_SIZE]);
        let ed25519_b = Ed25519Signature::from_bytes(&[0x22; SIGNATURE_SIZE]);
        let att_a =
            OwnerKeyMigrationAttestation::new(transcript.clone(), ed25519_a, signature_bytes(0x33));
        let att_b =
            OwnerKeyMigrationAttestation::new(transcript.clone(), ed25519_b, signature_bytes(0x44));

        assert_eq!(att_a.transcript.signing_bytes(), transcript.signing_bytes());
        assert_eq!(att_b.transcript.signing_bytes(), transcript.signing_bytes());
        assert_ne!(att_a, att_b);
    }
}
