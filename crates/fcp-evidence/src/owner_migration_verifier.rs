//! V3 to V4 owner-key migration attestation verifier.
//!
//! The verifier authenticates one append-only bridge from a trusted V3
//! Ed25519 owner key to a V4 ML-DSA-65 owner key. It reconstructs the canonical
//! migration transcript, verifies the V3 signature directly, delegates the V4
//! ML-DSA-65 signature check to a provider, and pins the attestation hashes that
//! bridge the old and new owner-governance chains.

use fcp_crypto::{Ed25519Signature, Ed25519VerifyingKey, KeyId};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// ML-DSA-65 public key length in bytes (FIPS 204).
pub const ML_DSA_65_PUBLIC_KEY_SIZE: usize = 1_952;

/// ML-DSA-65 signature length in bytes (FIPS 204).
pub const ML_DSA_65_SIGNATURE_SIZE: usize = 3_309;

/// Domain separator for V3 to V4 owner-key migration transcripts.
pub const OWNER_KEY_MIGRATION_DOMAIN: &[u8] = b"FCP-OWNER-KEY-MIGRATION-V1";

/// Schema identifier for owner-key migration attestations.
pub const OWNER_KEY_MIGRATION_ATTESTATION_SCHEMA: &str = "fcp.owner-key-migration.v1";

/// Opaque ML-DSA-65 verifying key bytes.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MlDsa65VerifyingKeyBytes(Vec<u8>);

impl MlDsa65VerifyingKeyBytes {
    /// Construct a public-key wrapper after enforcing the FIPS 204 byte length.
    ///
    /// # Errors
    ///
    /// Returns [`OwnerMigrationVerificationError::InvalidMlDsa65PublicKeyLength`]
    /// when `bytes` is not exactly [`ML_DSA_65_PUBLIC_KEY_SIZE`] bytes long.
    pub fn try_from_bytes(bytes: impl Into<Vec<u8>>) -> OwnerMigrationResult<Self> {
        let bytes = bytes.into();
        if bytes.len() != ML_DSA_65_PUBLIC_KEY_SIZE {
            return Err(
                OwnerMigrationVerificationError::InvalidMlDsa65PublicKeyLength {
                    expected: ML_DSA_65_PUBLIC_KEY_SIZE,
                    actual: bytes.len(),
                },
            );
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
pub struct MlDsa65SignatureBytes(Vec<u8>);

impl MlDsa65SignatureBytes {
    /// Construct a signature wrapper after enforcing the FIPS 204 byte length.
    ///
    /// # Errors
    ///
    /// Returns [`OwnerMigrationVerificationError::InvalidMlDsa65SignatureLength`]
    /// when `bytes` is not exactly [`ML_DSA_65_SIGNATURE_SIZE`] bytes long.
    pub fn try_from_bytes(bytes: impl Into<Vec<u8>>) -> OwnerMigrationResult<Self> {
        let bytes = bytes.into();
        if bytes.len() != ML_DSA_65_SIGNATURE_SIZE {
            return Err(
                OwnerMigrationVerificationError::InvalidMlDsa65SignatureLength {
                    expected: ML_DSA_65_SIGNATURE_SIZE,
                    actual: bytes.len(),
                },
            );
        }
        Ok(Self(bytes))
    }

    /// Borrow the encoded ML-DSA-65 signature bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for MlDsa65SignatureBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlDsa65SignatureBytes")
            .field("len", &self.0.len())
            .finish_non_exhaustive()
    }
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
    /// BLAKE3-256 hash of the last trusted V3 owner-state attestation object.
    pub prior_v3_attestation_hash: [u8; 32],
    /// BLAKE3-256 hash of the first trusted V4 owner-state attestation object.
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
            schema: OWNER_KEY_MIGRATION_ATTESTATION_SCHEMA.to_owned(),
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
    ///
    /// Signatures are intentionally excluded from these bytes.
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
    /// Counter-signature by the new V4 ML-DSA-65 owner key.
    pub signed_with_v4: MlDsa65SignatureBytes,
}

impl OwnerKeyMigrationAttestation {
    /// Construct a cross-signed migration attestation envelope.
    #[must_use]
    pub const fn new(
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

/// Trusted V3 owner-key set used to anchor migration attestations.
#[derive(Debug, Clone, Default)]
pub struct TrustedV3OwnerMap {
    owner_keys: Vec<Ed25519VerifyingKey>,
}

impl TrustedV3OwnerMap {
    /// Construct an empty trusted-owner map.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            owner_keys: Vec::new(),
        }
    }

    /// Construct a trusted-owner map from verifying keys.
    #[must_use]
    pub fn from_keys(owner_keys: impl IntoIterator<Item = Ed25519VerifyingKey>) -> Self {
        Self {
            owner_keys: owner_keys.into_iter().collect(),
        }
    }

    /// Add a trusted V3 owner verifying key.
    pub fn insert(&mut self, owner_key: Ed25519VerifyingKey) {
        self.owner_keys.push(owner_key);
    }

    /// Return the trusted key for `kid`, if present.
    #[must_use]
    pub fn get(&self, kid: &KeyId) -> Option<&Ed25519VerifyingKey> {
        self.owner_keys
            .iter()
            .find(|owner_key| owner_key.key_id() == *kid)
    }

    /// True when no V3 owner roots are configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.owner_keys.is_empty()
    }
}

/// Verification context for one migration attestation.
#[derive(Debug, Clone)]
pub struct OwnerMigrationVerificationContext {
    /// Trusted V3 Ed25519 owner roots.
    pub trusted_v3_owners: TrustedV3OwnerMap,
    /// Canonical bytes of the last trusted V3 owner-state attestation object.
    pub prior_v3_attestation_bytes: Vec<u8>,
    /// Canonical bytes of the first trusted V4 owner-state attestation object.
    pub new_v4_attestation_bytes: Vec<u8>,
    /// Last accepted migration epoch for replay prevention.
    pub last_accepted_migration_epoch: u64,
    /// Verification time as Unix seconds.
    pub now_unix: u64,
}

impl OwnerMigrationVerificationContext {
    /// Construct a verification context.
    #[must_use]
    pub fn new(
        trusted_v3_owners: TrustedV3OwnerMap,
        prior_v3_attestation_bytes: impl Into<Vec<u8>>,
        new_v4_attestation_bytes: impl Into<Vec<u8>>,
        last_accepted_migration_epoch: u64,
        now_unix: u64,
    ) -> Self {
        Self {
            trusted_v3_owners,
            prior_v3_attestation_bytes: prior_v3_attestation_bytes.into(),
            new_v4_attestation_bytes: new_v4_attestation_bytes.into(),
            last_accepted_migration_epoch,
            now_unix,
        }
    }
}

/// Provider hook for ML-DSA-65 signature verification.
///
/// The verifier owns transcript, epoch, key-id, and chain-hash checks; concrete
/// ML-DSA provider work plugs into this trait.
pub trait MlDsa65SignatureVerifier {
    /// Verify `signature` over `message` under `verifying_key`.
    fn verify_mldsa65(
        &self,
        verifying_key: &MlDsa65VerifyingKeyBytes,
        message: &[u8],
        signature: &MlDsa65SignatureBytes,
    ) -> bool;
}

/// Successful verification receipt for the accepted migration bridge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerMigrationVerificationReceipt {
    /// Trusted V3 owner KID that signed the bridge.
    pub prior_v3_kid: KeyId,
    /// V4 ML-DSA-65 owner KID accepted through the bridge.
    pub new_v4_kid: KeyId,
    /// Accepted migration epoch.
    pub migration_epoch: u64,
    /// BLAKE3 hash of the reconstructed canonical transcript.
    pub transcript_hash: [u8; 32],
}

/// Verification error for V3 to V4 owner-key migration attestations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum OwnerMigrationVerificationError {
    /// ML-DSA-65 public key length was not FIPS 204 compatible.
    #[error("invalid ML-DSA-65 public key length: expected {expected}, got {actual}")]
    InvalidMlDsa65PublicKeyLength {
        /// Expected byte length.
        expected: usize,
        /// Actual byte length.
        actual: usize,
    },

    /// ML-DSA-65 signature length was not FIPS 204 compatible.
    #[error("invalid ML-DSA-65 signature length: expected {expected}, got {actual}")]
    InvalidMlDsa65SignatureLength {
        /// Expected byte length.
        expected: usize,
        /// Actual byte length.
        actual: usize,
    },

    /// Migration transcript schema was not recognized.
    #[error("invalid owner migration schema: expected {expected}, got {actual}")]
    InvalidSchema {
        /// Expected schema identifier.
        expected: &'static str,
        /// Actual schema identifier.
        actual: String,
    },

    /// Validity window was malformed.
    #[error(
        "invalid owner migration validity window: not_before {not_before_unix} > not_after {not_after_unix}"
    )]
    InvalidValidityWindow {
        /// Earliest valid Unix timestamp.
        not_before_unix: u64,
        /// Latest valid Unix timestamp.
        not_after_unix: u64,
    },

    /// Migration is not yet valid.
    #[error("owner migration is not valid before {not_before_unix}; now {now_unix}")]
    NotYetValid {
        /// Verification time.
        now_unix: u64,
        /// Earliest valid Unix timestamp.
        not_before_unix: u64,
    },

    /// Migration is expired.
    #[error("owner migration expired at {not_after_unix}; now {now_unix}")]
    Expired {
        /// Verification time.
        now_unix: u64,
        /// Latest valid Unix timestamp.
        not_after_unix: u64,
    },

    /// Migration epoch is not strictly newer than the accepted epoch.
    #[error(
        "owner migration epoch replay: candidate {migration_epoch}, last accepted {last_accepted_epoch}"
    )]
    ReplayedEpoch {
        /// Candidate migration epoch.
        migration_epoch: u64,
        /// Last accepted migration epoch.
        last_accepted_epoch: u64,
    },

    /// V3 KID in the transcript is not present in the trusted owner map.
    #[error("prior V3 owner KID {prior_v3_kid} is not trusted")]
    PriorV3OwnerNotTrusted {
        /// Untrusted prior V3 KID.
        prior_v3_kid: KeyId,
    },

    /// V4 KID in the transcript did not match the supplied ML-DSA-65 key.
    #[error("new V4 owner KID mismatch: expected {expected}, got {actual}")]
    NewV4KidMismatch {
        /// KID derived from the supplied ML-DSA-65 public key.
        expected: KeyId,
        /// KID carried in the transcript.
        actual: KeyId,
    },

    /// Prior V3 attestation bytes did not match the transcript hash.
    #[error("prior V3 attestation hash mismatch")]
    PriorV3AttestationHashMismatch,

    /// New V4 attestation bytes did not match the transcript hash.
    #[error("new V4 attestation hash mismatch")]
    NewV4AttestationHashMismatch,

    /// V3 Ed25519 owner signature did not verify.
    #[error("V3 Ed25519 owner signature verification failed")]
    V3SignatureRejected,

    /// V4 ML-DSA-65 owner counter-signature did not verify.
    #[error("V4 ML-DSA-65 owner counter-signature verification failed")]
    V4SignatureRejected,
}

/// Result type for owner-key migration verification.
pub type OwnerMigrationResult<T> = Result<T, OwnerMigrationVerificationError>;

/// Verify a V3 to V4 owner-key migration attestation.
///
/// # Errors
///
/// Returns [`OwnerMigrationVerificationError`] when any bridge invariant fails.
pub fn verify_owner_key_migration_attestation<V>(
    attestation: &OwnerKeyMigrationAttestation,
    v4_verifying_key: &MlDsa65VerifyingKeyBytes,
    context: &OwnerMigrationVerificationContext,
    ml_dsa_verifier: &V,
) -> OwnerMigrationResult<OwnerMigrationVerificationReceipt>
where
    V: MlDsa65SignatureVerifier,
{
    let transcript = &attestation.transcript;
    if transcript.schema != OWNER_KEY_MIGRATION_ATTESTATION_SCHEMA {
        return Err(OwnerMigrationVerificationError::InvalidSchema {
            expected: OWNER_KEY_MIGRATION_ATTESTATION_SCHEMA,
            actual: transcript.schema.clone(),
        });
    }
    if transcript.not_before_unix > transcript.not_after_unix {
        return Err(OwnerMigrationVerificationError::InvalidValidityWindow {
            not_before_unix: transcript.not_before_unix,
            not_after_unix: transcript.not_after_unix,
        });
    }
    if context.now_unix < transcript.not_before_unix {
        return Err(OwnerMigrationVerificationError::NotYetValid {
            now_unix: context.now_unix,
            not_before_unix: transcript.not_before_unix,
        });
    }
    if context.now_unix > transcript.not_after_unix {
        return Err(OwnerMigrationVerificationError::Expired {
            now_unix: context.now_unix,
            not_after_unix: transcript.not_after_unix,
        });
    }
    if transcript.migration_epoch <= context.last_accepted_migration_epoch {
        return Err(OwnerMigrationVerificationError::ReplayedEpoch {
            migration_epoch: transcript.migration_epoch,
            last_accepted_epoch: context.last_accepted_migration_epoch,
        });
    }

    let Some(v3_owner_key) = context.trusted_v3_owners.get(&transcript.prior_v3_kid) else {
        return Err(OwnerMigrationVerificationError::PriorV3OwnerNotTrusted {
            prior_v3_kid: transcript.prior_v3_kid.clone(),
        });
    };

    let derived_v4_kid = v4_verifying_key.key_id();
    if derived_v4_kid != transcript.new_v4_kid {
        return Err(OwnerMigrationVerificationError::NewV4KidMismatch {
            expected: derived_v4_kid,
            actual: transcript.new_v4_kid.clone(),
        });
    }

    if blake3_256(&context.prior_v3_attestation_bytes) != transcript.prior_v3_attestation_hash {
        return Err(OwnerMigrationVerificationError::PriorV3AttestationHashMismatch);
    }
    if blake3_256(&context.new_v4_attestation_bytes) != transcript.new_v4_attestation_hash {
        return Err(OwnerMigrationVerificationError::NewV4AttestationHashMismatch);
    }

    let signing_bytes = transcript.signing_bytes();
    v3_owner_key
        .verify(&signing_bytes, &attestation.signed_with_v3)
        .map_err(|_| OwnerMigrationVerificationError::V3SignatureRejected)?;

    if !ml_dsa_verifier.verify_mldsa65(
        v4_verifying_key,
        &signing_bytes,
        &attestation.signed_with_v4,
    ) {
        return Err(OwnerMigrationVerificationError::V4SignatureRejected);
    }

    Ok(OwnerMigrationVerificationReceipt {
        prior_v3_kid: transcript.prior_v3_kid.clone(),
        new_v4_kid: transcript.new_v4_kid.clone(),
        migration_epoch: transcript.migration_epoch,
        transcript_hash: blake3_256(&signing_bytes),
    })
}

fn append_len_prefixed(out: &mut Vec<u8>, value: &[u8]) {
    let len = u32::try_from(value.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(value);
}

fn blake3_256(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

#[cfg(test)]
mod tests {
    use fcp_crypto::Ed25519SigningKey;

    use super::*;

    struct DeterministicMlDsa65Verifier;

    impl MlDsa65SignatureVerifier for DeterministicMlDsa65Verifier {
        fn verify_mldsa65(
            &self,
            verifying_key: &MlDsa65VerifyingKeyBytes,
            message: &[u8],
            signature: &MlDsa65SignatureBytes,
        ) -> bool {
            signature.as_bytes() == deterministic_mldsa65_signature(verifying_key, message)
        }
    }

    struct RejectingMlDsa65Verifier;

    impl MlDsa65SignatureVerifier for RejectingMlDsa65Verifier {
        fn verify_mldsa65(
            &self,
            _verifying_key: &MlDsa65VerifyingKeyBytes,
            _message: &[u8],
            _signature: &MlDsa65SignatureBytes,
        ) -> bool {
            false
        }
    }

    struct TestCase {
        v3_signing_key: Ed25519SigningKey,
        v4_verifying_key: MlDsa65VerifyingKeyBytes,
        prior_v3_attestation: Vec<u8>,
        new_v4_attestation: Vec<u8>,
        attestation: OwnerKeyMigrationAttestation,
    }

    fn deterministic_mldsa65_signature(
        verifying_key: &MlDsa65VerifyingKeyBytes,
        message: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(ML_DSA_65_SIGNATURE_SIZE);
        let mut counter = 0_u32;
        while out.len() < ML_DSA_65_SIGNATURE_SIZE {
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"test-mldsa65-signature");
            hasher.update(verifying_key.as_bytes());
            hasher.update(message);
            hasher.update(&counter.to_le_bytes());
            out.extend_from_slice(hasher.finalize().as_bytes());
            counter = counter.saturating_add(1);
        }
        out.truncate(ML_DSA_65_SIGNATURE_SIZE);
        out
    }

    fn test_case() -> TestCase {
        let v3_signing_key = Ed25519SigningKey::generate();
        let v4_verifying_key =
            MlDsa65VerifyingKeyBytes::try_from_bytes(vec![0xA5; ML_DSA_65_PUBLIC_KEY_SIZE])
                .expect("valid ML-DSA-65 public key bytes");
        let prior_v3_attestation = b"last-trusted-v3-owner-state".to_vec();
        let new_v4_attestation = b"first-trusted-v4-owner-state".to_vec();
        let transcript = OwnerKeyMigrationTranscript::new(
            v3_signing_key.verifying_key().key_id(),
            v4_verifying_key.key_id(),
            blake3_256(&prior_v3_attestation),
            blake3_256(&new_v4_attestation),
            42,
            1_700_000_000,
            1_800_000_000,
        );
        let signing_bytes = transcript.signing_bytes();
        let signed_with_v3 = v3_signing_key.sign(&signing_bytes);
        let signed_with_v4 = MlDsa65SignatureBytes::try_from_bytes(
            deterministic_mldsa65_signature(&v4_verifying_key, &signing_bytes),
        )
        .expect("valid ML-DSA-65 signature bytes");
        let attestation =
            OwnerKeyMigrationAttestation::new(transcript, signed_with_v3, signed_with_v4);
        TestCase {
            v3_signing_key,
            v4_verifying_key,
            prior_v3_attestation,
            new_v4_attestation,
            attestation,
        }
    }

    fn context_for(case: &TestCase) -> OwnerMigrationVerificationContext {
        OwnerMigrationVerificationContext::new(
            TrustedV3OwnerMap::from_keys([case.v3_signing_key.verifying_key()]),
            case.prior_v3_attestation.clone(),
            case.new_v4_attestation.clone(),
            41,
            1_750_000_000,
        )
    }

    #[test]
    fn owner_migration_verifier_accepts_dual_signed_bridge() {
        let case = test_case();
        let receipt = verify_owner_key_migration_attestation(
            &case.attestation,
            &case.v4_verifying_key,
            &context_for(&case),
            &DeterministicMlDsa65Verifier,
        )
        .expect("valid V3/V4 migration bridge must verify");

        assert_eq!(
            receipt.prior_v3_kid,
            case.v3_signing_key.verifying_key().key_id()
        );
        assert_eq!(receipt.new_v4_kid, case.v4_verifying_key.key_id());
        assert_eq!(receipt.migration_epoch, 42);
        assert_eq!(
            receipt.transcript_hash,
            blake3_256(&case.attestation.transcript.signing_bytes())
        );
    }

    #[test]
    fn owner_migration_verifier_rejects_untrusted_v3_owner() {
        let case = test_case();
        let context = OwnerMigrationVerificationContext::new(
            TrustedV3OwnerMap::new(),
            case.prior_v3_attestation.clone(),
            case.new_v4_attestation.clone(),
            41,
            1_750_000_000,
        );

        let err = verify_owner_key_migration_attestation(
            &case.attestation,
            &case.v4_verifying_key,
            &context,
            &DeterministicMlDsa65Verifier,
        )
        .expect_err("untrusted V3 owner must reject");
        assert!(matches!(
            err,
            OwnerMigrationVerificationError::PriorV3OwnerNotTrusted { .. }
        ));
    }

    #[test]
    fn owner_migration_verifier_rejects_v3_signature_tamper() {
        let mut case = test_case();
        let mut bytes = case.attestation.signed_with_v3.to_bytes();
        bytes[0] ^= 0x80;
        case.attestation.signed_with_v3 = Ed25519Signature::from_bytes(&bytes);

        let err = verify_owner_key_migration_attestation(
            &case.attestation,
            &case.v4_verifying_key,
            &context_for(&case),
            &DeterministicMlDsa65Verifier,
        )
        .expect_err("tampered V3 signature must reject");
        assert_eq!(err, OwnerMigrationVerificationError::V3SignatureRejected);
    }

    #[test]
    fn owner_migration_verifier_rejects_v4_counter_signature_tamper() {
        let case = test_case();
        let err = verify_owner_key_migration_attestation(
            &case.attestation,
            &case.v4_verifying_key,
            &context_for(&case),
            &RejectingMlDsa65Verifier,
        )
        .expect_err("failed ML-DSA counter-signature must reject");
        assert_eq!(err, OwnerMigrationVerificationError::V4SignatureRejected);
    }

    #[test]
    fn owner_migration_verifier_rejects_v4_key_substitution() {
        let case = test_case();
        let substituted_key =
            MlDsa65VerifyingKeyBytes::try_from_bytes(vec![0x5A; ML_DSA_65_PUBLIC_KEY_SIZE])
                .expect("valid substitute ML-DSA-65 public key bytes");

        let err = verify_owner_key_migration_attestation(
            &case.attestation,
            &substituted_key,
            &context_for(&case),
            &DeterministicMlDsa65Verifier,
        )
        .expect_err("substituted V4 key must reject");
        assert!(matches!(
            err,
            OwnerMigrationVerificationError::NewV4KidMismatch { .. }
        ));
    }

    #[test]
    fn owner_migration_verifier_rejects_prior_hash_discontinuity() {
        let case = test_case();
        let context = OwnerMigrationVerificationContext::new(
            TrustedV3OwnerMap::from_keys([case.v3_signing_key.verifying_key()]),
            b"different-v3-owner-state".to_vec(),
            case.new_v4_attestation.clone(),
            41,
            1_750_000_000,
        );

        let err = verify_owner_key_migration_attestation(
            &case.attestation,
            &case.v4_verifying_key,
            &context,
            &DeterministicMlDsa65Verifier,
        )
        .expect_err("V3 attestation hash mismatch must reject");
        assert_eq!(
            err,
            OwnerMigrationVerificationError::PriorV3AttestationHashMismatch
        );
    }

    #[test]
    fn owner_migration_verifier_rejects_new_v4_hash_discontinuity() {
        let case = test_case();
        let context = OwnerMigrationVerificationContext::new(
            TrustedV3OwnerMap::from_keys([case.v3_signing_key.verifying_key()]),
            case.prior_v3_attestation.clone(),
            b"different-v4-owner-state".to_vec(),
            41,
            1_750_000_000,
        );

        let err = verify_owner_key_migration_attestation(
            &case.attestation,
            &case.v4_verifying_key,
            &context,
            &DeterministicMlDsa65Verifier,
        )
        .expect_err("V4 attestation hash mismatch must reject");
        assert_eq!(
            err,
            OwnerMigrationVerificationError::NewV4AttestationHashMismatch
        );
    }

    #[test]
    fn owner_migration_verifier_rejects_replayed_epoch() {
        let case = test_case();
        let context = OwnerMigrationVerificationContext::new(
            TrustedV3OwnerMap::from_keys([case.v3_signing_key.verifying_key()]),
            case.prior_v3_attestation.clone(),
            case.new_v4_attestation.clone(),
            42,
            1_750_000_000,
        );

        let err = verify_owner_key_migration_attestation(
            &case.attestation,
            &case.v4_verifying_key,
            &context,
            &DeterministicMlDsa65Verifier,
        )
        .expect_err("non-increasing epoch must reject");
        assert!(matches!(
            err,
            OwnerMigrationVerificationError::ReplayedEpoch { .. }
        ));
    }

    #[test]
    fn owner_migration_verifier_rejects_expired_window() {
        let case = test_case();
        let context = OwnerMigrationVerificationContext::new(
            TrustedV3OwnerMap::from_keys([case.v3_signing_key.verifying_key()]),
            case.prior_v3_attestation.clone(),
            case.new_v4_attestation.clone(),
            41,
            1_900_000_000,
        );

        let err = verify_owner_key_migration_attestation(
            &case.attestation,
            &case.v4_verifying_key,
            &context,
            &DeterministicMlDsa65Verifier,
        )
        .expect_err("expired migration must reject");
        assert!(matches!(
            err,
            OwnerMigrationVerificationError::Expired { .. }
        ));
    }

    #[test]
    fn owner_migration_verifier_rejects_invalid_schema() {
        let mut case = test_case();
        case.attestation.transcript.schema = "fcp.owner-key-migration.v0".to_owned();

        let err = verify_owner_key_migration_attestation(
            &case.attestation,
            &case.v4_verifying_key,
            &context_for(&case),
            &DeterministicMlDsa65Verifier,
        )
        .expect_err("schema mismatch must reject");
        assert!(matches!(
            err,
            OwnerMigrationVerificationError::InvalidSchema { .. }
        ));
    }

    #[test]
    fn owner_migration_verifier_enforces_mldsa65_lengths() {
        let key_err = MlDsa65VerifyingKeyBytes::try_from_bytes(vec![0_u8; 32])
            .expect_err("short ML-DSA key must reject");
        assert!(matches!(
            key_err,
            OwnerMigrationVerificationError::InvalidMlDsa65PublicKeyLength { .. }
        ));

        let sig_err = MlDsa65SignatureBytes::try_from_bytes(vec![0_u8; 64])
            .expect_err("short ML-DSA signature must reject");
        assert!(matches!(
            sig_err,
            OwnerMigrationVerificationError::InvalidMlDsa65SignatureLength { .. }
        ));
    }
}
