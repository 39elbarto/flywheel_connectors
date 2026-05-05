//! V3/V4 compatibility ledger evidence.
//!
//! The compatibility ledger is the signed, canonical record of which mesh
//! nodes are effective V3-only, V4-capable, or V4-only during the post-quantum
//! migration. It deliberately separates the unsigned ledger body from the
//! signature envelope so the ledger root is stable and signatures are always
//! over `FCP4-COMPAT-LEDGER-SIGNATURE-V1 || ledger_root`.

use std::collections::{BTreeMap, BTreeSet};

use fcp_cbor::{MAX_DESERIALIZATION_RECURSION_LIMIT, SerializationError, to_canonical_cbor};
use fcp_core::SafetyTier;
use fcp_crypto::{
    Ed25519Signature, Ed25519SigningKey, Ed25519VerifyingKey, HybridOwnerSigner, KeyId,
    MAX_V4_PAYLOAD_BYTES, MlDsa65SignatureBytes, MlDsa65VerifyingKeyBytes,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Current compatibility ledger schema version.
pub const COMPATIBILITY_LEDGER_VERSION: u16 = 1;

/// Domain separator for deriving a ledger root from the unsigned body.
pub const COMPATIBILITY_LEDGER_ROOT_DOMAIN: &[u8] = b"FCP4-COMPAT-LEDGER-ROOT-V1";

/// Domain separator for signatures over a ledger root.
pub const COMPATIBILITY_LEDGER_SIGNATURE_DOMAIN: &[u8] = b"FCP4-COMPAT-LEDGER-SIGNATURE-V1";

/// Content hash of the unsigned compatibility ledger body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CompatibilityLedgerRoot(#[serde(with = "fcp_core::util::hex_or_bytes")] pub [u8; 32]);

impl CompatibilityLedgerRoot {
    /// Construct from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the root bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex rendering for logs and errors.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Display for CompatibilityLedgerRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Protocol version advertised and accepted by the ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolVersion {
    /// V3: Ed25519 signatures and X25519/HPKE zone-key sealing.
    V3,
    /// V4: post-quantum-capable signatures and hybrid KEM zone-key sealing.
    V4,
}

/// Signature suites tracked for peer capability negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SignatureSuite {
    /// V3 Ed25519 signatures.
    Ed25519V3,
    /// FIPS 204 ML-DSA-44.
    MlDsa44,
    /// FIPS 204 ML-DSA-65.
    MlDsa65,
    /// FIPS 204 ML-DSA-87.
    MlDsa87,
}

/// KEM suites tracked for zone-key negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KemSuite {
    /// V3 HPKE/X25519 path.
    HpkeX25519V3,
    /// X-Wing hybrid X25519 + ML-KEM-768 path.
    XWingMlKem768X25519,
    /// HPKE post-quantum hybrid profile using ML-KEM-768 and X25519.
    HpkeMlKem768X25519,
}

/// Ledger acceptance state for one node entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryState {
    /// Advertised but not yet accepted as effective V4 capability.
    Advertised,
    /// Verified and usable for effective negotiation.
    Verified,
    /// Temporarily barred from V4 use because live evidence contradicted the ledger.
    Quarantined,
    /// Explicitly revoked.
    Revoked,
    /// Expired by freshness bounds.
    Expired,
}

/// Mesh-wide migration phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationPhase {
    /// Observe V3/V4 support without changing V3 behavior.
    Observe,
    /// V4-capable peers advertise both versions.
    DualAdvertise,
    /// V4-capable peers require a dual-signed ledger.
    DualSignRequired,
    /// V4 is mandatory when both peers are V4-capable.
    V4Preferred,
    /// Risky, Dangerous, and Critical operations require V4 when either peer is V4-capable.
    V4RequiredForSensitive,
    /// V3 peers can receive safe/read-only traffic only.
    V3ReceiveOnly,
    /// V3 fallback is disabled except for signed emergency recovery.
    V4Only,
}

impl MigrationPhase {
    /// Whether this phase requires the ML-DSA half of the ledger signature.
    #[must_use]
    pub const fn requires_ml_dsa_signature(self) -> bool {
        matches!(
            self,
            Self::DualSignRequired
                | Self::V4Preferred
                | Self::V4RequiredForSensitive
                | Self::V3ReceiveOnly
                | Self::V4Only
        )
    }
}

/// Per-node fallback policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeFallbackPolicy {
    /// V3 fallback allowed when mesh policy and operation tier permit it.
    AllowV3Fallback,
    /// V3 fallback allowed only for safe/read-only work.
    SafeReadOnlyOnly,
    /// V3 fallback is refused for all operations.
    V4Only,
}

/// Mesh-wide fallback policy knobs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityPolicy {
    /// Minimum safety tier that requires V4 when either participant is V4-capable.
    pub v4_required_from_tier: SafetyTier,
    /// Last epoch at which safe/read-only V3 fallback may be accepted.
    pub v3_safe_fallback_until_epoch: Option<u64>,
    /// Whether emergency phase rollback ledgers are accepted.
    pub emergency_phase_rollback_allowed: bool,
}

impl Default for CompatibilityPolicy {
    fn default() -> Self {
        Self {
            v4_required_from_tier: SafetyTier::Risky,
            v3_safe_fallback_until_epoch: None,
            emergency_phase_rollback_allowed: false,
        }
    }
}

/// Evidence attached to one node's compatibility entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryEvidence {
    /// BLAKE3 hash of the signed node protocol claim.
    #[serde(with = "fcp_core::util::hex_or_bytes")]
    pub claim_hash: [u8; 32],
    /// Peers that observed this claim in live handshakes.
    pub observed_by: Vec<String>,
    /// Optional operator note or incident reference.
    pub note: Option<String>,
}

/// Per-node compatibility entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeCompatibilityEntry {
    /// Canonical mesh node id.
    pub node_id: String,
    /// BLAKE3 hash of the durable node attestation bound to this claim.
    #[serde(with = "fcp_core::util::hex_or_bytes")]
    pub node_attestation_hash: [u8; 32],
    /// Monotonic node-claim epoch.
    pub claim_epoch: u64,
    /// Claim issue time in Unix milliseconds.
    pub claim_issued_at_ms: u64,
    /// Claim expiry time in Unix milliseconds.
    pub claim_expires_at_ms: u64,
    /// Protocol versions this node claims to support.
    pub supported_protocols: BTreeSet<ProtocolVersion>,
    /// Signature suites this node claims to support.
    pub signature_suites: BTreeSet<SignatureSuite>,
    /// KEM suites this node claims to support.
    pub kem_suites: BTreeSet<KemSuite>,
    /// Local fallback posture for this node.
    pub fallback_policy: NodeFallbackPolicy,
    /// Ledger acceptance state.
    pub state: EntryState,
    /// Evidence that led to this entry.
    pub evidence: EntryEvidence,
}

impl NodeCompatibilityEntry {
    /// Whether the entry is verified and includes V4 in its protocol set.
    #[must_use]
    pub fn is_effective_v4_capable(&self) -> bool {
        self.state == EntryState::Verified
            && self.supported_protocols.contains(&ProtocolVersion::V4)
    }
}

/// Revoked or removed node marker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeTombstone {
    /// Node removed from the active entry set.
    pub node_id: String,
    /// Ledger epoch that introduced the tombstone.
    pub tombstoned_at_epoch: u64,
    /// Operator-visible reason code.
    pub reason: String,
}

/// Unsigned ledger body. The root and signatures are derived from this value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityLedgerBody {
    /// Schema version.
    pub ledger_version: u16,
    /// Mesh identifier.
    pub mesh_id: String,
    /// Strictly increasing mesh ledger epoch.
    pub epoch: u64,
    /// Root of the prior accepted epoch.
    pub previous_root: Option<CompatibilityLedgerRoot>,
    /// Earliest Unix millisecond at which this ledger is valid.
    pub valid_from_ms: u64,
    /// Unix millisecond after which this ledger is stale.
    pub expires_at_ms: u64,
    /// Mesh migration phase.
    pub phase: MigrationPhase,
    /// Active node entries keyed by canonical node id.
    pub entries: BTreeMap<String, NodeCompatibilityEntry>,
    /// Removed/revoked node markers keyed by canonical node id.
    pub tombstones: BTreeMap<String, NodeTombstone>,
    /// Mesh compatibility policy.
    pub policy: CompatibilityPolicy,
}

impl CompatibilityLedgerBody {
    /// Construct a v1 ledger body.
    #[must_use]
    pub fn new(mesh_id: impl Into<String>, epoch: u64, phase: MigrationPhase) -> Self {
        Self {
            ledger_version: COMPATIBILITY_LEDGER_VERSION,
            mesh_id: mesh_id.into(),
            epoch,
            previous_root: None,
            valid_from_ms: 0,
            expires_at_ms: u64::MAX,
            phase,
            entries: BTreeMap::new(),
            tombstones: BTreeMap::new(),
            policy: CompatibilityPolicy::default(),
        }
    }

    /// Canonical CBOR for the unsigned ledger body.
    ///
    /// # Errors
    /// Returns [`CompatibilityLedgerError::Encoding`] if canonical CBOR encoding fails.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, CompatibilityLedgerError> {
        Ok(to_canonical_cbor(self)?)
    }

    /// Compute the ledger root.
    ///
    /// # Errors
    /// Returns [`CompatibilityLedgerError::Encoding`] if canonical CBOR encoding fails.
    pub fn ledger_root(&self) -> Result<CompatibilityLedgerRoot, CompatibilityLedgerError> {
        let body = self.to_canonical_cbor()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(COMPATIBILITY_LEDGER_ROOT_DOMAIN);
        hasher.update(&body);
        Ok(CompatibilityLedgerRoot(*hasher.finalize().as_bytes()))
    }

    /// Signing bytes for signatures over this ledger root.
    ///
    /// # Errors
    /// Returns [`CompatibilityLedgerError::Encoding`] if root derivation fails.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, CompatibilityLedgerError> {
        Ok(signing_bytes_for_root(&self.ledger_root()?))
    }
}

/// Ed25519 half of the compatibility-ledger owner signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerEd25519Signature {
    /// Key identifier of the V3 owner key.
    pub key_id: KeyId,
    /// Signature over `COMPATIBILITY_LEDGER_SIGNATURE_DOMAIN || ledger_root`.
    pub signature: Ed25519Signature,
}

/// ML-DSA-65 half of the compatibility-ledger owner signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerMlDsa65Signature {
    /// Key identifier of the V4 owner key.
    pub key_id: KeyId,
    /// Signature over `COMPATIBILITY_LEDGER_SIGNATURE_DOMAIN || ledger_root`.
    pub signature: MlDsa65SignatureBytes,
}

/// Signature envelope attached to a compatibility ledger.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityLedgerSignatures {
    /// V3 owner signature.
    pub ed25519: Option<LedgerEd25519Signature>,
    /// V4 owner signature.
    pub ml_dsa_65: Option<LedgerMlDsa65Signature>,
}

/// Signed mesh compatibility ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshCompatibilityLedger {
    /// Unsigned body whose canonical bytes define the ledger root.
    pub body: CompatibilityLedgerBody,
    /// Signatures over the ledger root.
    pub signatures: CompatibilityLedgerSignatures,
}

impl MeshCompatibilityLedger {
    /// Build an unsigned ledger envelope.
    #[must_use]
    pub fn unsigned(body: CompatibilityLedgerBody) -> Self {
        Self {
            body,
            signatures: CompatibilityLedgerSignatures::default(),
        }
    }

    /// Sign a ledger body with a V3/V4 hybrid owner signer.
    ///
    /// # Errors
    /// Returns [`CompatibilityLedgerError`] if root derivation fails or the signer fails.
    pub fn seal_with_hybrid_owner(
        body: CompatibilityLedgerBody,
        signer: &impl HybridOwnerSigner,
    ) -> Result<Self, CompatibilityLedgerError> {
        let signing_bytes = body.signing_bytes()?;
        let key_ids = signer.hybrid_owner_key_ids();
        let signature = signer
            .sign_hybrid_owner(&signing_bytes)
            .map_err(|err| CompatibilityLedgerError::Crypto(err.to_string()))?;

        Ok(Self {
            body,
            signatures: CompatibilityLedgerSignatures {
                ed25519: Some(LedgerEd25519Signature {
                    key_id: key_ids.ed25519,
                    signature: signature.ed25519,
                }),
                ml_dsa_65: Some(LedgerMlDsa65Signature {
                    key_id: key_ids.ml_dsa_65,
                    signature: signature.ml_dsa_65,
                }),
            },
        })
    }

    /// Sign a ledger body with Ed25519 and attach a precomputed ML-DSA-65 signature.
    ///
    /// This is the bridge used until the concrete ML-DSA provider lands: the
    /// caller supplies the Dilithium signature bytes produced by that provider.
    ///
    /// # Errors
    /// Returns [`CompatibilityLedgerError::Encoding`] if root derivation fails.
    pub fn seal_with_signature_halves(
        body: CompatibilityLedgerBody,
        ed25519_signing_key: &Ed25519SigningKey,
        ml_dsa_65_key_id: KeyId,
        ml_dsa_65_signature: MlDsa65SignatureBytes,
    ) -> Result<Self, CompatibilityLedgerError> {
        let signing_bytes = body.signing_bytes()?;
        Ok(Self {
            body,
            signatures: CompatibilityLedgerSignatures {
                ed25519: Some(LedgerEd25519Signature {
                    key_id: ed25519_signing_key.verifying_key().key_id(),
                    signature: ed25519_signing_key.sign(&signing_bytes),
                }),
                ml_dsa_65: Some(LedgerMlDsa65Signature {
                    key_id: ml_dsa_65_key_id,
                    signature: ml_dsa_65_signature,
                }),
            },
        })
    }

    /// Mesh id accessor.
    #[must_use]
    pub fn mesh_id(&self) -> &str {
        &self.body.mesh_id
    }

    /// Epoch accessor.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.body.epoch
    }

    /// Previous-root accessor.
    #[must_use]
    pub const fn previous_root(&self) -> Option<CompatibilityLedgerRoot> {
        self.body.previous_root
    }

    /// Canonical CBOR for the unsigned body.
    ///
    /// # Errors
    /// Returns [`CompatibilityLedgerError::Encoding`] if canonical CBOR encoding fails.
    pub fn canonical_body_cbor(&self) -> Result<Vec<u8>, CompatibilityLedgerError> {
        self.body.to_canonical_cbor()
    }

    /// Compute the ledger root.
    ///
    /// # Errors
    /// Returns [`CompatibilityLedgerError::Encoding`] if canonical CBOR encoding fails.
    pub fn ledger_root(&self) -> Result<CompatibilityLedgerRoot, CompatibilityLedgerError> {
        self.body.ledger_root()
    }

    /// Bytes signed by both owner keys.
    ///
    /// # Errors
    /// Returns [`CompatibilityLedgerError::Encoding`] if root derivation fails.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, CompatibilityLedgerError> {
        self.body.signing_bytes()
    }

    /// Canonical CBOR for the signed ledger envelope.
    ///
    /// # Errors
    /// Returns [`CompatibilityLedgerError::Encoding`] if canonical CBOR encoding fails.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, CompatibilityLedgerError> {
        Ok(to_canonical_cbor(self)?)
    }

    /// Decode a canonical signed ledger envelope.
    ///
    /// # Errors
    /// Returns [`CompatibilityLedgerError`] if decoding fails or the input was not canonical.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, CompatibilityLedgerError> {
        if bytes.len() > MAX_V4_PAYLOAD_BYTES {
            return Err(CompatibilityLedgerError::PayloadTooLarge {
                observed: bytes.len(),
                max: MAX_V4_PAYLOAD_BYTES,
            });
        }
        let mut reader = bytes;
        let ledger: Self = ciborium::de::from_reader_with_recursion_limit(
            &mut reader,
            MAX_DESERIALIZATION_RECURSION_LIMIT,
        )
        .map_err(|err| CompatibilityLedgerError::Encoding(err.to_string()))?;
        if !reader.is_empty() {
            return Err(CompatibilityLedgerError::Encoding(
                "trailing bytes after compatibility ledger CBOR".to_owned(),
            ));
        }
        let recoded = ledger.to_canonical_cbor()?;
        if recoded != bytes {
            return Err(CompatibilityLedgerError::NonCanonicalCbor);
        }
        Ok(ledger)
    }

    /// Verify both owner signature halves.
    ///
    /// # Errors
    /// Returns [`CompatibilityLedgerError`] when any required signature is missing,
    /// unknown, malformed, or invalid.
    pub fn verify_hybrid_signatures(
        &self,
        trust_anchors: &CompatibilityLedgerTrustAnchors,
        ml_dsa_verifier: &impl MlDsa65LedgerVerifier,
    ) -> Result<CompatibilityLedgerRoot, CompatibilityLedgerError> {
        let signing_bytes = self.signing_bytes()?;
        let root = self.ledger_root()?;

        let ed25519 = self
            .signatures
            .ed25519
            .as_ref()
            .ok_or(CompatibilityLedgerError::MissingEd25519Signature)?;
        let ed25519_key = trust_anchors.find_ed25519(&ed25519.key_id).ok_or_else(|| {
            CompatibilityLedgerError::UnknownEd25519Key {
                key_id: ed25519.key_id.to_string(),
            }
        })?;
        ed25519_key
            .verify(&signing_bytes, &ed25519.signature)
            .map_err(
                |_| CompatibilityLedgerError::Ed25519SignatureVerificationFailed {
                    key_id: ed25519.key_id.to_string(),
                },
            )?;

        let ml_dsa_65 = self
            .signatures
            .ml_dsa_65
            .as_ref()
            .ok_or(CompatibilityLedgerError::MissingMlDsa65Signature)?;
        let ml_dsa_key = trust_anchors
            .find_ml_dsa_65(&ml_dsa_65.key_id)
            .ok_or_else(|| CompatibilityLedgerError::UnknownMlDsa65Key {
                key_id: ml_dsa_65.key_id.to_string(),
            })?;
        if !ml_dsa_verifier.verify_ml_dsa65(ml_dsa_key, &signing_bytes, &ml_dsa_65.signature) {
            return Err(
                CompatibilityLedgerError::MlDsa65SignatureVerificationFailed {
                    key_id: ml_dsa_65.key_id.to_string(),
                },
            );
        }

        Ok(root)
    }
}

/// Trust anchors for compatibility-ledger verification.
#[derive(Debug, Clone, Default)]
pub struct CompatibilityLedgerTrustAnchors {
    ed25519: Vec<Ed25519VerifyingKey>,
    ml_dsa_65: Vec<MlDsa65VerifyingKeyBytes>,
}

impl CompatibilityLedgerTrustAnchors {
    /// Construct a trust-anchor set.
    #[must_use]
    pub fn new(
        ed25519: impl Into<Vec<Ed25519VerifyingKey>>,
        ml_dsa_65: impl Into<Vec<MlDsa65VerifyingKeyBytes>>,
    ) -> Self {
        Self {
            ed25519: ed25519.into(),
            ml_dsa_65: ml_dsa_65.into(),
        }
    }

    fn find_ed25519(&self, key_id: &KeyId) -> Option<&Ed25519VerifyingKey> {
        self.ed25519
            .iter()
            .find(|anchor| anchor.key_id() == key_id.clone())
    }

    fn find_ml_dsa_65(&self, key_id: &KeyId) -> Option<&MlDsa65VerifyingKeyBytes> {
        self.ml_dsa_65
            .iter()
            .find(|anchor| anchor.key_id() == key_id.clone())
    }
}

/// Provider hook for the ML-DSA-65 half of ledger verification.
pub trait MlDsa65LedgerVerifier {
    /// Verify an ML-DSA-65 signature over the provided bytes.
    fn verify_ml_dsa65(
        &self,
        verifying_key: &MlDsa65VerifyingKeyBytes,
        message: &[u8],
        signature: &MlDsa65SignatureBytes,
    ) -> bool;
}

/// Errors returned by compatibility-ledger construction and verification.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CompatibilityLedgerError {
    /// Canonical CBOR encoding or decoding failed.
    #[error("compatibility ledger canonical CBOR failed: {0}")]
    Encoding(String),
    /// Decoded ledger did not round-trip to the original canonical bytes.
    #[error("compatibility ledger CBOR is not canonical")]
    NonCanonicalCbor,
    /// Encoded ledger exceeded the pre-decode size bound.
    #[error("compatibility ledger payload too large: observed {observed} bytes > max {max} bytes")]
    PayloadTooLarge {
        /// Observed payload length in bytes.
        observed: usize,
        /// Maximum accepted payload length in bytes.
        max: usize,
    },
    /// Ed25519 signature half is missing.
    #[error("compatibility ledger missing Ed25519 owner signature")]
    MissingEd25519Signature,
    /// ML-DSA-65 signature half is missing.
    #[error("compatibility ledger missing ML-DSA-65 owner signature")]
    MissingMlDsa65Signature,
    /// Ed25519 key id is not trusted.
    #[error("compatibility ledger Ed25519 key is not trusted: {key_id}")]
    UnknownEd25519Key {
        /// Missing key id.
        key_id: String,
    },
    /// ML-DSA-65 key id is not trusted.
    #[error("compatibility ledger ML-DSA-65 key is not trusted: {key_id}")]
    UnknownMlDsa65Key {
        /// Missing key id.
        key_id: String,
    },
    /// Ed25519 signature did not verify.
    #[error("compatibility ledger Ed25519 signature failed verification for key {key_id}")]
    Ed25519SignatureVerificationFailed {
        /// Failed key id.
        key_id: String,
    },
    /// ML-DSA-65 signature did not verify.
    #[error("compatibility ledger ML-DSA-65 signature failed verification for key {key_id}")]
    MlDsa65SignatureVerificationFailed {
        /// Failed key id.
        key_id: String,
    },
    /// Underlying crypto provider failed.
    #[error("compatibility ledger crypto error: {0}")]
    Crypto(String),
}

impl From<SerializationError> for CompatibilityLedgerError {
    fn from(value: SerializationError) -> Self {
        Self::Encoding(value.to_string())
    }
}

fn signing_bytes_for_root(root: &CompatibilityLedgerRoot) -> Vec<u8> {
    let mut out = Vec::with_capacity(COMPATIBILITY_LEDGER_SIGNATURE_DOMAIN.len() + 32);
    out.extend_from_slice(COMPATIBILITY_LEDGER_SIGNATURE_DOMAIN);
    out.extend_from_slice(root.as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use fcp_crypto::{CryptoResult, HybridOwnerKeyIds, HybridOwnerSignature};
    use proptest::prelude::*;

    use super::*;

    fn ed25519_key() -> Ed25519SigningKey {
        Ed25519SigningKey::from_bytes(&[11_u8; 32]).expect("valid deterministic signing key")
    }

    fn ml_dsa_key() -> MlDsa65VerifyingKeyBytes {
        MlDsa65VerifyingKeyBytes::try_from_bytes(vec![
            0xA5_u8;
            fcp_crypto::ML_DSA_65_PUBLIC_KEY_SIZE
        ])
        .expect("valid ML-DSA-65 key length")
    }

    fn fake_ml_dsa_signature(
        key: &MlDsa65VerifyingKeyBytes,
        message: &[u8],
    ) -> MlDsa65SignatureBytes {
        let mut seed = Vec::with_capacity(key.as_bytes().len() + message.len());
        seed.extend_from_slice(key.as_bytes());
        seed.extend_from_slice(message);
        let digest = blake3::hash(&seed);
        let mut bytes = Vec::with_capacity(fcp_crypto::ML_DSA_65_SIGNATURE_SIZE);
        while bytes.len() < fcp_crypto::ML_DSA_65_SIGNATURE_SIZE {
            bytes.extend_from_slice(digest.as_bytes());
        }
        bytes.truncate(fcp_crypto::ML_DSA_65_SIGNATURE_SIZE);
        MlDsa65SignatureBytes::try_from_bytes(bytes).expect("expanded signature has valid length")
    }

    struct FakeHybridSigner {
        ed25519: Ed25519SigningKey,
        ml_dsa_65: MlDsa65VerifyingKeyBytes,
    }

    impl HybridOwnerSigner for FakeHybridSigner {
        fn hybrid_owner_key_ids(&self) -> HybridOwnerKeyIds {
            HybridOwnerKeyIds {
                ed25519: self.ed25519.verifying_key().key_id(),
                ml_dsa_65: self.ml_dsa_65.key_id(),
            }
        }

        fn sign_hybrid_owner(&self, transcript: &[u8]) -> CryptoResult<HybridOwnerSignature> {
            Ok(HybridOwnerSignature {
                ed25519: self.ed25519.sign(transcript),
                ml_dsa_65: fake_ml_dsa_signature(&self.ml_dsa_65, transcript),
            })
        }
    }

    struct FakeMlDsaVerifier;

    impl MlDsa65LedgerVerifier for FakeMlDsaVerifier {
        fn verify_ml_dsa65(
            &self,
            verifying_key: &MlDsa65VerifyingKeyBytes,
            message: &[u8],
            signature: &MlDsa65SignatureBytes,
        ) -> bool {
            &fake_ml_dsa_signature(verifying_key, message) == signature
        }
    }

    fn sample_entry(node_id: &str) -> NodeCompatibilityEntry {
        NodeCompatibilityEntry {
            node_id: node_id.to_owned(),
            node_attestation_hash: [0x11; 32],
            claim_epoch: 7,
            claim_issued_at_ms: 1_700_000_000_000,
            claim_expires_at_ms: 1_700_086_400_000,
            supported_protocols: BTreeSet::from([ProtocolVersion::V3, ProtocolVersion::V4]),
            signature_suites: BTreeSet::from([SignatureSuite::Ed25519V3, SignatureSuite::MlDsa65]),
            kem_suites: BTreeSet::from([KemSuite::HpkeX25519V3, KemSuite::XWingMlKem768X25519]),
            fallback_policy: NodeFallbackPolicy::SafeReadOnlyOnly,
            state: EntryState::Verified,
            evidence: EntryEvidence {
                claim_hash: [0x22; 32],
                observed_by: vec!["node-observer".to_owned()],
                note: Some("unit-test".to_owned()),
            },
        }
    }

    fn sample_body() -> CompatibilityLedgerBody {
        let mut body =
            CompatibilityLedgerBody::new("mesh-alpha", 42, MigrationPhase::DualSignRequired);
        body.valid_from_ms = 1_700_000_000_000;
        body.expires_at_ms = 1_700_086_400_000;
        body.entries
            .insert("node-a".to_owned(), sample_entry("node-a"));
        body.entries
            .insert("node-b".to_owned(), sample_entry("node-b"));
        body
    }

    fn deep_unknown_field_cbor(depth: usize) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(9 + (depth * 3) + 1);
        bytes.push(0xA1);
        bytes.push(0x67);
        bytes.extend_from_slice(b"unknown");
        for _ in 0..depth {
            bytes.push(0xA1);
            bytes.push(0x61);
            bytes.push(b'x');
        }
        bytes.push(0xF6);
        bytes
    }

    fn length_prefix_lie_cbor() -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(0xA1);
        bytes.push(0x67);
        bytes.extend_from_slice(b"unknown");
        bytes.extend_from_slice(&[0x5A, 0xFF, 0xFF, 0xFF, 0xFF]);
        bytes
    }

    fn adversarial_cbor_prefix() -> impl Strategy<Value = Vec<u8>> {
        prop_oneof![
            Just(vec![0xBF]),
            Just(deep_unknown_field_cbor(200)),
            Just(length_prefix_lie_cbor()),
        ]
    }

    #[test]
    fn compatibility_ledger_canonical_cbor_is_stable_and_signature_free_for_root() {
        let signer = FakeHybridSigner {
            ed25519: ed25519_key(),
            ml_dsa_65: ml_dsa_key(),
        };
        let ledger = MeshCompatibilityLedger::seal_with_hybrid_owner(sample_body(), &signer)
            .expect("ledger signs");
        let root_before = ledger.ledger_root().expect("root derives");
        let mut mutated = ledger.clone();
        mutated.signatures.ml_dsa_65 = None;

        assert_eq!(
            root_before,
            mutated.ledger_root().expect("root ignores signatures")
        );
        assert_eq!(
            ledger.canonical_body_cbor().expect("body encodes"),
            mutated.canonical_body_cbor().expect("body encodes")
        );
        assert_ne!(
            ledger.to_canonical_cbor().expect("signed ledger encodes"),
            mutated.to_canonical_cbor().expect("signed ledger encodes")
        );
    }

    #[test]
    fn compatibility_ledger_round_trips_canonical_cbor() {
        let signer = FakeHybridSigner {
            ed25519: ed25519_key(),
            ml_dsa_65: ml_dsa_key(),
        };
        let ledger = MeshCompatibilityLedger::seal_with_hybrid_owner(sample_body(), &signer)
            .expect("ledger signs");
        let bytes = ledger.to_canonical_cbor().expect("ledger encodes");
        let decoded = MeshCompatibilityLedger::from_canonical_cbor(&bytes).expect("ledger decodes");

        assert_eq!(decoded, ledger);
        assert_eq!(decoded.to_canonical_cbor().unwrap(), bytes);
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 64,
            ..ProptestConfig::default()
        })]

        #[test]
        fn compatibility_ledger_oversized_adversarial_cbor_hits_length_guard(
            prefix in adversarial_cbor_prefix(),
            extra in 0usize..=256,
        ) {
            let mut bytes = prefix;
            bytes.resize(MAX_V4_PAYLOAD_BYTES + 1 + extra, 0);
            let observed_len = bytes.len();
            let err = MeshCompatibilityLedger::from_canonical_cbor(&bytes)
                .expect_err("oversized ledger CBOR must reject");
            let hit_length_guard = matches!(
                err,
                CompatibilityLedgerError::PayloadTooLarge { observed, max }
                    if observed == observed_len && max == MAX_V4_PAYLOAD_BYTES
            );
            prop_assert!(hit_length_guard);
        }
    }

    #[test]
    fn compatibility_ledger_deep_unknown_field_hits_recursion_limit() {
        let bytes = deep_unknown_field_cbor(MAX_DESERIALIZATION_RECURSION_LIMIT + 80);
        assert!(bytes.len() <= MAX_V4_PAYLOAD_BYTES);

        let err = MeshCompatibilityLedger::from_canonical_cbor(&bytes)
            .expect_err("deep ledger CBOR must reject");
        assert!(
            matches!(err, CompatibilityLedgerError::Encoding(ref message) if message.to_ascii_lowercase().contains("recursion")),
            "expected recursion-limit decode error, got {err:?}"
        );
    }

    #[test]
    fn compatibility_ledger_length_prefix_lie_rejects_without_panic() {
        let bytes = length_prefix_lie_cbor();
        assert!(bytes.len() <= MAX_V4_PAYLOAD_BYTES);

        let result =
            std::panic::catch_unwind(|| MeshCompatibilityLedger::from_canonical_cbor(&bytes));
        assert!(result.is_ok(), "length-prefix lie must not panic");
        assert!(result.unwrap().is_err(), "length-prefix lie must reject");
    }

    #[test]
    fn compatibility_ledger_hybrid_signature_verifies_root() {
        let ml_dsa_key = ml_dsa_key();
        let signer = FakeHybridSigner {
            ed25519: ed25519_key(),
            ml_dsa_65: ml_dsa_key.clone(),
        };
        let ledger = MeshCompatibilityLedger::seal_with_hybrid_owner(sample_body(), &signer)
            .expect("ledger signs");
        let anchors = CompatibilityLedgerTrustAnchors::new(
            vec![signer.ed25519.verifying_key()],
            vec![ml_dsa_key],
        );

        let verified_root = ledger
            .verify_hybrid_signatures(&anchors, &FakeMlDsaVerifier)
            .expect("hybrid signatures verify");

        assert_eq!(verified_root, ledger.ledger_root().unwrap());
    }

    #[test]
    fn compatibility_ledger_tampered_epoch_breaks_ed25519_signature() {
        let ml_dsa_key = ml_dsa_key();
        let signer = FakeHybridSigner {
            ed25519: ed25519_key(),
            ml_dsa_65: ml_dsa_key.clone(),
        };
        let mut ledger = MeshCompatibilityLedger::seal_with_hybrid_owner(sample_body(), &signer)
            .expect("ledger signs");
        ledger.body.epoch += 1;
        let anchors = CompatibilityLedgerTrustAnchors::new(
            vec![signer.ed25519.verifying_key()],
            vec![ml_dsa_key],
        );

        let err = ledger
            .verify_hybrid_signatures(&anchors, &FakeMlDsaVerifier)
            .expect_err("tampering must break the root signature");

        assert!(matches!(
            err,
            CompatibilityLedgerError::Ed25519SignatureVerificationFailed { .. }
        ));
    }

    #[test]
    fn compatibility_ledger_requires_ml_dsa_half_for_hybrid_verification() {
        let ml_dsa_key = ml_dsa_key();
        let signer = FakeHybridSigner {
            ed25519: ed25519_key(),
            ml_dsa_65: ml_dsa_key.clone(),
        };
        let mut ledger = MeshCompatibilityLedger::seal_with_hybrid_owner(sample_body(), &signer)
            .expect("ledger signs");
        ledger.signatures.ml_dsa_65 = None;
        let anchors = CompatibilityLedgerTrustAnchors::new(
            vec![signer.ed25519.verifying_key()],
            vec![ml_dsa_key],
        );

        let err = ledger
            .verify_hybrid_signatures(&anchors, &FakeMlDsaVerifier)
            .expect_err("missing ML-DSA half must fail");

        assert!(matches!(
            err,
            CompatibilityLedgerError::MissingMlDsa65Signature
        ));
    }

    #[test]
    fn compatibility_ledger_effective_v4_capable_requires_verified_state() {
        let mut entry = sample_entry("node-a");
        assert!(entry.is_effective_v4_capable());

        entry.state = EntryState::Advertised;
        assert!(!entry.is_effective_v4_capable());
    }
}
