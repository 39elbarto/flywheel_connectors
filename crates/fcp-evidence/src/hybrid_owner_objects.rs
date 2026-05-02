//! Hybrid V3/V4 owner-object verification.
//!
//! Owner-governed objects accepted during the V4 cutover must be bound to the
//! accepted V3 to V4 owner-key migration bridge and must carry signatures from
//! both the historical Ed25519 owner key and the new ML-DSA-65 owner key.

use fcp_crypto::{Ed25519Signature, KeyId};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    MlDsa65SignatureBytes, MlDsa65SignatureVerifier, MlDsa65VerifyingKeyBytes,
    OwnerKeyMigrationAttestation, OwnerMigrationVerificationContext,
    OwnerMigrationVerificationError, OwnerMigrationVerificationReceipt, ZoneId,
    verify_owner_key_migration_attestation,
};

/// Domain separator for owner-governed object transcripts during V4 cutover.
pub const HYBRID_OWNER_OBJECT_DOMAIN: &[u8] = b"FCP-HYBRID-OWNER-OBJECT-V1";

/// Schema identifier for hybrid owner-governed object transcripts.
pub const HYBRID_OWNER_OBJECT_SCHEMA: &str = "fcp.hybrid-owner-object.v1";

/// Owner-governed object family covered by the hybrid signature check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HybridOwnerObjectKind {
    /// Zone key manifest accepted into zone state.
    ZoneKeyManifest,
    /// Capability token accepted as an owner-authorized object.
    CapabilityToken,
    /// Audit-chain event.
    AuditEvent,
    /// Audit-chain head checkpoint.
    AuditHead,
    /// Emergency revocation payload authorized by the zone owner.
    EmergencyRevocation,
}

impl HybridOwnerObjectKind {
    /// Stable string used in owner-object transcript bytes.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ZoneKeyManifest => "zone-key-manifest",
            Self::AuditEvent => "audit-event",
            Self::AuditHead => "audit-head",
            Self::EmergencyRevocation => "emergency-revocation",
            _ => "capability-token",
        }
    }
}

/// Canonical owner-object transcript signed by both V3 and V4 owner keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridOwnerObjectTranscript {
    /// Schema identifier; must be [`HYBRID_OWNER_OBJECT_SCHEMA`].
    pub schema: String,
    /// Object family being authorized.
    pub kind: HybridOwnerObjectKind,
    /// Zone whose owner authority governs this object.
    pub zone_id: ZoneId,
    /// BLAKE3-256 hash of the canonical unsigned object payload.
    pub payload_hash: [u8; 32],
    /// Length of the canonical unsigned object payload.
    pub payload_len: u64,
}

impl HybridOwnerObjectTranscript {
    /// Build a transcript for `payload_bytes`.
    #[must_use]
    pub fn new(kind: HybridOwnerObjectKind, zone_id: ZoneId, payload_bytes: &[u8]) -> Self {
        Self {
            schema: HYBRID_OWNER_OBJECT_SCHEMA.to_owned(),
            kind,
            zone_id,
            payload_hash: blake3_256(payload_bytes),
            payload_len: u64::try_from(payload_bytes.len()).unwrap_or(u64::MAX),
        }
    }

    /// Deterministic bytes signed by both V3 and V4 owner keys.
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            HYBRID_OWNER_OBJECT_DOMAIN.len()
                + HYBRID_OWNER_OBJECT_SCHEMA.len()
                + self.zone_id.as_bytes().len()
                + 96,
        );
        bytes.extend_from_slice(HYBRID_OWNER_OBJECT_DOMAIN);
        append_len_prefixed(&mut bytes, self.schema.as_bytes());
        append_len_prefixed(&mut bytes, self.kind.as_str().as_bytes());
        append_len_prefixed(&mut bytes, self.zone_id.as_bytes());
        bytes.extend_from_slice(&self.payload_hash);
        bytes.extend_from_slice(&self.payload_len.to_le_bytes());
        bytes
    }
}

/// V3 + V4 signature envelope for one owner-governed object transcript.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridOwnerObjectSignatures {
    /// Signature by the prior V3 Ed25519 owner key.
    pub signed_with_v3: Ed25519Signature,
    /// Signature by the accepted V4 ML-DSA-65 owner key.
    pub signed_with_v4: MlDsa65SignatureBytes,
}

impl HybridOwnerObjectSignatures {
    /// Construct a hybrid owner-object signature envelope.
    #[must_use]
    pub const fn new(
        signed_with_v3: Ed25519Signature,
        signed_with_v4: MlDsa65SignatureBytes,
    ) -> Self {
        Self {
            signed_with_v3,
            signed_with_v4,
        }
    }
}

/// Successful hybrid owner-object verification receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridOwnerObjectVerificationReceipt {
    /// Verified object family.
    pub kind: HybridOwnerObjectKind,
    /// Zone whose owner authority governs this object.
    pub zone_id: ZoneId,
    /// Trusted V3 owner key that anchors the migration bridge.
    pub prior_v3_kid: KeyId,
    /// Accepted V4 owner key that counter-signed the bridge and object.
    pub new_v4_kid: KeyId,
    /// Accepted migration epoch.
    pub migration_epoch: u64,
    /// BLAKE3 hash of the owner-object transcript bytes.
    pub object_transcript_hash: [u8; 32],
    /// BLAKE3 hash of the migration transcript bytes.
    pub migration_transcript_hash: [u8; 32],
    /// Hash of the object payload that was authorized.
    pub payload_hash: [u8; 32],
}

/// Verification error for hybrid owner-governed objects.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum HybridOwnerObjectVerificationError {
    /// Owner-object transcript schema was not recognized.
    #[error("invalid hybrid owner-object schema: expected {expected}, got {actual}")]
    InvalidSchema {
        /// Expected schema identifier.
        expected: &'static str,
        /// Actual schema identifier.
        actual: String,
    },

    /// Migration attestation verification failed.
    #[error("owner migration bridge rejected: {0}")]
    Migration(#[from] OwnerMigrationVerificationError),

    /// V3 owner key accepted by the bridge was unavailable for object check.
    #[error("accepted V3 owner KID {prior_v3_kid} missing from trusted owner map")]
    AcceptedV3OwnerMissing {
        /// Accepted V3 owner KID.
        prior_v3_kid: KeyId,
    },

    /// V3 Ed25519 owner-object signature did not verify.
    #[error("V3 Ed25519 owner-object signature verification failed")]
    V3ObjectSignatureRejected,

    /// V4 ML-DSA-65 owner-object signature did not verify.
    #[error("V4 ML-DSA-65 owner-object signature verification failed")]
    V4ObjectSignatureRejected,
}

/// Verifier adapter backed by the concrete `fcp-crypto` ML-DSA-65 provider.
#[derive(Debug, Clone, Copy, Default)]
pub struct FcpCryptoMlDsa65Verifier;

impl MlDsa65SignatureVerifier for FcpCryptoMlDsa65Verifier {
    fn verify_mldsa65(
        &self,
        verifying_key: &MlDsa65VerifyingKeyBytes,
        message: &[u8],
        signature: &MlDsa65SignatureBytes,
    ) -> bool {
        let Ok(crypto_key) = fcp_crypto::MlDsa65VerifyingKey::from_bytes(verifying_key.as_bytes())
        else {
            return false;
        };
        let Ok(crypto_signature) = fcp_crypto::owner_key::MlDsa65SignatureBytes::try_from_bytes(
            signature.as_bytes().to_vec(),
        ) else {
            return false;
        };
        crypto_key.verify(message, b"", &crypto_signature).is_ok()
    }
}

/// Verify one hybrid owner-governed object against an accepted migration bridge.
///
/// # Errors
///
/// Returns [`HybridOwnerObjectVerificationError`] when the migration bridge,
/// V3 owner signature, or V4 owner signature does not verify.
pub fn verify_hybrid_owner_object<V>(
    transcript: &HybridOwnerObjectTranscript,
    signatures: &HybridOwnerObjectSignatures,
    migration_attestation: &OwnerKeyMigrationAttestation,
    v4_verifying_key: &MlDsa65VerifyingKeyBytes,
    context: &OwnerMigrationVerificationContext,
    ml_dsa_verifier: &V,
) -> Result<HybridOwnerObjectVerificationReceipt, HybridOwnerObjectVerificationError>
where
    V: MlDsa65SignatureVerifier,
{
    if transcript.schema != HYBRID_OWNER_OBJECT_SCHEMA {
        return Err(HybridOwnerObjectVerificationError::InvalidSchema {
            expected: HYBRID_OWNER_OBJECT_SCHEMA,
            actual: transcript.schema.clone(),
        });
    }

    let migration_receipt = verify_owner_key_migration_attestation(
        migration_attestation,
        v4_verifying_key,
        context,
        ml_dsa_verifier,
    )?;

    verify_object_signatures(
        transcript,
        signatures,
        v4_verifying_key,
        context,
        ml_dsa_verifier,
        &migration_receipt,
    )
}

fn verify_object_signatures<V>(
    transcript: &HybridOwnerObjectTranscript,
    signatures: &HybridOwnerObjectSignatures,
    v4_verifying_key: &MlDsa65VerifyingKeyBytes,
    context: &OwnerMigrationVerificationContext,
    ml_dsa_verifier: &V,
    migration_receipt: &OwnerMigrationVerificationReceipt,
) -> Result<HybridOwnerObjectVerificationReceipt, HybridOwnerObjectVerificationError>
where
    V: MlDsa65SignatureVerifier,
{
    let Some(v3_owner_key) = context
        .trusted_v3_owners
        .get(&migration_receipt.prior_v3_kid)
    else {
        return Err(HybridOwnerObjectVerificationError::AcceptedV3OwnerMissing {
            prior_v3_kid: migration_receipt.prior_v3_kid.clone(),
        });
    };

    let signing_bytes = transcript.signing_bytes();
    v3_owner_key
        .verify(&signing_bytes, &signatures.signed_with_v3)
        .map_err(|_| HybridOwnerObjectVerificationError::V3ObjectSignatureRejected)?;

    if !ml_dsa_verifier.verify_mldsa65(v4_verifying_key, &signing_bytes, &signatures.signed_with_v4)
    {
        return Err(HybridOwnerObjectVerificationError::V4ObjectSignatureRejected);
    }

    Ok(HybridOwnerObjectVerificationReceipt {
        kind: transcript.kind,
        zone_id: transcript.zone_id.clone(),
        prior_v3_kid: migration_receipt.prior_v3_kid.clone(),
        new_v4_kid: migration_receipt.new_v4_kid.clone(),
        migration_epoch: migration_receipt.migration_epoch,
        object_transcript_hash: blake3_256(&signing_bytes),
        migration_transcript_hash: migration_receipt.transcript_hash,
        payload_hash: transcript.payload_hash,
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
    use fcp_crypto::{Ed25519SigningKey, MlDsa65SigningKey};

    use super::*;
    use crate::{
        OwnerKeyMigrationTranscript, OwnerMigrationVerificationContext, TrustedV3OwnerMap,
    };

    struct HybridObjectTestCase {
        v3_signing_key: Ed25519SigningKey,
        v4_signing_key: MlDsa65SigningKey,
        v4_verifying_key: MlDsa65VerifyingKeyBytes,
        prior_v3_attestation: Vec<u8>,
        new_v4_attestation: Vec<u8>,
        migration_attestation: OwnerKeyMigrationAttestation,
    }

    impl HybridObjectTestCase {
        fn new() -> Self {
            let v3_signing_key = Ed25519SigningKey::generate();
            let v4_signing_key = MlDsa65SigningKey::generate().expect("generate ML-DSA-65 key");
            let v4_verifying_key = evidence_v4_key(&v4_signing_key);
            let prior_v3_attestation = b"last-v3-owner-state".to_vec();
            let new_v4_attestation = b"first-v4-owner-state".to_vec();
            let transcript = OwnerKeyMigrationTranscript::new(
                v3_signing_key.verifying_key().key_id(),
                v4_verifying_key.key_id(),
                blake3_256(&prior_v3_attestation),
                blake3_256(&new_v4_attestation),
                7,
                1_700_000_000,
                1_800_000_000,
            );
            let signing_bytes = transcript.signing_bytes();
            let migration_attestation = OwnerKeyMigrationAttestation::new(
                transcript,
                v3_signing_key.sign(&signing_bytes),
                evidence_v4_signature(
                    &v4_signing_key
                        .sign_deterministic(&signing_bytes, b"")
                        .expect("sign migration bridge"),
                ),
            );
            Self {
                v3_signing_key,
                v4_signing_key,
                v4_verifying_key,
                prior_v3_attestation,
                new_v4_attestation,
                migration_attestation,
            }
        }

        fn context(&self) -> OwnerMigrationVerificationContext {
            OwnerMigrationVerificationContext::new(
                TrustedV3OwnerMap::from_keys([self.v3_signing_key.verifying_key()]),
                self.prior_v3_attestation.clone(),
                self.new_v4_attestation.clone(),
                6,
                1_750_000_000,
            )
        }

        fn sign_object(
            &self,
            transcript: &HybridOwnerObjectTranscript,
        ) -> HybridOwnerObjectSignatures {
            let signing_bytes = transcript.signing_bytes();
            HybridOwnerObjectSignatures::new(
                self.v3_signing_key.sign(&signing_bytes),
                evidence_v4_signature(
                    &self
                        .v4_signing_key
                        .sign_deterministic(&signing_bytes, b"")
                        .expect("sign hybrid owner object"),
                ),
            )
        }
    }

    fn evidence_v4_key(signing_key: &MlDsa65SigningKey) -> MlDsa65VerifyingKeyBytes {
        MlDsa65VerifyingKeyBytes::try_from_bytes(signing_key.verifying_key().as_bytes().to_vec())
            .expect("valid evidence ML-DSA-65 key")
    }

    fn evidence_v4_signature(
        signature: &fcp_crypto::owner_key::MlDsa65SignatureBytes,
    ) -> MlDsa65SignatureBytes {
        MlDsa65SignatureBytes::try_from_bytes(signature.as_bytes().to_vec())
            .expect("valid evidence ML-DSA-65 signature")
    }

    #[test]
    fn hybrid_owner_objects_accept_zone_capability_and_audit_families() {
        let case = HybridObjectTestCase::new();
        let context = case.context();
        for (kind, payload) in [
            (
                HybridOwnerObjectKind::ZoneKeyManifest,
                b"zone-key-manifest-cbor".as_slice(),
            ),
            (
                HybridOwnerObjectKind::CapabilityToken,
                b"capability-token-cose".as_slice(),
            ),
            (
                HybridOwnerObjectKind::AuditHead,
                b"audit-head-cbor".as_slice(),
            ),
        ] {
            let transcript = HybridOwnerObjectTranscript::new(kind, ZoneId::work(), payload);
            let signatures = case.sign_object(&transcript);
            let receipt = verify_hybrid_owner_object(
                &transcript,
                &signatures,
                &case.migration_attestation,
                &case.v4_verifying_key,
                &context,
                &FcpCryptoMlDsa65Verifier,
            )
            .expect("hybrid owner object verifies");

            assert_eq!(receipt.kind, kind);
            assert_eq!(receipt.zone_id, ZoneId::work());
            assert_eq!(receipt.migration_epoch, 7);
            assert_eq!(receipt.payload_hash, transcript.payload_hash);
        }
    }

    #[test]
    fn hybrid_owner_objects_reject_tampered_v4_signature() {
        let case = HybridObjectTestCase::new();
        let context = case.context();
        let transcript = HybridOwnerObjectTranscript::new(
            HybridOwnerObjectKind::AuditEvent,
            ZoneId::work(),
            b"audit-event-cbor",
        );
        let mut signatures = case.sign_object(&transcript);
        let mut tampered_v4 = signatures.signed_with_v4.as_bytes().to_vec();
        tampered_v4[0] ^= 0x01;
        signatures.signed_with_v4 =
            MlDsa65SignatureBytes::try_from_bytes(tampered_v4).expect("valid length");

        let error = verify_hybrid_owner_object(
            &transcript,
            &signatures,
            &case.migration_attestation,
            &case.v4_verifying_key,
            &context,
            &FcpCryptoMlDsa65Verifier,
        )
        .expect_err("tampered V4 object signature must be rejected");

        assert_eq!(
            error,
            HybridOwnerObjectVerificationError::V4ObjectSignatureRejected
        );
    }

    #[test]
    fn hybrid_owner_production_rejects_missing_v3_attestation_context() {
        let case = HybridObjectTestCase::new();
        let mut context = case.context();
        context.prior_v3_attestation_bytes = b"missing-v3-owner-state".to_vec();
        let transcript = HybridOwnerObjectTranscript::new(
            HybridOwnerObjectKind::CapabilityToken,
            ZoneId::work(),
            b"capability-token-cose",
        );
        let signatures = case.sign_object(&transcript);

        let error = verify_hybrid_owner_object(
            &transcript,
            &signatures,
            &case.migration_attestation,
            &case.v4_verifying_key,
            &context,
            &FcpCryptoMlDsa65Verifier,
        )
        .expect_err("missing prior V3 owner-state attestation must reject production objects");

        assert_eq!(
            error,
            HybridOwnerObjectVerificationError::Migration(
                OwnerMigrationVerificationError::PriorV3AttestationHashMismatch,
            ),
        );
    }

    #[test]
    fn hybrid_owner_objects_reject_replayed_migration_epoch() {
        let case = HybridObjectTestCase::new();
        let mut context = case.context();
        context.last_accepted_migration_epoch = 7;
        let transcript = HybridOwnerObjectTranscript::new(
            HybridOwnerObjectKind::ZoneKeyManifest,
            ZoneId::work(),
            b"zone-key-manifest-cbor",
        );
        let signatures = case.sign_object(&transcript);

        let error = verify_hybrid_owner_object(
            &transcript,
            &signatures,
            &case.migration_attestation,
            &case.v4_verifying_key,
            &context,
            &FcpCryptoMlDsa65Verifier,
        )
        .expect_err("replayed migration bridge must be rejected");

        assert_eq!(
            error,
            HybridOwnerObjectVerificationError::Migration(
                OwnerMigrationVerificationError::ReplayedEpoch {
                    migration_epoch: 7,
                    last_accepted_epoch: 7,
                },
            ),
        );
    }
}
