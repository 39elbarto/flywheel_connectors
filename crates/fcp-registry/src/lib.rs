//! Registry verification and mirroring for FCP2 connectors.
//!
//! This crate validates connector manifests and binaries against supply-chain
//! policies and mirrors verified bundles into the object store.

use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use chrono::Utc;
use fcp_cbor::{CanonicalSerializer, SchemaId, SerializationError};
use fcp_core::{
    CapabilityId, ObjectHeader, ObjectId, ObjectIdKey, Provenance, RateLimitDeclarations,
    RetentionClass, StorageMeta, StoredObject, ZoneId, ZonePolicyObject,
};
use fcp_crypto::ed25519::{Ed25519Signature, Ed25519VerifyingKey};
use fcp_manifest::{
    AttestationType, Base64Bytes, ConnectorManifest, ManifestError, SignatureEntry,
    SignaturesSection,
};
use fcp_store::{ObjectStore, ObjectStoreError};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Signing context for manifest signatures.

pub const MANIFEST_SIGNATURE_CONTEXT: &[u8] = b"fcp.registry.manifest.v1";

/// Registry verification failures.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("manifest parse failed: {0}")]
    ManifestParse(#[from] ManifestError),
    #[error("signature section missing from manifest")]
    MissingSignatures,
    #[error("no trusted key for kid `{kid}`")]
    UnknownKid { kid: String },
    #[error("signature verification failed for kid `{kid}`")]
    SignatureInvalid { kid: String },
    #[error("publisher signature threshold unmet (required {required}, valid {valid})")]
    PublisherThresholdUnmet { required: u8, valid: u8 },
    #[error("registry signature required but missing or invalid")]
    RegistrySignatureRequired,
    #[error("target mismatch (expected {expected}, got {found})")]
    TargetMismatch { expected: String, found: String },
    #[error("capability `{capability}` exceeds zone ceiling")]
    CapabilityCeilingViolation { capability: String },
    #[error("missing transparency log entry in manifest")]
    TransparencyLogMissing,
    #[error("transparency log evidence missing")]
    TransparencyEvidenceMissing,
    #[error("required attestation `{attestation}` not present")]
    RequiredAttestationMissing { attestation: String },
    #[error("attestation evidence missing")]
    AttestationEvidenceMissing,
    #[error("attestation does not meet minimum SLSA level {required}")]
    SlsaLevelInsufficient { required: u8 },
    #[error("attestation builder `{builder}` not in trusted builders list")]
    UntrustedBuilder { builder: String },
    #[error("manifest signing bytes serialization failed: {0}")]
    SigningBytes(#[from] SerializationError),
    #[error("signature bytes malformed")]
    SignatureBytes,
    #[error("object store failure: {0}")]
    ObjectStore(#[from] ObjectStoreError),
}

/// Connector bundle fetched from a registry.
#[derive(Debug, Clone)]
pub struct ConnectorBundle {
    pub manifest_toml: String,
    pub binary: Vec<u8>,
    pub target: ConnectorTarget,
}

/// Operating system + CPU architecture pairing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorTarget {
    pub os: String,
    pub arch: String,
}

impl ConnectorTarget {
    /// Build the target from the current process environment.
    #[must_use]
    pub fn from_env() -> Self {
        let arch = match std::env::consts::ARCH {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            other => other,
        };
        Self {
            os: std::env::consts::OS.to_string(),
            arch: arch.to_string(),
        }
    }

    #[must_use]
    pub fn as_string(&self) -> String {
        format!("{}-{}", self.os, self.arch)
    }
}

/// Trust roots used for registry verification.
#[derive(Debug, Clone, Default)]
pub struct RegistryTrustPolicy {
    pub publisher_keys: HashMap<String, Ed25519VerifyingKey>,
    pub registry_keys: HashMap<String, Ed25519VerifyingKey>,
    pub require_registry_signature: bool,
}

/// Evidence from external supply-chain verification.
#[derive(Debug, Clone, Default)]
pub struct SupplyChainEvidence {
    pub transparency_log_present: bool,
    pub attestations: Vec<AttestationEvidence>,
}

/// Attestation metadata verified by an external system.
#[derive(Debug, Clone)]
pub struct AttestationEvidence {
    pub attestation_type: AttestationType,
    pub slsa_level: Option<u8>,
    pub builder_id: Option<String>,
}

/// Verified connector bundle metadata.
#[derive(Debug, Clone)]
pub struct VerifiedConnectorBundle {
    pub manifest: ConnectorManifest,
    pub manifest_hash: String,
    pub binary_hash: String,
    pub target: ConnectorTarget,
}

/// Minimal structured report for audit/logging sinks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryVerificationReport {
    pub connector_id: String,
    pub manifest_hash: String,
    pub binary_hash: String,
    pub target: ConnectorTarget,
    pub verified_at: u64,
    pub outcome: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Supply-Chain Verification Adapters
// ─────────────────────────────────────────────────────────────────────────────

/// Transparency log entry with proof data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransparencyLogEntry {
    /// Log index of the entry.
    pub log_index: u64,
    /// SHA256 hash of the entry being logged.
    pub entry_hash: String,
    /// Merkle proof for inclusion verification.
    pub inclusion_proof: InclusionProof,
    /// Signed entry timestamp from the log server.
    pub signed_entry_timestamp: Vec<u8>,
    /// Log ID (public key hash of the log).
    pub log_id: String,
}

/// Merkle inclusion proof for transparency log verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionProof {
    /// Merkle tree root hash.
    pub root_hash: String,
    /// Tree size at time of proof.
    pub tree_size: u64,
    /// Merkle audit path (hashes from leaf to root).
    pub hashes: Vec<String>,
    /// Index of the leaf in the tree.
    pub leaf_index: u64,
}

/// TUF root metadata for anti-rollback protection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TufRootMetadata {
    /// Version of the root metadata.
    pub version: u32,
    /// SHA256 hash of the canonical root.json.
    pub root_hash: String,
    /// Expiration timestamp (Unix seconds).
    pub expires: u64,
    /// Key IDs for threshold verification.
    pub key_ids: Vec<String>,
    /// Threshold required for valid signatures.
    pub threshold: u8,
}

/// TUF delegation target for connector binaries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TufTargetInfo {
    /// Target path in the TUF repo.
    pub target_path: String,
    /// SHA256 hash of the target.
    pub hash: String,
    /// Length of the target in bytes.
    pub length: u64,
    /// Delegation chain from root to target.
    pub delegations: Vec<String>,
}

/// Sigstore bundle containing signature and attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigstoreBundle {
    /// Base64-encoded signature.
    pub signature: String,
    /// Certificate chain (PEM-encoded).
    pub certificate: String,
    /// Rekor log entry for the signature.
    pub rekor_entry: Option<TransparencyLogEntry>,
    /// OIDC identity that signed (e.g., "github-actions").
    pub identity: String,
    /// OIDC issuer URL.
    pub issuer: String,
}

/// Result of transparency log verification.
#[derive(Debug, Clone)]
pub struct TransparencyVerificationResult {
    /// Whether the entry was found and verified.
    pub verified: bool,
    /// Log index of the verified entry.
    pub log_index: Option<u64>,
    /// Timestamp when entry was logged.
    pub logged_at: Option<u64>,
}

/// Result of TUF verification.
#[derive(Debug, Clone)]
pub struct TufVerificationResult {
    /// Whether the target was found in valid TUF metadata.
    pub verified: bool,
    /// Root version used for verification.
    pub root_version: u32,
    /// Target info if found.
    pub target: Option<TufTargetInfo>,
}

/// Result of Sigstore bundle verification.
#[derive(Debug, Clone)]
pub struct SigstoreVerificationResult {
    /// Whether the signature is valid.
    pub verified: bool,
    /// OIDC identity from certificate.
    pub identity: Option<String>,
    /// OIDC issuer from certificate.
    pub issuer: Option<String>,
    /// Rekor log index if available.
    pub rekor_log_index: Option<u64>,
}

/// Errors specific to supply-chain verification adapters.
#[derive(Debug, thiserror::Error)]
pub enum SupplyChainVerificationError {
    #[error("transparency log entry not found")]
    TransparencyEntryNotFound,
    #[error("transparency log inclusion proof invalid")]
    TransparencyProofInvalid,
    #[error("transparency log signature invalid")]
    TransparencySignatureInvalid,
    #[error("TUF root hash mismatch (expected {expected}, got {actual})")]
    TufRootMismatch { expected: String, actual: String },
    #[error("TUF metadata expired")]
    TufExpired,
    #[error("TUF target not found: {target}")]
    TufTargetNotFound { target: String },
    #[error("TUF rollback detected (got version {got}, expected > {current})")]
    TufRollback { current: u32, got: u32 },
    #[error("TUF freeze attack detected: timestamp metadata unchanged")]
    TufFreeze,
    #[error("Sigstore signature invalid")]
    SigstoreSignatureInvalid,
    #[error("Sigstore certificate expired or not yet valid")]
    SigstoreCertificateInvalid,
    #[error("Sigstore identity mismatch (expected {expected}, got {actual})")]
    SigstoreIdentityMismatch { expected: String, actual: String },
    #[error("Sigstore issuer not trusted: {issuer}")]
    SigstoreIssuerUntrusted { issuer: String },
    #[error("network error: {0}")]
    Network(String),
    #[error("verification not configured")]
    NotConfigured,
}

/// Trait for transparency log verification adapters.
#[async_trait]
pub trait TransparencyLogVerifier: Send + Sync {
    /// Verify that an entry exists in the transparency log.
    async fn verify_entry(
        &self,
        entry_hash: &str,
        expected_entry: Option<&TransparencyLogEntry>,
    ) -> Result<TransparencyVerificationResult, SupplyChainVerificationError>;
}

/// Trait for TUF metadata verification adapters.
#[async_trait]
pub trait TufVerifier: Send + Sync {
    /// Verify TUF metadata chain and find target info.
    ///
    /// # Arguments
    /// * `pinned_root` - Expected root metadata hash for anti-rollback
    /// * `target_path` - Path to the target in the TUF repo
    async fn verify_target(
        &self,
        pinned_root: &TufRootMetadata,
        target_path: &str,
    ) -> Result<TufVerificationResult, SupplyChainVerificationError>;

    /// Fetch and verify the current root metadata.
    async fn fetch_root(&self) -> Result<TufRootMetadata, SupplyChainVerificationError>;
}

/// Trait for Sigstore bundle verification adapters.
#[async_trait]
pub trait SigstoreVerifier: Send + Sync {
    /// Verify a Sigstore bundle against an artifact.
    ///
    /// # Arguments
    /// * `bundle` - The Sigstore bundle containing signature and certificate
    /// * `artifact_hash` - SHA256 hash of the artifact being verified
    /// * `trusted_identities` - Allowed OIDC identities (e.g., "github-actions")
    /// * `trusted_issuers` - Allowed OIDC issuers
    async fn verify_bundle(
        &self,
        bundle: &SigstoreBundle,
        artifact_hash: &str,
        trusted_identities: &[String],
        trusted_issuers: &[String],
    ) -> Result<SigstoreVerificationResult, SupplyChainVerificationError>;
}

/// Configuration for supply-chain verification.
#[derive(Debug, Clone, Default)]
pub struct SupplyChainVerificationConfig {
    /// Pinned TUF root for anti-rollback.
    pub tuf_pinned_root: Option<TufRootMetadata>,
    /// Trusted OIDC identities for Sigstore.
    pub trusted_sigstore_identities: Vec<String>,
    /// Trusted OIDC issuers for Sigstore.
    pub trusted_sigstore_issuers: Vec<String>,
    /// Whether to require transparency log verification.
    pub require_transparency: bool,
    /// Whether to require TUF verification.
    pub require_tuf: bool,
    /// Whether to require Sigstore verification.
    pub require_sigstore: bool,
}

/// No-op transparency log verifier for testing without external dependencies.
#[derive(Debug, Default)]
pub struct NoOpTransparencyVerifier;

#[async_trait]
impl TransparencyLogVerifier for NoOpTransparencyVerifier {
    async fn verify_entry(
        &self,
        _entry_hash: &str,
        _expected_entry: Option<&TransparencyLogEntry>,
    ) -> Result<TransparencyVerificationResult, SupplyChainVerificationError> {
        Ok(TransparencyVerificationResult {
            verified: true,
            log_index: Some(0),
            logged_at: Some(0),
        })
    }
}

/// No-op TUF verifier for testing without external dependencies.
#[derive(Debug, Default)]
pub struct NoOpTufVerifier;

#[async_trait]
impl TufVerifier for NoOpTufVerifier {
    async fn verify_target(
        &self,
        _pinned_root: &TufRootMetadata,
        _target_path: &str,
    ) -> Result<TufVerificationResult, SupplyChainVerificationError> {
        Ok(TufVerificationResult {
            verified: true,
            root_version: 1,
            target: None,
        })
    }

    async fn fetch_root(&self) -> Result<TufRootMetadata, SupplyChainVerificationError> {
        Ok(TufRootMetadata {
            version: 1,
            root_hash: String::new(),
            expires: u64::MAX,
            key_ids: Vec::new(),
            threshold: 1,
        })
    }
}

/// No-op Sigstore verifier for testing without external dependencies.
#[derive(Debug, Default)]
pub struct NoOpSigstoreVerifier;

#[async_trait]
impl SigstoreVerifier for NoOpSigstoreVerifier {
    async fn verify_bundle(
        &self,
        _bundle: &SigstoreBundle,
        _artifact_hash: &str,
        _trusted_identities: &[String],
        _trusted_issuers: &[String],
    ) -> Result<SigstoreVerificationResult, SupplyChainVerificationError> {
        Ok(SigstoreVerificationResult {
            verified: true,
            identity: None,
            issuer: None,
            rekor_log_index: None,
        })
    }
}

/// Mock transparency log verifier for controlled testing.
#[derive(Debug, Default)]
pub struct MockTransparencyVerifier {
    /// Entries to accept as valid.
    pub valid_entries: std::sync::Mutex<HashMap<String, TransparencyLogEntry>>,
}

impl MockTransparencyVerifier {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_valid_entry(&self, entry_hash: String, entry: TransparencyLogEntry) {
        self.valid_entries.lock().unwrap().insert(entry_hash, entry);
    }
}

#[async_trait]
impl TransparencyLogVerifier for MockTransparencyVerifier {
    async fn verify_entry(
        &self,
        entry_hash: &str,
        _expected_entry: Option<&TransparencyLogEntry>,
    ) -> Result<TransparencyVerificationResult, SupplyChainVerificationError> {
        let entries = self.valid_entries.lock().unwrap();
        if let Some(entry) = entries.get(entry_hash) {
            Ok(TransparencyVerificationResult {
                verified: true,
                log_index: Some(entry.log_index),
                logged_at: Some(0),
            })
        } else {
            Err(SupplyChainVerificationError::TransparencyEntryNotFound)
        }
    }
}

/// Mock TUF verifier for controlled testing.
#[derive(Debug)]
pub struct MockTufVerifier {
    /// Root metadata to return.
    pub root: TufRootMetadata,
    /// Targets to accept as valid.
    pub valid_targets: std::sync::Mutex<HashMap<String, TufTargetInfo>>,
}

impl MockTufVerifier {
    pub fn new(root: TufRootMetadata) -> Self {
        Self {
            root,
            valid_targets: std::sync::Mutex::new(HashMap::new()),
        }
    }

    pub fn add_valid_target(&self, path: String, target: TufTargetInfo) {
        self.valid_targets.lock().unwrap().insert(path, target);
    }
}

#[async_trait]
impl TufVerifier for MockTufVerifier {
    async fn verify_target(
        &self,
        pinned_root: &TufRootMetadata,
        target_path: &str,
    ) -> Result<TufVerificationResult, SupplyChainVerificationError> {
        // Check root hash matches
        if pinned_root.root_hash != self.root.root_hash {
            return Err(SupplyChainVerificationError::TufRootMismatch {
                expected: pinned_root.root_hash.clone(),
                actual: self.root.root_hash.clone(),
            });
        }
        // Check for rollback
        if self.root.version < pinned_root.version {
            return Err(SupplyChainVerificationError::TufRollback {
                current: pinned_root.version,
                got: self.root.version,
            });
        }

        let targets = self.valid_targets.lock().unwrap();
        if let Some(target) = targets.get(target_path) {
            Ok(TufVerificationResult {
                verified: true,
                root_version: self.root.version,
                target: Some(target.clone()),
            })
        } else {
            Err(SupplyChainVerificationError::TufTargetNotFound {
                target: target_path.to_string(),
            })
        }
    }

    async fn fetch_root(&self) -> Result<TufRootMetadata, SupplyChainVerificationError> {
        Ok(self.root.clone())
    }
}

/// Mock Sigstore verifier for controlled testing.
#[derive(Debug, Default)]
pub struct MockSigstoreVerifier {
    /// Bundles to accept as valid (keyed by artifact hash).
    pub valid_bundles: std::sync::Mutex<HashMap<String, SigstoreVerificationResult>>,
}

impl MockSigstoreVerifier {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_valid_bundle(&self, artifact_hash: String, result: SigstoreVerificationResult) {
        self.valid_bundles
            .lock()
            .unwrap()
            .insert(artifact_hash, result);
    }
}

#[async_trait]
impl SigstoreVerifier for MockSigstoreVerifier {
    async fn verify_bundle(
        &self,
        _bundle: &SigstoreBundle,
        artifact_hash: &str,
        trusted_identities: &[String],
        trusted_issuers: &[String],
    ) -> Result<SigstoreVerificationResult, SupplyChainVerificationError> {
        let bundles = self.valid_bundles.lock().unwrap();
        if let Some(result) = bundles.get(artifact_hash) {
            // Verify identity if specified
            if let Some(identity) = &result.identity {
                if !trusted_identities.is_empty() && !trusted_identities.contains(identity) {
                    return Err(SupplyChainVerificationError::SigstoreIdentityMismatch {
                        expected: trusted_identities.join(","),
                        actual: identity.clone(),
                    });
                }
            }
            // Verify issuer if specified
            if let Some(issuer) = &result.issuer {
                if !trusted_issuers.is_empty() && !trusted_issuers.contains(issuer) {
                    return Err(SupplyChainVerificationError::SigstoreIssuerUntrusted {
                        issuer: issuer.clone(),
                    });
                }
            }
            Ok(result.clone())
        } else {
            Err(SupplyChainVerificationError::SigstoreSignatureInvalid)
        }
    }
}

impl VerifiedConnectorBundle {
    #[must_use]
    pub fn report(&self, outcome: &str) -> RegistryVerificationReport {
        let verified_at = u64::try_from(Utc::now().timestamp()).unwrap_or(0);
        RegistryVerificationReport {
            connector_id: self.manifest.connector.id.to_string(),
            manifest_hash: self.manifest_hash.clone(),
            binary_hash: self.binary_hash.clone(),
            target: self.target.clone(),
            verified_at,
            outcome: outcome.to_string(),
        }
    }

    /// Extract rate limit declarations from the verified manifest, if present.
    #[must_use]
    pub fn rate_limit_declarations(&self) -> Option<RateLimitDeclarations> {
        self.manifest
            .rate_limits
            .as_ref()
            .map(|section| section.to_declarations())
    }
}

/// Mirroring outcome (object ids + hashes).
#[derive(Debug, Clone)]
pub struct MirrorResult {
    pub manifest_object_id: ObjectId,
    pub binary_object_id: ObjectId,
    pub manifest_hash: String,
    pub binary_hash: String,
}

/// Registry verifier and mirroring helper.
#[derive(Debug, Clone)]
pub struct RegistryVerifier {
    trust_policy: RegistryTrustPolicy,
}

impl RegistryVerifier {
    #[must_use]
    pub const fn new(trust_policy: RegistryTrustPolicy) -> Self {
        Self { trust_policy }
    }

    /// Verify a registry bundle against trust roots, policy, and target.
    ///
    /// # Errors
    /// Returns [`RegistryError`] if verification fails.
    pub fn verify_bundle(
        &self,
        bundle: &ConnectorBundle,
        zone_policy: Option<&ZonePolicyObject>,
        supply_chain: Option<&SupplyChainEvidence>,
        expected_target: Option<&ConnectorTarget>,
    ) -> Result<VerifiedConnectorBundle, RegistryError> {
        let manifest = ConnectorManifest::parse_str(&bundle.manifest_toml)?;

        if let Some(expected) = expected_target {
            if &bundle.target != expected {
                return Err(RegistryError::TargetMismatch {
                    expected: expected.as_string(),
                    found: bundle.target.as_string(),
                });
            }
        }

        let binary_hash = hash_bytes(&bundle.binary);
        let manifest_hash = hash_bytes(bundle.manifest_toml.as_bytes());
        let signing_bytes = manifest_signing_bytes(&manifest)?;

        let sig_section = manifest
            .signatures
            .as_ref()
            .ok_or(RegistryError::MissingSignatures)?;

        let publisher_ok = verify_publishers(
            &self.trust_policy,
            sig_section,
            &signing_bytes,
            &binary_hash,
        )?;
        let registry_ok = verify_registry(
            &self.trust_policy,
            sig_section,
            &signing_bytes,
            &binary_hash,
        )?;

        if self.trust_policy.require_registry_signature && !registry_ok {
            return Err(RegistryError::RegistrySignatureRequired);
        }

        if !publisher_ok && !registry_ok {
            return Err(RegistryError::RegistrySignatureRequired);
        }

        enforce_capability_ceiling(zone_policy, &manifest)?;
        enforce_supply_chain_policy(&manifest, supply_chain)?;

        Ok(VerifiedConnectorBundle {
            manifest,
            manifest_hash,
            binary_hash,
            target: bundle.target.clone(),
        })
    }

    /// Mirror a verified bundle into the object store as pinned objects.
    ///
    /// # Errors
    /// Returns [`RegistryError`] if object storage fails.
    pub async fn mirror_bundle(
        &self,
        verified: &VerifiedConnectorBundle,
        bundle: &ConnectorBundle,
        zone_id: ZoneId,
        object_id_key: &ObjectIdKey,
        store: &dyn ObjectStore,
    ) -> Result<MirrorResult, RegistryError> {
        let manifest_obj = ConnectorManifestObject {
            manifest_toml: bundle.manifest_toml.clone(),
            manifest_hash: verified.manifest_hash.clone(),
        };
        let binary_obj = ConnectorBinaryObject {
            target: verified.target.clone(),
            binary_hash: verified.binary_hash.clone(),
            binary: bundle.binary.clone(),
        };

        let manifest_schema =
            SchemaId::new("fcp.registry", "ConnectorManifest", Version::new(1, 0, 0));
        let binary_schema = SchemaId::new("fcp.registry", "ConnectorBinary", Version::new(1, 0, 0));

        let manifest_body = CanonicalSerializer::serialize(&manifest_obj, &manifest_schema)?;
        let binary_body = CanonicalSerializer::serialize(&binary_obj, &binary_schema)?;

        let now = u64::try_from(Utc::now().timestamp()).unwrap_or(0);
        let provenance = Provenance::new(zone_id.clone());

        let manifest_header = ObjectHeader {
            schema: manifest_schema,
            zone_id: zone_id.clone(),
            created_at: now,
            provenance: provenance.clone(),
            refs: Vec::new(),
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        };

        let manifest_object_id =
            StoredObject::derive_id(&manifest_header, &manifest_body, object_id_key)?;
        let manifest_record = StoredObject {
            object_id: manifest_object_id,
            header: manifest_header,
            body: manifest_body,
            storage: StorageMeta {
                retention: RetentionClass::Pinned,
            },
        };

        let binary_header = ObjectHeader {
            schema: binary_schema,
            zone_id,
            created_at: now,
            provenance,
            refs: vec![manifest_object_id],
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        };

        let binary_object_id =
            StoredObject::derive_id(&binary_header, &binary_body, object_id_key)?;
        let binary_record = StoredObject {
            object_id: binary_object_id,
            header: binary_header,
            body: binary_body,
            storage: StorageMeta {
                retention: RetentionClass::Pinned,
            },
        };

        store.put(manifest_record).await?;
        store.put(binary_record).await?;

        Ok(MirrorResult {
            manifest_object_id,
            binary_object_id,
            manifest_hash: verified.manifest_hash.clone(),
            binary_hash: verified.binary_hash.clone(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConnectorManifestObject {
    manifest_toml: String,
    manifest_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConnectorBinaryObject {
    target: ConnectorTarget,
    binary_hash: String,
    binary: Vec<u8>,
}

/// Compute canonical signing bytes for a manifest (excludes signatures section).
///
/// # Errors
/// Returns `RegistryError` if serialization fails.

pub fn manifest_signing_bytes(manifest: &ConnectorManifest) -> Result<Vec<u8>, RegistryError> {
    let mut value = serde_json::to_value(manifest).map_err(|_| RegistryError::SignatureBytes)?;
    if let Some(object) = value.as_object_mut() {
        object.remove("signatures");
    }
    let schema = SchemaId::new("fcp.registry", "ManifestSigningView", Version::new(1, 0, 0));
    Ok(CanonicalSerializer::serialize(&value, &schema)?)
}

fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    format!("sha256:{}", hex::encode(digest))
}

fn verify_publishers(
    trust: &RegistryTrustPolicy,
    sigs: &SignaturesSection,
    signing_bytes: &[u8],
    binary_hash: &str,
) -> Result<bool, RegistryError> {
    if sigs.publisher_signatures.is_empty() {
        return Ok(false);
    }

    let required = sigs.publisher_threshold.map_or(0, |t| t.k);
    let mut valid = 0u8;

    for entry in &sigs.publisher_signatures {
        if verify_signature_entry(trust, entry, signing_bytes, binary_hash, true)? {
            valid = valid.saturating_add(1);
        }
    }

    if required > 0 && valid < required {
        return Err(RegistryError::PublisherThresholdUnmet { required, valid });
    }

    Ok(valid > 0)
}

fn verify_registry(
    trust: &RegistryTrustPolicy,
    sigs: &SignaturesSection,
    signing_bytes: &[u8],
    binary_hash: &str,
) -> Result<bool, RegistryError> {
    let Some(entry) = sigs.registry_signature.as_ref() else {
        return Ok(false);
    };

    verify_signature_entry(trust, entry, signing_bytes, binary_hash, false)
}

fn verify_signature_entry(
    trust: &RegistryTrustPolicy,
    entry: &SignatureEntry,
    signing_bytes: &[u8],
    binary_hash: &str,
    publisher: bool,
) -> Result<bool, RegistryError> {
    let key = if publisher {
        trust.publisher_keys.get(&entry.kid)
    } else {
        trust.registry_keys.get(&entry.kid)
    }
    .ok_or_else(|| RegistryError::UnknownKid {
        kid: entry.kid.clone(),
    })?;

    let signature = signature_from_entry(&entry.sig)?;
    let message = signature_message(signing_bytes, binary_hash);

    key.verify_with_context(MANIFEST_SIGNATURE_CONTEXT, &message, &signature)
        .map_err(|_| RegistryError::SignatureInvalid {
            kid: entry.kid.clone(),
        })?;

    Ok(true)
}

fn signature_from_entry(sig: &Base64Bytes) -> Result<Ed25519Signature, RegistryError> {
    Ed25519Signature::try_from_slice(sig.as_bytes()).map_err(|_| RegistryError::SignatureBytes)
}

/// Build the message to sign/verify: `signing_bytes || binary_hash`.

#[must_use]
pub fn signature_message(signing_bytes: &[u8], binary_hash: &str) -> Vec<u8> {
    let mut message = Vec::with_capacity(signing_bytes.len() + binary_hash.len());
    message.extend_from_slice(signing_bytes);
    message.extend_from_slice(binary_hash.as_bytes());
    message
}

fn enforce_capability_ceiling(
    zone_policy: Option<&ZonePolicyObject>,
    manifest: &ConnectorManifest,
) -> Result<(), RegistryError> {
    let Some(policy) = zone_policy else {
        return Ok(());
    };

    if policy.capability_ceiling.is_empty() {
        return Ok(());
    }

    let mut caps: HashSet<CapabilityId> = HashSet::new();
    caps.extend(manifest.capabilities.required.iter().cloned());
    caps.extend(manifest.capabilities.optional.iter().cloned());
    for op in manifest.provides.operations.values() {
        caps.insert(op.capability.clone());
    }

    for cap in caps {
        if !policy.capability_ceiling.contains(&cap) {
            return Err(RegistryError::CapabilityCeilingViolation {
                capability: cap.as_str().to_string(),
            });
        }
    }

    Ok(())
}

fn enforce_supply_chain_policy(
    manifest: &ConnectorManifest,
    evidence: Option<&SupplyChainEvidence>,
) -> Result<(), RegistryError> {
    let Some(policy) = manifest.policy.as_ref() else {
        return Ok(());
    };

    if policy.require_transparency_log {
        let entry_present = manifest
            .signatures
            .as_ref()
            .and_then(|sig| sig.transparency_log_entry.as_ref())
            .is_some();
        if !entry_present {
            return Err(RegistryError::TransparencyLogMissing);
        }
        let evidence = evidence.ok_or(RegistryError::TransparencyEvidenceMissing)?;
        if !evidence.transparency_log_present {
            return Err(RegistryError::TransparencyEvidenceMissing);
        }
    }

    if !policy.require_attestation_types.is_empty() {
        let evidence = evidence.ok_or(RegistryError::AttestationEvidenceMissing)?;
        for required in &policy.require_attestation_types {
            if !evidence
                .attestations
                .iter()
                .any(|att| &att.attestation_type == required)
            {
                return Err(RegistryError::RequiredAttestationMissing {
                    attestation: attestation_label(*required).to_string(),
                });
            }
        }
    }

    if let Some(required_level) = policy.min_slsa_level {
        let evidence = evidence.ok_or(RegistryError::AttestationEvidenceMissing)?;
        let meets_level = evidence
            .attestations
            .iter()
            .any(|att| att.slsa_level.is_some_and(|level| level >= required_level));
        if !meets_level {
            return Err(RegistryError::SlsaLevelInsufficient {
                required: required_level,
            });
        }
    }

    if !policy.trusted_builders.is_empty() {
        let evidence = evidence.ok_or(RegistryError::AttestationEvidenceMissing)?;
        for attestation in &evidence.attestations {
            if let Some(builder) = attestation.builder_id.as_ref() {
                if !policy.trusted_builders.iter().any(|b| b == builder) {
                    return Err(RegistryError::UntrustedBuilder {
                        builder: builder.clone(),
                    });
                }
            }
        }
    }

    Ok(())
}

fn attestation_label(attestation: AttestationType) -> &'static str {
    match attestation {
        AttestationType::InToto => "in-toto",
        AttestationType::ReproducibleBuild => "reproducible-build",
        AttestationType::CodeReview => "code-review",
    }
}

#[async_trait]
pub trait RegistrySource: Send + Sync {
    async fn fetch_bundle(&self, connector_id: &str) -> Result<ConnectorBundle, RegistryError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use chrono::Utc;
    use fcp_core::{DecisionReceiptPolicy, ZoneTransportPolicy};
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_manifest::PolicySection;
    use fcp_store::{MemoryObjectStore, MemoryObjectStoreConfig};
    use serde_json::json;
    use std::panic::{self, AssertUnwindSafe};
    use std::time::Instant;
    use uuid::Uuid;

    const PLACEHOLDER_HASH: &str = "blake3-256:fcp.interface.v2:0000000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn test_connector_target_normalization() {
        let target = ConnectorTarget::from_env();
        // Since we can't easily mock std::env::consts::ARCH, we just verify it's NOT x86_64/aarch64
        // if the platform matches those.
        match std::env::consts::ARCH {
            "x86_64" => assert_eq!(target.arch, "amd64"),
            "aarch64" => assert_eq!(target.arch, "arm64"),
            _ => {} // Other archs passed through
        }
    }

    #[derive(Default)]
    struct RegistryLogData {
        connector_id: Option<String>,
        version: Option<String>,
        manifest_hash: Option<String>,
        binary_hash: Option<String>,
        target: Option<String>,
        reason_code: Option<String>,
        details: Option<serde_json::Value>,
    }

    fn run_registry_test<F, Fut>(
        test_name: &str,
        phase: &str,
        operation: &str,
        assertions: u32,
        f: F,
    ) where
        F: FnOnce() -> Fut + panic::UnwindSafe,
        Fut: std::future::Future<Output = RegistryLogData>,
    {
        let start = Instant::now();
        let result = panic::catch_unwind(AssertUnwindSafe(|| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .expect("runtime");
            rt.block_on(f())
        }));
        let duration_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);

        let (passed, failed, outcome, data) = match &result {
            Ok(data) => (assertions, 0, "pass", Some(data)),
            Err(_) => (0, assertions, "fail", None),
        };

        let log = json!({
            "timestamp": Utc::now().to_rfc3339(),
            "level": "info",
            "test_name": test_name,
            "module": "fcp-registry",
            "phase": phase,
            "operation": operation,
            "correlation_id": Uuid::new_v4().to_string(),
            "result": outcome,
            "duration_ms": duration_ms,
            "connector_id": data.and_then(|d| d.connector_id.clone()),
            "version": data.and_then(|d| d.version.clone()),
            "manifest_hash": data.and_then(|d| d.manifest_hash.clone()),
            "binary_hash": data.and_then(|d| d.binary_hash.clone()),
            "target": data.and_then(|d| d.target.clone()),
            "reason_code": data.and_then(|d| d.reason_code.clone()),
            "details": data.and_then(|d| d.details.clone()),
            "assertions": {
                "passed": passed,
                "failed": failed
            }
        });
        println!("{log}");

        if let Err(payload) = result {
            panic::resume_unwind(payload);
        }
    }

    fn minimal_manifest() -> ConnectorManifest {
        let raw = include_str!("../../../tests/vectors/manifest/manifest_minimal.toml");
        ConnectorManifest::parse_str_unchecked(raw).expect("manifest parse")
    }

    fn base_manifest_toml() -> String {
        let raw = include_str!("../../../tests/vectors/manifest/manifest_minimal.toml");
        let unchecked = ConnectorManifest::parse_str_unchecked(raw).expect("manifest");
        let hash = unchecked.compute_interface_hash().expect("interface hash");
        raw.replace(PLACEHOLDER_HASH, &hash.to_string())
    }

    fn unsigned_manifest_toml(extra_sections: &str) -> String {
        if extra_sections.trim().is_empty() {
            base_manifest_toml()
        } else {
            format!("{}\n{}", base_manifest_toml(), extra_sections)
        }
    }

    fn manifest_with_signature(sig: Base64Bytes) -> ConnectorManifest {
        let mut manifest = minimal_manifest();
        manifest.signatures = Some(SignaturesSection {
            publisher_signatures: vec![SignatureEntry {
                kid: "pub1".to_string(),
                sig,
            }],
            publisher_threshold: Some(fcp_manifest::SignatureThreshold { k: 1, n: 1 }),
            registry_signature: None,
            transparency_log_entry: None,
        });
        manifest
    }

    fn sign_manifest_toml(
        manifest_toml: &str,
        signing_key: &Ed25519SigningKey,
        binary_hash: &str,
    ) -> Base64Bytes {
        let manifest = ConnectorManifest::parse_str(manifest_toml).expect("manifest");
        let signing_bytes = manifest_signing_bytes(&manifest).expect("signing bytes");
        let message = signature_message(&signing_bytes, binary_hash);
        let signature = signing_key.sign_with_context(MANIFEST_SIGNATURE_CONTEXT, &message);
        Base64Bytes::try_from(format!(
            "base64:{}",
            base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
        ))
        .expect("base64 sig")
    }

    fn publisher_signature_section(kid: &str, sig: &Base64Bytes) -> String {
        format!(
            r#"[signatures]
publisher_threshold = "1-of-1"

[[signatures.publisher_signatures]]
kid = "{kid}"
sig = "{sig}"
"#,
            sig = String::from(sig.clone())
        )
    }

    fn registry_signature_section(kid: &str, sig: &Base64Bytes) -> String {
        format!(
            r#"[signatures.registry_signature]
kid = "{kid}"
sig = "{sig}"
"#,
            sig = String::from(sig.clone())
        )
    }

    fn with_signatures(unsigned: &str, signatures: &str) -> String {
        format!("{unsigned}\n{signatures}")
    }

    fn test_target() -> ConnectorTarget {
        ConnectorTarget {
            os: "linux".to_string(),
            arch: "amd64".to_string(),
        }
    }

    fn test_zone_policy(capability_ceiling: Vec<CapabilityId>) -> ZonePolicyObject {
        let zone = ZoneId::work();
        ZonePolicyObject {
            header: ObjectHeader {
                schema: SchemaId::new("fcp.test", "ZonePolicyObject", Version::new(1, 0, 0)),
                zone_id: zone.clone(),
                created_at: 1_700_000_000,
                provenance: Provenance::new(zone.clone()),
                refs: vec![],
                foreign_refs: vec![],
                ttl_secs: None,
                placement: None,
            },
            zone_id: zone,
            principal_allow: Vec::new(),
            principal_deny: Vec::new(),
            connector_allow: Vec::new(),
            connector_deny: Vec::new(),
            capability_allow: Vec::new(),
            capability_deny: Vec::new(),
            capability_ceiling,
            transport_policy: ZoneTransportPolicy::default(),
            decision_receipts: DecisionReceiptPolicy::default(),
            usage_budget: None,
            requires_posture: None,
        }
    }

    #[test]
    fn verify_publisher_signature_ok() {
        run_registry_test(
            "verify_publisher_signature_ok",
            "verify",
            "signature",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let manifest = minimal_manifest();
                let signing_bytes = manifest_signing_bytes(&manifest).expect("signing bytes");
                let binary_hash = "sha256:deadbeef";
                let message = signature_message(&signing_bytes, binary_hash);
                let signature = signing_key.sign_with_context(MANIFEST_SIGNATURE_CONTEXT, &message);
                let sig = Base64Bytes::try_from(format!(
                    "base64:{}",
                    base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
                ))
                .expect("base64 sig");

                let manifest = manifest_with_signature(sig);
                let sigs = manifest.signatures.as_ref().expect("signatures");

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let ok = verify_publishers(&trust, sigs, &signing_bytes, binary_hash)
                    .expect("verify publishers");
                assert!(ok);

                RegistryLogData {
                    connector_id: Some(manifest.connector.id.to_string()),
                    version: Some(manifest.connector.version.to_string()),
                    reason_code: Some("publisher_signature_valid".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_publisher_signature_rejects_unknown_kid() {
        run_registry_test(
            "verify_publisher_signature_rejects_unknown_kid",
            "verify",
            "signature",
            1,
            || async {
                let manifest = minimal_manifest();
                let signing_bytes = manifest_signing_bytes(&manifest).expect("signing bytes");
                let sig = Base64Bytes::try_from("base64:AA==".to_string()).expect("base64 sig");
                let manifest = manifest_with_signature(sig);
                let sigs = manifest.signatures.as_ref().expect("signatures");

                let trust = RegistryTrustPolicy::default();
                let err = verify_publishers(&trust, sigs, &signing_bytes, "sha256:dead")
                    .expect_err("unknown kid");
                assert!(matches!(err, RegistryError::UnknownKid { .. }));

                RegistryLogData {
                    connector_id: Some(manifest.connector.id.to_string()),
                    reason_code: Some("unknown_kid".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn supply_chain_policy_requires_attestation_evidence() {
        run_registry_test(
            "supply_chain_policy_requires_attestation_evidence",
            "verify",
            "attestation",
            1,
            || async {
                let mut manifest = minimal_manifest();
                manifest.policy = Some(PolicySection {
                    require_transparency_log: false,
                    require_attestation_types: vec![AttestationType::InToto],
                    min_slsa_level: None,
                    trusted_builders: Vec::new(),
                });

                let err =
                    enforce_supply_chain_policy(&manifest, None).expect_err("missing evidence");
                assert!(matches!(err, RegistryError::AttestationEvidenceMissing));

                RegistryLogData {
                    connector_id: Some(manifest.connector.id.to_string()),
                    reason_code: Some("attestation_evidence_missing".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn capability_ceiling_violation_detected() {
        run_registry_test(
            "capability_ceiling_violation_detected",
            "verify",
            "policy",
            1,
            || async {
                let manifest = minimal_manifest();
                let policy = test_zone_policy(vec![CapabilityId::from_static("cap.other")]);

                let err =
                    enforce_capability_ceiling(Some(&policy), &manifest).expect_err("ceiling");
                assert!(matches!(
                    err,
                    RegistryError::CapabilityCeilingViolation { .. }
                ));

                RegistryLogData {
                    connector_id: Some(manifest.connector.id.to_string()),
                    reason_code: Some("capability_ceiling_violation".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_accepts_valid_publisher_signature() {
        run_registry_test(
            "verify_bundle_accepts_valid_publisher_signature",
            "verify",
            "signature",
            3,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml: manifest_toml.clone(),
                    binary: binary.clone(),
                    target: test_target(),
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                let verified = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect("verify");

                assert_eq!(verified.binary_hash, binary_hash);
                assert_eq!(verified.manifest_hash, hash_bytes(manifest_toml.as_bytes()));
                assert_eq!(verified.target, bundle.target);

                RegistryLogData {
                    connector_id: Some(verified.manifest.connector.id.to_string()),
                    version: Some(verified.manifest.connector.version.to_string()),
                    manifest_hash: Some(verified.manifest_hash),
                    binary_hash: Some(verified.binary_hash),
                    target: Some(verified.target.as_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_rejects_missing_signatures() {
        run_registry_test(
            "verify_bundle_rejects_missing_signatures",
            "verify",
            "signature",
            1,
            || async {
                let binary = b"registry-binary".to_vec();
                let bundle = ConnectorBundle {
                    manifest_toml: unsigned_manifest_toml(""),
                    binary,
                    target: test_target(),
                };

                let verifier = RegistryVerifier::new(RegistryTrustPolicy::default());
                let err = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect_err("missing signatures");
                assert!(matches!(err, RegistryError::MissingSignatures));

                RegistryLogData {
                    reason_code: Some("missing_signatures".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_rejects_malformed_manifest() {
        run_registry_test(
            "verify_bundle_rejects_malformed_manifest",
            "verify",
            "manifest",
            1,
            || async {
                let bundle = ConnectorBundle {
                    manifest_toml: "not-a-manifest".to_string(),
                    binary: vec![0u8],
                    target: test_target(),
                };

                let verifier = RegistryVerifier::new(RegistryTrustPolicy::default());
                let err = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect_err("malformed manifest");
                assert!(matches!(&err, RegistryError::ManifestParse(_)));

                RegistryLogData {
                    reason_code: Some("manifest_parse_failed".to_string()),
                    details: Some(json!({
                        "error": format!("{err}")
                    })),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_rejects_unknown_kid() {
        run_registry_test(
            "verify_bundle_rejects_unknown_kid",
            "verify",
            "signature",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let verifier = RegistryVerifier::new(RegistryTrustPolicy::default());
                let err = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect_err("unknown kid");
                assert!(matches!(err, RegistryError::UnknownKid { .. }));

                RegistryLogData {
                    reason_code: Some("unknown_kid".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_rejects_binary_hash_mismatch() {
        run_registry_test(
            "verify_bundle_rejects_binary_hash_mismatch",
            "verify",
            "checksum",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let expected_binary = b"expected-binary".to_vec();
                let expected_hash = hash_bytes(&expected_binary);
                let unsigned = unsigned_manifest_toml("");
                let sig = sign_manifest_toml(&unsigned, &signing_key, &expected_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary: b"tampered-binary".to_vec(),
                    target: test_target(),
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                let err = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect_err("binary mismatch");
                assert!(matches!(err, RegistryError::SignatureInvalid { .. }));

                RegistryLogData {
                    reason_code: Some("checksum_mismatch".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_rejects_target_mismatch() {
        run_registry_test(
            "verify_bundle_rejects_target_mismatch",
            "verify",
            "target",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                let err = verifier
                    .verify_bundle(
                        &bundle,
                        None,
                        None,
                        Some(&ConnectorTarget {
                            os: "darwin".to_string(),
                            arch: "amd64".to_string(),
                        }),
                    )
                    .expect_err("target mismatch");
                assert!(matches!(err, RegistryError::TargetMismatch { .. }));

                RegistryLogData {
                    reason_code: Some("target_mismatch".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_rejects_capability_ceiling_violation() {
        run_registry_test(
            "verify_bundle_rejects_capability_ceiling_violation",
            "verify",
            "policy",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let zone_policy = test_zone_policy(vec![CapabilityId::from_static("network.dns")]);
                let verifier = RegistryVerifier::new(trust);
                let err = verifier
                    .verify_bundle(&bundle, Some(&zone_policy), None, None)
                    .expect_err("capability ceiling");
                assert!(matches!(
                    err,
                    RegistryError::CapabilityCeilingViolation { .. }
                ));

                RegistryLogData {
                    reason_code: Some("capability_ceiling_violation".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_rejects_transparency_log_missing() {
        run_registry_test(
            "verify_bundle_rejects_transparency_log_missing",
            "verify",
            "transparency",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let policy = r#"[policy]
require_transparency_log = true
"#;
                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml(policy);
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                let err = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect_err("missing transparency entry");
                assert!(matches!(err, RegistryError::TransparencyLogMissing));

                RegistryLogData {
                    reason_code: Some("transparency_log_missing".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_rejects_transparency_evidence_missing() {
        run_registry_test(
            "verify_bundle_rejects_transparency_evidence_missing",
            "verify",
            "transparency",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let policy = r#"[policy]
require_transparency_log = true
"#;
                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml(policy);
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);

                // Create combined signatures section with both publisher sig and transparency entry
                let signatures_section = format!(
                    r#"[signatures]
publisher_threshold = "1-of-1"
transparency_log_entry = "objectid:{}"

[[signatures.publisher_signatures]]
kid = "pub1"
sig = "{}"
"#,
                    hex::encode([0u8; 32]),
                    String::from(sig)
                );

                let manifest_toml = with_signatures(&unsigned, &signatures_section);

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                let err = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect_err("missing transparency evidence");
                assert!(matches!(err, RegistryError::TransparencyEvidenceMissing));

                RegistryLogData {
                    reason_code: Some("transparency_evidence_missing".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_rejects_missing_attestation_type() {
        run_registry_test(
            "verify_bundle_rejects_missing_attestation_type",
            "verify",
            "attestation",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let policy = r#"[policy]
require_attestation_types = ["in-toto"]
"#;
                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml(policy);
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let evidence = SupplyChainEvidence {
                    transparency_log_present: false,
                    attestations: vec![AttestationEvidence {
                        attestation_type: AttestationType::CodeReview,
                        slsa_level: Some(2),
                        builder_id: Some("builder-a".to_string()),
                    }],
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                let err = verifier
                    .verify_bundle(&bundle, None, Some(&evidence), None)
                    .expect_err("missing attestation type");
                assert!(matches!(
                    err,
                    RegistryError::RequiredAttestationMissing { .. }
                ));

                RegistryLogData {
                    reason_code: Some("attestation_missing".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_rejects_slsa_level_insufficient() {
        run_registry_test(
            "verify_bundle_rejects_slsa_level_insufficient",
            "verify",
            "attestation",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let policy = r#"[policy]
min_slsa_level = 3
"#;
                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml(policy);
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let evidence = SupplyChainEvidence {
                    transparency_log_present: false,
                    attestations: vec![AttestationEvidence {
                        attestation_type: AttestationType::InToto,
                        slsa_level: Some(2),
                        builder_id: Some("builder-a".to_string()),
                    }],
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                let err = verifier
                    .verify_bundle(&bundle, None, Some(&evidence), None)
                    .expect_err("insufficient slsa level");
                assert!(matches!(
                    err,
                    RegistryError::SlsaLevelInsufficient { required: 3 }
                ));

                RegistryLogData {
                    reason_code: Some("slsa_level_insufficient".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_rejects_untrusted_builder() {
        run_registry_test(
            "verify_bundle_rejects_untrusted_builder",
            "verify",
            "attestation",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let policy = r#"[policy]
trusted_builders = ["trusted-builder"]
"#;
                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml(policy);
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let evidence = SupplyChainEvidence {
                    transparency_log_present: false,
                    attestations: vec![AttestationEvidence {
                        attestation_type: AttestationType::InToto,
                        slsa_level: Some(3),
                        builder_id: Some("untrusted".to_string()),
                    }],
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                let err = verifier
                    .verify_bundle(&bundle, None, Some(&evidence), None)
                    .expect_err("untrusted builder");
                assert!(matches!(err, RegistryError::UntrustedBuilder { .. }));

                RegistryLogData {
                    reason_code: Some("untrusted_builder".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_rejects_registry_signature_required() {
        run_registry_test(
            "verify_bundle_rejects_registry_signature_required",
            "verify",
            "signature",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);
                trust.require_registry_signature = true;

                let verifier = RegistryVerifier::new(trust);
                let err = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect_err("registry signature required");
                assert!(matches!(err, RegistryError::RegistrySignatureRequired));

                RegistryLogData {
                    reason_code: Some("registry_signature_required".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_accepts_registry_signature_only() {
        run_registry_test(
            "verify_bundle_accepts_registry_signature_only",
            "verify",
            "signature",
            2,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &registry_signature_section("reg1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml: manifest_toml.clone(),
                    binary: binary.clone(),
                    target: test_target(),
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .registry_keys
                    .insert("reg1".to_string(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                let verified = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect("registry signature");
                assert_eq!(verified.binary_hash, binary_hash);
                assert_eq!(verified.manifest_hash, hash_bytes(manifest_toml.as_bytes()));

                RegistryLogData {
                    connector_id: Some(verified.manifest.connector.id.to_string()),
                    manifest_hash: Some(verified.manifest_hash),
                    binary_hash: Some(verified.binary_hash),
                    target: Some(verified.target.as_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn mirror_bundle_persists_objects() {
        run_registry_test(
            "mirror_bundle_persists_objects",
            "verify",
            "mirror",
            4,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                let verified = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect("verify");

                let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
                let zone_id = ZoneId::work();
                let object_id_key = ObjectIdKey::from_bytes([1u8; 32]);

                let result = verifier
                    .mirror_bundle(&verified, &bundle, zone_id, &object_id_key, &store)
                    .await
                    .expect("mirror bundle");

                let manifest_object = store
                    .get(&result.manifest_object_id)
                    .await
                    .expect("manifest object");
                let binary_object = store
                    .get(&result.binary_object_id)
                    .await
                    .expect("binary object");

                assert_eq!(manifest_object.storage.retention, RetentionClass::Pinned);
                assert_eq!(binary_object.storage.retention, RetentionClass::Pinned);
                assert_eq!(binary_object.header.refs, vec![result.manifest_object_id]);
                assert_eq!(binary_object.header.zone_id, ZoneId::work());

                RegistryLogData {
                    manifest_hash: Some(result.manifest_hash),
                    binary_hash: Some(result.binary_hash),
                    target: Some(verified.target.as_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Additional Manifest Verification Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn verify_bundle_rejects_invalid_signature() {
        run_registry_test(
            "verify_bundle_rejects_invalid_signature",
            "verify",
            "signature",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let wrong_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                // Sign with the wrong key
                let sig = sign_manifest_toml(&unsigned, &wrong_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                let err = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect_err("invalid signature");
                assert!(matches!(err, RegistryError::SignatureInvalid { .. }));

                RegistryLogData {
                    reason_code: Some("signature_invalid".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_rejects_missing_required_field() {
        run_registry_test(
            "verify_bundle_rejects_missing_required_field",
            "verify",
            "manifest",
            1,
            || async {
                // Manifest missing connector section
                let incomplete_toml = r#"[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"
min_mesh_version = "2.0.0"
min_protocol = "fcp2-sym/2.0"
"#;
                let bundle = ConnectorBundle {
                    manifest_toml: incomplete_toml.to_string(),
                    binary: b"binary".to_vec(),
                    target: test_target(),
                };

                let verifier = RegistryVerifier::new(RegistryTrustPolicy::default());
                let err = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect_err("missing required field");
                assert!(matches!(err, RegistryError::ManifestParse(_)));

                RegistryLogData {
                    reason_code: Some("missing_required_field".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_rejects_malformed_signature_bytes() {
        run_registry_test(
            "verify_bundle_rejects_malformed_signature_bytes",
            "verify",
            "signature",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                // Create a signature that's too short (not 64 bytes)
                let malformed_sig =
                    Base64Bytes::try_from("base64:AQIDBA==".to_string()).expect("base64");
                let unsigned = unsigned_manifest_toml("");
                let manifest_toml = with_signatures(
                    &unsigned,
                    &publisher_signature_section("pub1", &malformed_sig),
                );

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary: b"binary".to_vec(),
                    target: test_target(),
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                let err = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect_err("malformed signature");
                assert!(matches!(err, RegistryError::SignatureBytes));

                RegistryLogData {
                    reason_code: Some("signature_bytes_malformed".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Binary Verification Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn verify_bundle_accepts_zero_length_binary() {
        run_registry_test(
            "verify_bundle_accepts_zero_length_binary",
            "verify",
            "checksum",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                // Empty binary is valid if hash matches
                let binary: Vec<u8> = vec![];
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                let verified = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect("empty binary valid");

                assert_eq!(verified.binary_hash, hash_bytes(&[]));

                RegistryLogData {
                    binary_hash: Some(verified.binary_hash),
                    reason_code: Some("zero_length_binary_accepted".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_rejects_truncated_binary() {
        run_registry_test(
            "verify_bundle_rejects_truncated_binary",
            "verify",
            "checksum",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let original_binary = b"this is the full binary content".to_vec();
                let truncated_binary = b"this is the".to_vec();
                let original_hash = hash_bytes(&original_binary);
                let unsigned = unsigned_manifest_toml("");
                let sig = sign_manifest_toml(&unsigned, &signing_key, &original_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary: truncated_binary,
                    target: test_target(),
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                let err = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect_err("truncated binary");
                assert!(matches!(err, RegistryError::SignatureInvalid { .. }));

                RegistryLogData {
                    reason_code: Some("binary_truncated".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_rejects_extra_bytes_in_binary() {
        run_registry_test(
            "verify_bundle_rejects_extra_bytes_in_binary",
            "verify",
            "checksum",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let original_binary = b"original content".to_vec();
                let mut extended_binary = original_binary.clone();
                extended_binary.extend_from_slice(b"extra malicious bytes");
                let original_hash = hash_bytes(&original_binary);
                let unsigned = unsigned_manifest_toml("");
                let sig = sign_manifest_toml(&unsigned, &signing_key, &original_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary: extended_binary,
                    target: test_target(),
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                let err = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect_err("extra bytes");
                assert!(matches!(err, RegistryError::SignatureInvalid { .. }));

                RegistryLogData {
                    reason_code: Some("binary_extra_bytes".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Platform/Architecture Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn verify_bundle_rejects_wrong_architecture() {
        run_registry_test(
            "verify_bundle_rejects_wrong_architecture",
            "verify",
            "target",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: ConnectorTarget {
                        os: "linux".to_string(),
                        arch: "amd64".to_string(),
                    },
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                let err = verifier
                    .verify_bundle(
                        &bundle,
                        None,
                        None,
                        Some(&ConnectorTarget {
                            os: "linux".to_string(),
                            arch: "arm64".to_string(),
                        }),
                    )
                    .expect_err("arch mismatch");
                assert!(matches!(err, RegistryError::TargetMismatch { .. }));

                RegistryLogData {
                    reason_code: Some("arch_mismatch".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn connector_target_from_env_matches_runtime() {
        run_registry_test(
            "connector_target_from_env_matches_runtime",
            "verify",
            "target",
            2,
            || async {
                let target = ConnectorTarget::from_env();
                assert_eq!(target.os, std::env::consts::OS);
                // ConnectorTarget normalizes arch names for OCI/Docker compatibility
                let expected_arch = match std::env::consts::ARCH {
                    "x86_64" => "amd64",
                    "aarch64" => "arm64",
                    other => other,
                };
                assert_eq!(target.arch, expected_arch);

                RegistryLogData {
                    target: Some(target.as_string()),
                    reason_code: Some("target_matches_runtime".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Publisher Threshold Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn verify_bundle_rejects_publisher_threshold_unmet() {
        run_registry_test(
            "verify_bundle_rejects_publisher_threshold_unmet",
            "verify",
            "signature",
            1,
            || async {
                let signing_key1 = Ed25519SigningKey::generate();
                let verifying_key1 = signing_key1.verifying_key();
                let verifying_key2 = Ed25519SigningKey::generate().verifying_key();

                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                let sig1 = sign_manifest_toml(&unsigned, &signing_key1, &binary_hash);

                // Create threshold 2-of-2 but only provide 1 signature
                let signatures = format!(
                    r#"[signatures]
publisher_threshold = "2-of-2"

[[signatures.publisher_signatures]]
kid = "pub1"
sig = "{}"
"#,
                    String::from(sig1)
                );

                let manifest_toml = with_signatures(&unsigned, &signatures);

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key1);
                trust
                    .publisher_keys
                    .insert("pub2".to_string(), verifying_key2);

                let verifier = RegistryVerifier::new(trust);
                let err = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect_err("threshold unmet");
                // Manifest parsing validates signature count >= threshold before verification
                assert!(matches!(&err, RegistryError::ManifestParse(e)
                        if e.to_string().contains("insufficient signatures")));

                RegistryLogData {
                    reason_code: Some("manifest_parse_insufficient_signatures".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Attestation Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn verify_bundle_accepts_valid_attestation() {
        run_registry_test(
            "verify_bundle_accepts_valid_attestation",
            "verify",
            "attestation",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let policy = r#"[policy]
require_attestation_types = ["in-toto"]
min_slsa_level = 2
trusted_builders = ["trusted-builder"]
"#;
                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml(policy);
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let evidence = SupplyChainEvidence {
                    transparency_log_present: false,
                    attestations: vec![AttestationEvidence {
                        attestation_type: AttestationType::InToto,
                        slsa_level: Some(3),
                        builder_id: Some("trusted-builder".to_string()),
                    }],
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                let verified = verifier
                    .verify_bundle(&bundle, None, Some(&evidence), None)
                    .expect("attestation valid");

                RegistryLogData {
                    connector_id: Some(verified.manifest.connector.id.to_string()),
                    reason_code: Some("attestation_valid".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_accepts_transparency_log_with_evidence() {
        run_registry_test(
            "verify_bundle_accepts_transparency_log_with_evidence",
            "verify",
            "transparency",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let policy = r#"[policy]
require_transparency_log = true
"#;
                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml(policy);
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);

                // Combined signatures section with transparency_log_entry
                let signatures_section = format!(
                    r#"[signatures]
publisher_threshold = "1-of-1"
transparency_log_entry = "objectid:{}"

[[signatures.publisher_signatures]]
kid = "pub1"
sig = "{}"
"#,
                    hex::encode([0u8; 32]),
                    String::from(sig)
                );
                let manifest_toml = with_signatures(&unsigned, &signatures_section);

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let evidence = SupplyChainEvidence {
                    transparency_log_present: true,
                    attestations: vec![],
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                let verified = verifier
                    .verify_bundle(&bundle, None, Some(&evidence), None)
                    .expect("transparency log valid");

                RegistryLogData {
                    connector_id: Some(verified.manifest.connector.id.to_string()),
                    reason_code: Some("transparency_log_valid".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Capability Ceiling Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn verify_bundle_accepts_capabilities_within_ceiling() {
        run_registry_test(
            "verify_bundle_accepts_capabilities_within_ceiling",
            "verify",
            "policy",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                // Allow all capabilities required by the minimal manifest
                let zone_policy = test_zone_policy(vec![
                    CapabilityId::from_static("network.dns"),
                    CapabilityId::from_static("minimal.op"),
                ]);

                let verifier = RegistryVerifier::new(trust);
                let verified = verifier
                    .verify_bundle(&bundle, Some(&zone_policy), None, None)
                    .expect("capabilities within ceiling");

                RegistryLogData {
                    connector_id: Some(verified.manifest.connector.id.to_string()),
                    reason_code: Some("capabilities_within_ceiling".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Verification Report Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn verification_report_contains_all_fields() {
        run_registry_test(
            "verification_report_contains_all_fields",
            "verify",
            "report",
            5,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml: manifest_toml.clone(),
                    binary: binary.clone(),
                    target: test_target(),
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                let verified = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect("verify");

                let report = verified.report("success");
                assert_eq!(report.connector_id, "fcp.minimal");
                assert_eq!(report.manifest_hash, hash_bytes(manifest_toml.as_bytes()));
                assert_eq!(report.binary_hash, binary_hash);
                assert_eq!(report.target.os, "linux");
                assert_eq!(report.outcome, "success");

                RegistryLogData {
                    connector_id: Some(report.connector_id),
                    manifest_hash: Some(report.manifest_hash),
                    binary_hash: Some(report.binary_hash),
                    target: Some(report.target.as_string()),
                    reason_code: Some("report_complete".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Multiple Attestation Types Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn verify_bundle_accepts_multiple_attestation_types() {
        run_registry_test(
            "verify_bundle_accepts_multiple_attestation_types",
            "verify",
            "attestation",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let policy = r#"[policy]
require_attestation_types = ["in-toto", "code-review"]
"#;
                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml(policy);
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let evidence = SupplyChainEvidence {
                    transparency_log_present: false,
                    attestations: vec![
                        AttestationEvidence {
                            attestation_type: AttestationType::InToto,
                            slsa_level: Some(2),
                            builder_id: None,
                        },
                        AttestationEvidence {
                            attestation_type: AttestationType::CodeReview,
                            slsa_level: None,
                            builder_id: None,
                        },
                    ],
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                let verified = verifier
                    .verify_bundle(&bundle, None, Some(&evidence), None)
                    .expect("multiple attestations valid");

                RegistryLogData {
                    connector_id: Some(verified.manifest.connector.id.to_string()),
                    reason_code: Some("multiple_attestations_valid".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // MockRegistry Implementation for Structured Testing
    // ─────────────────────────────────────────────────────────────────────────────

    /// Mock registry for deterministic testing.
    struct MockRegistry {
        connectors: HashMap<String, MockConnectorEntry>,
    }

    struct MockConnectorEntry {
        manifest_toml: String,
        binary: Vec<u8>,
        target: ConnectorTarget,
        signing_key: Ed25519SigningKey,
    }

    impl MockRegistry {
        fn new() -> Self {
            Self {
                connectors: HashMap::new(),
            }
        }

        fn with_valid_connector(mut self, id: &str, version: &str) -> Self {
            let signing_key = Ed25519SigningKey::generate();
            let binary = format!("binary-for-{id}-{version}").into_bytes();
            let binary_hash = hash_bytes(&binary);

            let manifest_toml = format!(
                r#"[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"
min_mesh_version = "2.0.0"
min_protocol = "fcp2-sym/2.0"
protocol_features = []
max_datagram_bytes = 1200
interface_hash = "{placeholder}"

[connector]
id = "{id}"
name = "Test Connector"
version = "{version}"
description = "Test connector"
archetypes = ["operational"]
format = "native"

[zones]
home = "z:work"
allowed_sources = ["z:work"]
allowed_targets = ["z:work"]
forbidden = []

[capabilities]
required = []
optional = []
forbidden = ["system.exec"]

[provides.operations.test_op]
description = "Test operation"
capability = "test.op"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
idempotency = "none"
input_schema = {{ type = "object" }}
output_schema = {{ type = "object" }}

[sandbox]
profile = "strict"
memory_mb = 64
cpu_percent = 20
wall_clock_timeout_ms = 1000
fs_readonly_paths = ["/usr"]
fs_writable_paths = ["$CONNECTOR_STATE"]
deny_exec = true
deny_ptrace = true
"#,
                placeholder = PLACEHOLDER_HASH
            );

            // Parse and compute interface hash
            let unchecked =
                ConnectorManifest::parse_str_unchecked(&manifest_toml).expect("manifest");
            let interface_hash = unchecked.compute_interface_hash().expect("interface hash");
            let manifest_toml =
                manifest_toml.replace(PLACEHOLDER_HASH, &interface_hash.to_string());

            // Sign
            let manifest = ConnectorManifest::parse_str(&manifest_toml).expect("manifest");
            let signing_bytes = manifest_signing_bytes(&manifest).expect("signing bytes");
            let message = signature_message(&signing_bytes, &binary_hash);
            let signature = signing_key.sign_with_context(MANIFEST_SIGNATURE_CONTEXT, &message);
            let sig_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());

            let signed_manifest = format!(
                r#"{manifest_toml}

[signatures]
publisher_threshold = "1-of-1"

[[signatures.publisher_signatures]]
kid = "{id}-key"
sig = "base64:{sig_b64}"
"#
            );

            self.connectors.insert(
                id.to_string(),
                MockConnectorEntry {
                    manifest_toml: signed_manifest,
                    binary,
                    target: test_target(),
                    signing_key,
                },
            );
            self
        }

        fn get_bundle(&self, connector_id: &str) -> Option<ConnectorBundle> {
            self.connectors
                .get(connector_id)
                .map(|entry| ConnectorBundle {
                    manifest_toml: entry.manifest_toml.clone(),
                    binary: entry.binary.clone(),
                    target: entry.target.clone(),
                })
        }

        fn get_trust_policy(&self, connector_id: &str) -> Option<RegistryTrustPolicy> {
            self.connectors.get(connector_id).map(|entry| {
                let mut policy = RegistryTrustPolicy::default();
                policy.publisher_keys.insert(
                    format!("{connector_id}-key"),
                    entry.signing_key.verifying_key(),
                );
                policy
            })
        }
    }

    #[test]
    fn mock_registry_creates_verifiable_bundles() {
        run_registry_test(
            "mock_registry_creates_verifiable_bundles",
            "mock",
            "registry",
            2,
            || async {
                let registry = MockRegistry::new()
                    .with_valid_connector("fcp.test", "1.0.0")
                    .with_valid_connector("fcp.another", "2.0.0");

                let bundle = registry.get_bundle("fcp.test").expect("bundle");
                let trust = registry.get_trust_policy("fcp.test").expect("trust");

                let verifier = RegistryVerifier::new(trust);
                let verified = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect("verify");

                assert_eq!(verified.manifest.connector.id.as_str(), "fcp.test");
                assert_eq!(verified.manifest.connector.version.to_string(), "1.0.0");

                RegistryLogData {
                    connector_id: Some(verified.manifest.connector.id.to_string()),
                    version: Some(verified.manifest.connector.version.to_string()),
                    reason_code: Some("mock_registry_valid".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn mock_registry_nonexistent_connector_returns_none() {
        run_registry_test(
            "mock_registry_nonexistent_connector_returns_none",
            "mock",
            "registry",
            1,
            || async {
                let registry = MockRegistry::new().with_valid_connector("fcp.exists", "1.0.0");

                let bundle = registry.get_bundle("fcp.nonexistent");
                assert!(bundle.is_none());

                RegistryLogData {
                    reason_code: Some("nonexistent_connector".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Supply-Chain Verification Adapter Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn mock_transparency_verifier_accepts_valid_entry() {
        run_registry_test(
            "mock_transparency_verifier_accepts_valid_entry",
            "verify",
            "transparency-adapter",
            1,
            || async {
                let verifier = MockTransparencyVerifier::new();
                let entry = TransparencyLogEntry {
                    log_index: 12345,
                    entry_hash: "sha256:abc123".to_string(),
                    inclusion_proof: InclusionProof {
                        root_hash: "sha256:root".to_string(),
                        tree_size: 10000,
                        hashes: vec!["sha256:h1".to_string(), "sha256:h2".to_string()],
                        leaf_index: 12345,
                    },
                    signed_entry_timestamp: vec![1, 2, 3, 4],
                    log_id: "rekor.sigstore.dev".to_string(),
                };
                verifier.add_valid_entry("sha256:abc123".to_string(), entry);

                let result = verifier
                    .verify_entry("sha256:abc123", None)
                    .await
                    .expect("entry valid");
                assert!(result.verified);
                assert_eq!(result.log_index, Some(12345));

                RegistryLogData {
                    reason_code: Some("transparency_entry_verified".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn mock_transparency_verifier_rejects_unknown_entry() {
        run_registry_test(
            "mock_transparency_verifier_rejects_unknown_entry",
            "verify",
            "transparency-adapter",
            1,
            || async {
                let verifier = MockTransparencyVerifier::new();

                let err = verifier
                    .verify_entry("sha256:unknown", None)
                    .await
                    .expect_err("entry not found");
                assert!(matches!(
                    err,
                    SupplyChainVerificationError::TransparencyEntryNotFound
                ));

                RegistryLogData {
                    reason_code: Some("transparency_entry_not_found".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn mock_tuf_verifier_accepts_valid_target() {
        run_registry_test(
            "mock_tuf_verifier_accepts_valid_target",
            "verify",
            "tuf-adapter",
            1,
            || async {
                let root = TufRootMetadata {
                    version: 5,
                    root_hash: "sha256:rootabc".to_string(),
                    expires: u64::MAX,
                    key_ids: vec!["key1".to_string()],
                    threshold: 1,
                };
                let verifier = MockTufVerifier::new(root.clone());

                let target = TufTargetInfo {
                    target_path: "connectors/fcp.test-1.0.0.tar.gz".to_string(),
                    hash: "sha256:binaryhash".to_string(),
                    length: 1024,
                    delegations: vec!["targets".to_string()],
                };
                verifier.add_valid_target(
                    "connectors/fcp.test-1.0.0.tar.gz".to_string(),
                    target.clone(),
                );

                let result = verifier
                    .verify_target(&root, "connectors/fcp.test-1.0.0.tar.gz")
                    .await
                    .expect("target valid");
                assert!(result.verified);
                assert_eq!(result.root_version, 5);
                assert!(result.target.is_some());

                RegistryLogData {
                    reason_code: Some("tuf_target_verified".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn mock_tuf_verifier_rejects_root_mismatch() {
        run_registry_test(
            "mock_tuf_verifier_rejects_root_mismatch",
            "verify",
            "tuf-adapter",
            1,
            || async {
                let root = TufRootMetadata {
                    version: 5,
                    root_hash: "sha256:rootabc".to_string(),
                    expires: u64::MAX,
                    key_ids: vec!["key1".to_string()],
                    threshold: 1,
                };
                let verifier = MockTufVerifier::new(root);

                let pinned = TufRootMetadata {
                    version: 5,
                    root_hash: "sha256:different".to_string(),
                    expires: u64::MAX,
                    key_ids: vec!["key1".to_string()],
                    threshold: 1,
                };

                let err = verifier
                    .verify_target(&pinned, "connectors/fcp.test-1.0.0.tar.gz")
                    .await
                    .expect_err("root mismatch");
                assert!(matches!(
                    err,
                    SupplyChainVerificationError::TufRootMismatch { .. }
                ));

                RegistryLogData {
                    reason_code: Some("tuf_root_mismatch".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn mock_tuf_verifier_rejects_rollback() {
        run_registry_test(
            "mock_tuf_verifier_rejects_rollback",
            "verify",
            "tuf-adapter",
            1,
            || async {
                let root = TufRootMetadata {
                    version: 3,
                    root_hash: "sha256:rootabc".to_string(),
                    expires: u64::MAX,
                    key_ids: vec!["key1".to_string()],
                    threshold: 1,
                };
                let verifier = MockTufVerifier::new(root);

                // Pinned root has higher version (rollback attempt)
                let pinned = TufRootMetadata {
                    version: 5,
                    root_hash: "sha256:rootabc".to_string(),
                    expires: u64::MAX,
                    key_ids: vec!["key1".to_string()],
                    threshold: 1,
                };

                let err = verifier
                    .verify_target(&pinned, "connectors/fcp.test-1.0.0.tar.gz")
                    .await
                    .expect_err("rollback detected");
                assert!(matches!(
                    err,
                    SupplyChainVerificationError::TufRollback { current: 5, got: 3 }
                ));

                RegistryLogData {
                    reason_code: Some("tuf_rollback_detected".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn mock_tuf_verifier_rejects_target_not_found() {
        run_registry_test(
            "mock_tuf_verifier_rejects_target_not_found",
            "verify",
            "tuf-adapter",
            1,
            || async {
                let root = TufRootMetadata {
                    version: 5,
                    root_hash: "sha256:rootabc".to_string(),
                    expires: u64::MAX,
                    key_ids: vec!["key1".to_string()],
                    threshold: 1,
                };
                let verifier = MockTufVerifier::new(root.clone());

                let err = verifier
                    .verify_target(&root, "connectors/nonexistent.tar.gz")
                    .await
                    .expect_err("target not found");
                assert!(matches!(
                    err,
                    SupplyChainVerificationError::TufTargetNotFound { .. }
                ));

                RegistryLogData {
                    reason_code: Some("tuf_target_not_found".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn mock_sigstore_verifier_accepts_valid_bundle() {
        run_registry_test(
            "mock_sigstore_verifier_accepts_valid_bundle",
            "verify",
            "sigstore-adapter",
            1,
            || async {
                let verifier = MockSigstoreVerifier::new();
                let result = SigstoreVerificationResult {
                    verified: true,
                    identity: Some("github-actions".to_string()),
                    issuer: Some("https://token.actions.githubusercontent.com".to_string()),
                    rekor_log_index: Some(54321),
                };
                verifier.add_valid_bundle("sha256:artifact".to_string(), result);

                let bundle = SigstoreBundle {
                    signature: "base64sig".to_string(),
                    certificate: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
                        .to_string(),
                    rekor_entry: None,
                    identity: "github-actions".to_string(),
                    issuer: "https://token.actions.githubusercontent.com".to_string(),
                };

                let result = verifier
                    .verify_bundle(
                        &bundle,
                        "sha256:artifact",
                        &["github-actions".to_string()],
                        &["https://token.actions.githubusercontent.com".to_string()],
                    )
                    .await
                    .expect("bundle valid");
                assert!(result.verified);
                assert_eq!(result.identity, Some("github-actions".to_string()));
                assert_eq!(result.rekor_log_index, Some(54321));

                RegistryLogData {
                    reason_code: Some("sigstore_bundle_verified".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn mock_sigstore_verifier_rejects_untrusted_identity() {
        run_registry_test(
            "mock_sigstore_verifier_rejects_untrusted_identity",
            "verify",
            "sigstore-adapter",
            1,
            || async {
                let verifier = MockSigstoreVerifier::new();
                let result = SigstoreVerificationResult {
                    verified: true,
                    identity: Some("untrusted-ci".to_string()),
                    issuer: Some("https://example.com".to_string()),
                    rekor_log_index: Some(54321),
                };
                verifier.add_valid_bundle("sha256:artifact".to_string(), result);

                let bundle = SigstoreBundle {
                    signature: "base64sig".to_string(),
                    certificate: "cert".to_string(),
                    rekor_entry: None,
                    identity: "untrusted-ci".to_string(),
                    issuer: "https://example.com".to_string(),
                };

                let err = verifier
                    .verify_bundle(
                        &bundle,
                        "sha256:artifact",
                        &["github-actions".to_string()],
                        &[],
                    )
                    .await
                    .expect_err("identity mismatch");
                assert!(matches!(
                    err,
                    SupplyChainVerificationError::SigstoreIdentityMismatch { .. }
                ));

                RegistryLogData {
                    reason_code: Some("sigstore_identity_mismatch".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn mock_sigstore_verifier_rejects_untrusted_issuer() {
        run_registry_test(
            "mock_sigstore_verifier_rejects_untrusted_issuer",
            "verify",
            "sigstore-adapter",
            1,
            || async {
                let verifier = MockSigstoreVerifier::new();
                let result = SigstoreVerificationResult {
                    verified: true,
                    identity: Some("github-actions".to_string()),
                    issuer: Some("https://untrusted-issuer.com".to_string()),
                    rekor_log_index: Some(54321),
                };
                verifier.add_valid_bundle("sha256:artifact".to_string(), result);

                let bundle = SigstoreBundle {
                    signature: "base64sig".to_string(),
                    certificate: "cert".to_string(),
                    rekor_entry: None,
                    identity: "github-actions".to_string(),
                    issuer: "https://untrusted-issuer.com".to_string(),
                };

                let err = verifier
                    .verify_bundle(
                        &bundle,
                        "sha256:artifact",
                        &[],
                        &["https://token.actions.githubusercontent.com".to_string()],
                    )
                    .await
                    .expect_err("issuer untrusted");
                assert!(matches!(
                    err,
                    SupplyChainVerificationError::SigstoreIssuerUntrusted { .. }
                ));

                RegistryLogData {
                    reason_code: Some("sigstore_issuer_untrusted".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn mock_sigstore_verifier_rejects_invalid_signature() {
        run_registry_test(
            "mock_sigstore_verifier_rejects_invalid_signature",
            "verify",
            "sigstore-adapter",
            1,
            || async {
                let verifier = MockSigstoreVerifier::new();
                // No valid bundles added

                let bundle = SigstoreBundle {
                    signature: "bad_sig".to_string(),
                    certificate: "cert".to_string(),
                    rekor_entry: None,
                    identity: "github-actions".to_string(),
                    issuer: "https://token.actions.githubusercontent.com".to_string(),
                };

                let err = verifier
                    .verify_bundle(&bundle, "sha256:unknown_artifact", &[], &[])
                    .await
                    .expect_err("signature invalid");
                assert!(matches!(
                    err,
                    SupplyChainVerificationError::SigstoreSignatureInvalid
                ));

                RegistryLogData {
                    reason_code: Some("sigstore_signature_invalid".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn noop_verifiers_always_succeed() {
        run_registry_test(
            "noop_verifiers_always_succeed",
            "verify",
            "noop-adapters",
            3,
            || async {
                // Test NoOp Transparency verifier
                let transparency = NoOpTransparencyVerifier;
                let result = transparency
                    .verify_entry("any_hash", None)
                    .await
                    .expect("noop always succeeds");
                assert!(result.verified);

                // Test NoOp TUF verifier
                let tuf = NoOpTufVerifier;
                let pinned = TufRootMetadata {
                    version: 1,
                    root_hash: String::new(),
                    expires: 0,
                    key_ids: Vec::new(),
                    threshold: 1,
                };
                let result = tuf
                    .verify_target(&pinned, "any/target")
                    .await
                    .expect("noop always succeeds");
                assert!(result.verified);
                let root = tuf.fetch_root().await.expect("noop returns default root");
                assert_eq!(root.version, 1);

                // Test NoOp Sigstore verifier
                let sigstore = NoOpSigstoreVerifier;
                let bundle = SigstoreBundle {
                    signature: String::new(),
                    certificate: String::new(),
                    rekor_entry: None,
                    identity: String::new(),
                    issuer: String::new(),
                };
                let result = sigstore
                    .verify_bundle(&bundle, "any_hash", &[], &[])
                    .await
                    .expect("noop always succeeds");
                assert!(result.verified);

                RegistryLogData {
                    reason_code: Some("noop_verifiers_succeed".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn supply_chain_verification_config_defaults() {
        run_registry_test(
            "supply_chain_verification_config_defaults",
            "config",
            "supply-chain",
            1,
            || async {
                let config = SupplyChainVerificationConfig::default();
                assert!(config.tuf_pinned_root.is_none());
                assert!(config.trusted_sigstore_identities.is_empty());
                assert!(config.trusted_sigstore_issuers.is_empty());
                assert!(!config.require_transparency);
                assert!(!config.require_tuf);
                assert!(!config.require_sigstore);

                RegistryLogData {
                    reason_code: Some("config_defaults_correct".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }
}
