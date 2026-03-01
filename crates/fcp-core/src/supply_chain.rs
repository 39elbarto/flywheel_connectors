//! Supply-chain attestation and SBOM objects (NORMATIVE).
//!
//! This module defines canonical supply-chain object shapes used by FCP2:
//! - `SupplyChainAttestation`: provenance statement bound to an artifact digest
//! - `SoftwareBillOfMaterials`: component and dependency inventory
//!
//! Both objects support:
//! - Structural validation with fail-closed semantics
//! - Deterministic canonical encodings (JSON + CBOR)
//! - Deterministic content hashing
//! - Deterministic signing bytes with schema-domain separation

use std::collections::HashSet;

use chrono::{DateTime, Utc};
use fcp_crypto::canonicalize::{canonical_signing_bytes, to_deterministic_cbor};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};

/// Format identifier for supply-chain attestations.
pub const SUPPLY_CHAIN_ATTESTATION_FORMAT: &str = "fcp-supply-chain-attestation";
/// Schema version for supply-chain attestations.
pub const SUPPLY_CHAIN_ATTESTATION_SCHEMA_VERSION: &str = "1.0";
/// Schema ID for supply-chain attestation signing bytes.
pub const SUPPLY_CHAIN_ATTESTATION_SCHEMA_ID: &str = "fcp://schemas/supply-chain-attestation/v1";

/// Format identifier for SBOM objects.
pub const SBOM_FORMAT: &str = "fcp-sbom";
/// Schema version for SBOM objects.
pub const SBOM_SCHEMA_VERSION: &str = "1.0";
/// Schema ID for SBOM signing bytes.
pub const SBOM_SCHEMA_ID: &str = "fcp://schemas/sbom/v1";

/// Signed fields for `SupplyChainAttestation` (strict ordering).
pub const SUPPLY_CHAIN_ATTESTATION_SIGNED_FIELDS: &[&str] = &[
    "format",
    "schema_version",
    "subject_digest",
    "predicate_type",
    "builder_id",
    "build_type",
    "materials",
    "metadata",
    "slsa_level",
    "provenance_hash",
    "trust_root",
    "builder_allowlist",
];

/// Signed fields for `SoftwareBillOfMaterials` (strict ordering).
pub const SBOM_SIGNED_FIELDS: &[&str] = &[
    "format",
    "schema_version",
    "bom_format",
    "bom_version",
    "tool_chain",
    "components",
    "dependencies",
    "trust_root",
];

/// Supported canonical encodings for content hashing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalEncoding {
    /// Deterministic CBOR.
    Cbor,
    /// Canonical JSON (sorted object keys, compact serialization).
    Json,
}

/// Supported digest algorithms for canonical object hashing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum HashAlgorithm {
    /// BLAKE3-256 digest (`blake3-256:<hex>`).
    #[default]
    Blake3_256,
    /// SHA-256 digest (`sha256:<hex>`).
    Sha256,
}

impl HashAlgorithm {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Blake3_256 => "blake3-256",
            Self::Sha256 => "sha256",
        }
    }
}

/// Supply-chain validation and canonicalization errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SupplyChainError {
    #[error("invalid attestation: {reason}")]
    InvalidAttestation { reason: String },
    #[error("invalid sbom: {reason}")]
    InvalidSbom { reason: String },
    #[error("invalid signature: {reason}")]
    InvalidSignature { reason: String },
    #[error("invalid trust root: {reason}")]
    InvalidTrustRoot { reason: String },
    #[error("canonicalization failed: {reason}")]
    CanonicalizationFailed { reason: String },
}

/// Supported predicate families for supply-chain attestations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttestationPredicateType {
    /// SLSA provenance v1 predicate.
    #[serde(rename = "https://slsa.dev/provenance/v1")]
    SlsaProvenanceV1,
    /// in-toto statement v1 predicate.
    #[serde(rename = "https://in-toto.io/Statement/v1")]
    InTotoStatementV1,
}

/// Build material reference inside a supply-chain attestation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationMaterial {
    /// Material URI (for example: git URI, archive URI).
    pub uri: String,
    /// Material digest (`blake3-256:<hex>`).
    pub digest: String,
}

impl AttestationMaterial {
    fn validate(&self) -> Result<(), SupplyChainError> {
        if self.uri.trim().is_empty() {
            return Err(SupplyChainError::InvalidAttestation {
                reason: "materials.uri cannot be empty".to_string(),
            });
        }
        validate_digest_with_algo(&self.digest, "materials.digest", HashAlgorithm::Blake3_256)
            .map_err(|reason| SupplyChainError::InvalidAttestation { reason })?;
        Ok(())
    }
}

/// Build metadata for a supply-chain attestation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationMetadata {
    /// Timestamp when the build started.
    pub build_started_at: DateTime<Utc>,
    /// Timestamp when the build completed.
    pub build_finished_at: DateTime<Utc>,
    /// Optional invocation identifier from CI/build system.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invocation_id: Option<String>,
}

impl AttestationMetadata {
    fn validate(&self) -> Result<(), SupplyChainError> {
        if self.build_finished_at < self.build_started_at {
            return Err(SupplyChainError::InvalidAttestation {
                reason: "metadata.build_finished_at must be >= metadata.build_started_at"
                    .to_string(),
            });
        }
        if self
            .invocation_id
            .as_ref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(SupplyChainError::InvalidAttestation {
                reason: "metadata.invocation_id cannot be empty when present".to_string(),
            });
        }
        Ok(())
    }
}

/// Trust-root binding for signed supply-chain objects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustRootBinding {
    /// Trust root type (`sigstore`, `tuf`, `manual`).
    pub root_type: String,
    /// Stable trust root identifier.
    pub root_id: String,
}

impl TrustRootBinding {
    fn validate(&self) -> Result<(), SupplyChainError> {
        if self.root_id.trim().is_empty() {
            return Err(SupplyChainError::InvalidTrustRoot {
                reason: "root_id cannot be empty".to_string(),
            });
        }
        let root_type = self.root_type.as_str();
        if !matches!(root_type, "sigstore" | "tuf" | "manual") {
            return Err(SupplyChainError::InvalidTrustRoot {
                reason: format!(
                    "root_type must be one of [sigstore, tuf, manual], got `{root_type}`"
                ),
            });
        }
        Ok(())
    }
}

/// Signature envelope for supply-chain objects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupplyChainSignature {
    /// Signature algorithm (`ed25519`).
    pub algorithm: String,
    /// Key identifier used for signing.
    pub key_id: String,
    /// Signature bytes (base64/hex encoded external representation).
    pub signature: String,
    /// Exact set of signed fields (stable order).
    pub signed_fields: Vec<String>,
}

impl SupplyChainSignature {
    /// Create a new `ed25519` signature envelope.
    #[must_use]
    pub fn new(
        key_id: impl Into<String>,
        signature: impl Into<String>,
        signed_fields: Vec<String>,
    ) -> Self {
        Self {
            algorithm: "ed25519".to_string(),
            key_id: key_id.into(),
            signature: signature.into(),
            signed_fields,
        }
    }

    fn validate(&self, expected_fields: &[&str]) -> Result<(), SupplyChainError> {
        if self.algorithm != "ed25519" {
            return Err(SupplyChainError::InvalidSignature {
                reason: format!("algorithm must be `ed25519`, got `{}`", self.algorithm),
            });
        }
        if self.key_id.trim().is_empty() {
            return Err(SupplyChainError::InvalidSignature {
                reason: "key_id cannot be empty".to_string(),
            });
        }
        if self.signature.trim().is_empty() {
            return Err(SupplyChainError::InvalidSignature {
                reason: "signature cannot be empty".to_string(),
            });
        }
        let expected: Vec<String> = expected_fields
            .iter()
            .map(|field| (*field).to_string())
            .collect();
        if self.signed_fields != expected {
            return Err(SupplyChainError::InvalidSignature {
                reason: format!(
                    "signed_fields must exactly match [{}]",
                    expected_fields.join(", ")
                ),
            });
        }
        Ok(())
    }
}

/// Canonical supply-chain attestation object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupplyChainAttestation {
    /// Format identifier (`fcp-supply-chain-attestation`).
    pub format: String,
    /// Schema version (`1.0`).
    pub schema_version: String,
    /// Subject artifact digest (`blake3-256:<hex>`).
    pub subject_digest: String,
    /// Predicate type.
    pub predicate_type: AttestationPredicateType,
    /// Builder identity.
    pub builder_id: String,
    /// Build type descriptor.
    pub build_type: String,
    /// Build materials.
    pub materials: Vec<AttestationMaterial>,
    /// Build metadata.
    pub metadata: AttestationMetadata,
    /// SLSA level for this attestation (0..=4).
    pub slsa_level: u8,
    /// Digest of canonical provenance payload (`blake3-256:<hex>`).
    pub provenance_hash: String,
    /// Trust root used to validate signature.
    pub trust_root: TrustRootBinding,
    /// Optional builder allowlist hook used by policy checks.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub builder_allowlist: Vec<String>,
    /// Signature envelope.
    pub signature: SupplyChainSignature,
}

impl SupplyChainAttestation {
    /// Validate attestation structure and policy hooks.
    ///
    /// # Errors
    ///
    /// Returns [`SupplyChainError`] when validation fails.
    pub fn validate(&self) -> Result<(), SupplyChainError> {
        if self.format != SUPPLY_CHAIN_ATTESTATION_FORMAT {
            return Err(SupplyChainError::InvalidAttestation {
                reason: format!(
                    "format must be `{SUPPLY_CHAIN_ATTESTATION_FORMAT}`, got `{}`",
                    self.format
                ),
            });
        }
        if self.schema_version != SUPPLY_CHAIN_ATTESTATION_SCHEMA_VERSION {
            return Err(SupplyChainError::InvalidAttestation {
                reason: format!(
                    "schema_version must be `{SUPPLY_CHAIN_ATTESTATION_SCHEMA_VERSION}`, got `{}`",
                    self.schema_version
                ),
            });
        }
        if self.builder_id.trim().is_empty() {
            return Err(SupplyChainError::InvalidAttestation {
                reason: "builder_id cannot be empty".to_string(),
            });
        }
        if self.build_type.trim().is_empty() {
            return Err(SupplyChainError::InvalidAttestation {
                reason: "build_type cannot be empty".to_string(),
            });
        }
        validate_digest_with_algo(
            &self.subject_digest,
            "subject_digest",
            HashAlgorithm::Blake3_256,
        )
        .map_err(|reason| SupplyChainError::InvalidAttestation { reason })?;
        validate_digest_with_algo(
            &self.provenance_hash,
            "provenance_hash",
            HashAlgorithm::Blake3_256,
        )
        .map_err(|reason| SupplyChainError::InvalidAttestation { reason })?;
        if self.materials.is_empty() {
            return Err(SupplyChainError::InvalidAttestation {
                reason: "materials cannot be empty".to_string(),
            });
        }
        for material in &self.materials {
            material.validate()?;
        }
        self.metadata.validate()?;
        if self.slsa_level > 4 {
            return Err(SupplyChainError::InvalidAttestation {
                reason: "slsa_level must be in range 0..=4".to_string(),
            });
        }
        if self
            .builder_allowlist
            .iter()
            .any(|entry| entry.trim().is_empty())
        {
            return Err(SupplyChainError::InvalidAttestation {
                reason: "builder_allowlist cannot contain empty entries".to_string(),
            });
        }
        if !self.builder_allowlist.is_empty() && !self.builder_allowlist.contains(&self.builder_id)
        {
            return Err(SupplyChainError::InvalidAttestation {
                reason: format!(
                    "builder_id `{}` is not present in builder_allowlist",
                    self.builder_id
                ),
            });
        }
        self.trust_root.validate()?;
        self.signature
            .validate(SUPPLY_CHAIN_ATTESTATION_SIGNED_FIELDS)?;
        Ok(())
    }

    /// Deterministic signing bytes (`SIGNING_DOMAIN || schema_hash || cbor(unsigned_view)`).
    ///
    /// # Errors
    ///
    /// Returns [`SupplyChainError::CanonicalizationFailed`] on serialization failures.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, SupplyChainError> {
        let signable = SupplyChainAttestationSignable {
            format: self.format.clone(),
            schema_version: self.schema_version.clone(),
            subject_digest: self.subject_digest.clone(),
            predicate_type: self.predicate_type,
            builder_id: self.builder_id.clone(),
            build_type: self.build_type.clone(),
            materials: self.materials.clone(),
            metadata: self.metadata.clone(),
            slsa_level: self.slsa_level,
            provenance_hash: self.provenance_hash.clone(),
            trust_root: self.trust_root.clone(),
            builder_allowlist: self.builder_allowlist.clone(),
        };
        let cbor = to_deterministic_cbor(&signable).map_err(|err| {
            SupplyChainError::CanonicalizationFailed {
                reason: err.to_string(),
            }
        })?;
        Ok(canonical_signing_bytes(
            SUPPLY_CHAIN_ATTESTATION_SCHEMA_ID,
            &cbor,
        ))
    }

    /// Canonical bytes for this object in the selected encoding.
    ///
    /// # Errors
    ///
    /// Returns [`SupplyChainError::CanonicalizationFailed`] on serialization failures.
    pub fn canonical_bytes(
        &self,
        encoding: CanonicalEncoding,
    ) -> Result<Vec<u8>, SupplyChainError> {
        match encoding {
            CanonicalEncoding::Cbor => to_deterministic_cbor(self).map_err(|err| {
                SupplyChainError::CanonicalizationFailed {
                    reason: err.to_string(),
                }
            }),
            CanonicalEncoding::Json => canonical_json_bytes(self),
        }
    }

    /// Compute canonical content hash in the requested encoding/algorithm.
    ///
    /// # Errors
    ///
    /// Returns [`SupplyChainError::CanonicalizationFailed`] on serialization failures.
    pub fn content_hash(
        &self,
        encoding: CanonicalEncoding,
        algorithm: HashAlgorithm,
    ) -> Result<String, SupplyChainError> {
        let bytes = self.canonical_bytes(encoding)?;
        Ok(hash_bytes(&bytes, algorithm))
    }
}

#[derive(Debug, Clone, Serialize)]
struct SupplyChainAttestationSignable {
    format: String,
    schema_version: String,
    subject_digest: String,
    predicate_type: AttestationPredicateType,
    builder_id: String,
    build_type: String,
    materials: Vec<AttestationMaterial>,
    metadata: AttestationMetadata,
    slsa_level: u8,
    provenance_hash: String,
    trust_root: TrustRootBinding,
    builder_allowlist: Vec<String>,
}

/// Supported SBOM formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SbomFormat {
    /// CycloneDX-compatible representation.
    Cyclonedx,
    /// SPDX-compatible representation.
    Spdx,
}

/// A software component entry in SBOM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SbomComponent {
    /// Stable component identifier.
    pub component_id: String,
    /// Human-readable component name.
    pub name: String,
    /// Version string.
    pub version: String,
    /// Declared component digests (`blake3-256:<hex>` or `sha256:<hex>`).
    pub hashes: Vec<String>,
    /// Declared licenses for this component.
    pub licenses: Vec<String>,
}

impl SbomComponent {
    fn validate(&self) -> Result<(), SupplyChainError> {
        if self.component_id.trim().is_empty() {
            return Err(SupplyChainError::InvalidSbom {
                reason: "components.component_id cannot be empty".to_string(),
            });
        }
        if self.name.trim().is_empty() {
            return Err(SupplyChainError::InvalidSbom {
                reason: "components.name cannot be empty".to_string(),
            });
        }
        if self.version.trim().is_empty() {
            return Err(SupplyChainError::InvalidSbom {
                reason: "components.version cannot be empty".to_string(),
            });
        }
        if self.hashes.is_empty() {
            return Err(SupplyChainError::InvalidSbom {
                reason: "components.hashes cannot be empty".to_string(),
            });
        }
        if self.licenses.is_empty() {
            return Err(SupplyChainError::InvalidSbom {
                reason: "components.licenses cannot be empty".to_string(),
            });
        }
        for hash in &self.hashes {
            if !digest_is_supported(hash) {
                return Err(SupplyChainError::InvalidSbom {
                    reason: format!(
                        "components.hashes value `{hash}` must use blake3-256 or sha256 with 64 lowercase hex chars"
                    ),
                });
            }
        }
        if self
            .licenses
            .iter()
            .any(|license| license.trim().is_empty())
        {
            return Err(SupplyChainError::InvalidSbom {
                reason: "components.licenses cannot contain empty values".to_string(),
            });
        }
        Ok(())
    }
}

/// Dependency graph edge set for a single component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SbomDependency {
    /// Component that owns this dependency edge set.
    pub component_id: String,
    /// Referenced component IDs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<String>,
}

/// Canonical software bill of materials object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftwareBillOfMaterials {
    /// Format identifier (`fcp-sbom`).
    pub format: String,
    /// Schema version (`1.0`).
    pub schema_version: String,
    /// SBOM family.
    pub bom_format: SbomFormat,
    /// SBOM document version.
    pub bom_version: String,
    /// Toolchain components used to produce this SBOM.
    pub tool_chain: Vec<String>,
    /// Components declared in the bill.
    pub components: Vec<SbomComponent>,
    /// Component dependency graph.
    pub dependencies: Vec<SbomDependency>,
    /// Trust root used to validate signature.
    pub trust_root: TrustRootBinding,
    /// Signature envelope.
    pub signature: SupplyChainSignature,
}

impl SoftwareBillOfMaterials {
    /// Validate SBOM structure and dependency graph.
    ///
    /// # Errors
    ///
    /// Returns [`SupplyChainError`] when validation fails.
    pub fn validate(&self) -> Result<(), SupplyChainError> {
        if self.format != SBOM_FORMAT {
            return Err(SupplyChainError::InvalidSbom {
                reason: format!("format must be `{SBOM_FORMAT}`, got `{}`", self.format),
            });
        }
        if self.schema_version != SBOM_SCHEMA_VERSION {
            return Err(SupplyChainError::InvalidSbom {
                reason: format!(
                    "schema_version must be `{SBOM_SCHEMA_VERSION}`, got `{}`",
                    self.schema_version
                ),
            });
        }
        if self.bom_version.trim().is_empty() {
            return Err(SupplyChainError::InvalidSbom {
                reason: "bom_version cannot be empty".to_string(),
            });
        }
        if self.tool_chain.is_empty() {
            return Err(SupplyChainError::InvalidSbom {
                reason: "tool_chain cannot be empty".to_string(),
            });
        }
        if self.tool_chain.iter().any(|entry| entry.trim().is_empty()) {
            return Err(SupplyChainError::InvalidSbom {
                reason: "tool_chain cannot contain empty values".to_string(),
            });
        }
        if self.components.is_empty() {
            return Err(SupplyChainError::InvalidSbom {
                reason: "components cannot be empty".to_string(),
            });
        }

        let mut component_ids = HashSet::with_capacity(self.components.len());
        for component in &self.components {
            component.validate()?;
            if !component_ids.insert(component.component_id.clone()) {
                return Err(SupplyChainError::InvalidSbom {
                    reason: format!(
                        "components contains duplicate component_id `{}`",
                        component.component_id
                    ),
                });
            }
        }

        let mut seen_dependency_nodes = HashSet::with_capacity(self.dependencies.len());
        for dependency in &self.dependencies {
            if dependency.component_id.trim().is_empty() {
                return Err(SupplyChainError::InvalidSbom {
                    reason: "dependencies.component_id cannot be empty".to_string(),
                });
            }
            if !component_ids.contains(&dependency.component_id) {
                return Err(SupplyChainError::InvalidSbom {
                    reason: format!(
                        "dependencies.component_id `{}` not found in components",
                        dependency.component_id
                    ),
                });
            }
            if !seen_dependency_nodes.insert(dependency.component_id.clone()) {
                return Err(SupplyChainError::InvalidSbom {
                    reason: format!(
                        "dependencies contains duplicate component_id `{}`",
                        dependency.component_id
                    ),
                });
            }
            for target in &dependency.depends_on {
                if target.trim().is_empty() {
                    return Err(SupplyChainError::InvalidSbom {
                        reason: format!(
                            "dependencies for `{}` contain empty target",
                            dependency.component_id
                        ),
                    });
                }
                if !component_ids.contains(target) {
                    return Err(SupplyChainError::InvalidSbom {
                        reason: format!(
                            "dependency target `{target}` referenced by `{}` not found in components",
                            dependency.component_id
                        ),
                    });
                }
            }
        }

        self.trust_root.validate()?;
        self.signature.validate(SBOM_SIGNED_FIELDS)?;
        Ok(())
    }

    /// Deterministic signing bytes (`SIGNING_DOMAIN || schema_hash || cbor(unsigned_view)`).
    ///
    /// # Errors
    ///
    /// Returns [`SupplyChainError::CanonicalizationFailed`] on serialization failures.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, SupplyChainError> {
        let signable = SoftwareBillOfMaterialsSignable {
            format: self.format.clone(),
            schema_version: self.schema_version.clone(),
            bom_format: self.bom_format,
            bom_version: self.bom_version.clone(),
            tool_chain: self.tool_chain.clone(),
            components: self.components.clone(),
            dependencies: self.dependencies.clone(),
            trust_root: self.trust_root.clone(),
        };
        let cbor = to_deterministic_cbor(&signable).map_err(|err| {
            SupplyChainError::CanonicalizationFailed {
                reason: err.to_string(),
            }
        })?;
        Ok(canonical_signing_bytes(SBOM_SCHEMA_ID, &cbor))
    }

    /// Canonical bytes for this object in the selected encoding.
    ///
    /// # Errors
    ///
    /// Returns [`SupplyChainError::CanonicalizationFailed`] on serialization failures.
    pub fn canonical_bytes(
        &self,
        encoding: CanonicalEncoding,
    ) -> Result<Vec<u8>, SupplyChainError> {
        match encoding {
            CanonicalEncoding::Cbor => to_deterministic_cbor(self).map_err(|err| {
                SupplyChainError::CanonicalizationFailed {
                    reason: err.to_string(),
                }
            }),
            CanonicalEncoding::Json => canonical_json_bytes(self),
        }
    }

    /// Compute canonical content hash in the requested encoding/algorithm.
    ///
    /// # Errors
    ///
    /// Returns [`SupplyChainError::CanonicalizationFailed`] on serialization failures.
    pub fn content_hash(
        &self,
        encoding: CanonicalEncoding,
        algorithm: HashAlgorithm,
    ) -> Result<String, SupplyChainError> {
        let bytes = self.canonical_bytes(encoding)?;
        Ok(hash_bytes(&bytes, algorithm))
    }
}

#[derive(Debug, Clone, Serialize)]
struct SoftwareBillOfMaterialsSignable {
    format: String,
    schema_version: String,
    bom_format: SbomFormat,
    bom_version: String,
    tool_chain: Vec<String>,
    components: Vec<SbomComponent>,
    dependencies: Vec<SbomDependency>,
    trust_root: TrustRootBinding,
}

fn validate_digest_with_algo(
    digest: &str,
    field_name: &str,
    algorithm: HashAlgorithm,
) -> Result<(), String> {
    let Some((prefix, hex)) = digest.split_once(':') else {
        return Err(format!(
            "{field_name} must use `<algorithm>:<64-lowercase-hex>` format"
        ));
    };
    if prefix != algorithm.as_str() || !is_lower_hex_64(hex) {
        return Err(format!(
            "{field_name} must use `{}` with 64 lowercase hex chars",
            algorithm.as_str()
        ));
    }
    Ok(())
}

fn digest_is_supported(digest: &str) -> bool {
    digest.split_once(':').is_some_and(|(prefix, hex)| {
        matches!(prefix, "blake3-256" | "sha256") && is_lower_hex_64(hex)
    })
}

fn is_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, SupplyChainError> {
    let as_value =
        serde_json::to_value(value).map_err(|err| SupplyChainError::CanonicalizationFailed {
            reason: err.to_string(),
        })?;
    let canonical = canonicalize_json_value(as_value);
    serde_json::to_vec(&canonical).map_err(|err| SupplyChainError::CanonicalizationFailed {
        reason: err.to_string(),
    })
}

fn canonicalize_json_value(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> = map.into_iter().collect();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            let ordered: Map<String, Value> = entries
                .into_iter()
                .map(|(key, item)| (key, canonicalize_json_value(item)))
                .collect();
            Value::Object(ordered)
        }
        Value::Array(items) => {
            Value::Array(items.into_iter().map(canonicalize_json_value).collect())
        }
        other => other,
    }
}

fn hash_bytes(bytes: &[u8], algorithm: HashAlgorithm) -> String {
    match algorithm {
        HashAlgorithm::Blake3_256 => {
            let hash = blake3::hash(bytes);
            format!("{}:{}", algorithm.as_str(), hash.to_hex())
        }
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(bytes);
            format!("{}:{}", algorithm.as_str(), hex::encode(hasher.finalize()))
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    fn attestation_signature() -> SupplyChainSignature {
        SupplyChainSignature::new(
            "owner-key-1",
            "sig-data",
            SUPPLY_CHAIN_ATTESTATION_SIGNED_FIELDS
                .iter()
                .map(|field| (*field).to_string())
                .collect(),
        )
    }

    fn sbom_signature() -> SupplyChainSignature {
        SupplyChainSignature::new(
            "owner-key-1",
            "sig-data",
            SBOM_SIGNED_FIELDS
                .iter()
                .map(|field| (*field).to_string())
                .collect(),
        )
    }

    fn sample_trust_root() -> TrustRootBinding {
        TrustRootBinding {
            root_type: "sigstore".to_string(),
            root_id: "sigstore-public-good".to_string(),
        }
    }

    fn sample_attestation() -> SupplyChainAttestation {
        SupplyChainAttestation {
            format: SUPPLY_CHAIN_ATTESTATION_FORMAT.to_string(),
            schema_version: SUPPLY_CHAIN_ATTESTATION_SCHEMA_VERSION.to_string(),
            subject_digest: format!("blake3-256:{}", "a".repeat(64)),
            predicate_type: AttestationPredicateType::SlsaProvenanceV1,
            builder_id: "builder://github/actions".to_string(),
            build_type: "https://slsa.dev/container-based-build/v1".to_string(),
            materials: vec![
                AttestationMaterial {
                    uri: "git+https://github.com/flywheel/connectors@refs/heads/main".to_string(),
                    digest: format!("blake3-256:{}", "b".repeat(64)),
                },
                AttestationMaterial {
                    uri: "https://github.com/flywheel/connectors/archive/v1.2.3.tar.gz".to_string(),
                    digest: format!("blake3-256:{}", "c".repeat(64)),
                },
            ],
            metadata: AttestationMetadata {
                build_started_at: Utc.with_ymd_and_hms(2026, 2, 1, 12, 0, 0).single().unwrap(),
                build_finished_at: Utc.with_ymd_and_hms(2026, 2, 1, 12, 5, 0).single().unwrap(),
                invocation_id: Some("gh-run-42".to_string()),
            },
            slsa_level: 3,
            provenance_hash: format!("blake3-256:{}", "d".repeat(64)),
            trust_root: sample_trust_root(),
            builder_allowlist: vec!["builder://github/actions".to_string()],
            signature: attestation_signature(),
        }
    }

    fn sample_sbom() -> SoftwareBillOfMaterials {
        SoftwareBillOfMaterials {
            format: SBOM_FORMAT.to_string(),
            schema_version: SBOM_SCHEMA_VERSION.to_string(),
            bom_format: SbomFormat::Cyclonedx,
            bom_version: "1.6".to_string(),
            tool_chain: vec![
                "cargo 1.86.0-nightly".to_string(),
                "fcp-cli package".to_string(),
            ],
            components: vec![
                SbomComponent {
                    component_id: "connector-root".to_string(),
                    name: "fcp-connector-openai".to_string(),
                    version: "1.2.3".to_string(),
                    hashes: vec![
                        format!("blake3-256:{}", "e".repeat(64)),
                        format!("sha256:{}", "f".repeat(64)),
                    ],
                    licenses: vec!["Apache-2.0".to_string()],
                },
                SbomComponent {
                    component_id: "dep-serde".to_string(),
                    name: "serde".to_string(),
                    version: "1.0.210".to_string(),
                    hashes: vec![format!("sha256:{}", "1".repeat(64))],
                    licenses: vec!["MIT".to_string(), "Apache-2.0".to_string()],
                },
            ],
            dependencies: vec![
                SbomDependency {
                    component_id: "connector-root".to_string(),
                    depends_on: vec!["dep-serde".to_string()],
                },
                SbomDependency {
                    component_id: "dep-serde".to_string(),
                    depends_on: vec![],
                },
            ],
            trust_root: sample_trust_root(),
            signature: sbom_signature(),
        }
    }

    #[test]
    fn valid_attestation_passes_validation() {
        let attestation = sample_attestation();
        assert!(attestation.validate().is_ok());
    }

    #[test]
    fn attestation_rejects_builder_not_in_allowlist() {
        let mut attestation = sample_attestation();
        attestation.builder_allowlist = vec!["builder://other-ci".to_string()];
        let result = attestation.validate();
        assert!(
            matches!(result, Err(SupplyChainError::InvalidAttestation { .. })),
            "builder allowlist mismatch should be rejected"
        );
    }

    #[test]
    fn attestation_signing_bytes_are_deterministic() {
        let attestation = sample_attestation();
        let bytes_one = attestation.signing_bytes().unwrap();
        let bytes_two = attestation.signing_bytes().unwrap();
        assert_eq!(bytes_one, bytes_two);
    }

    #[test]
    fn canonicalization_is_stable_for_permuted_field_order() {
        let value_one: Value = serde_json::from_str(
            r#"{
                "b": {"z": 1, "a": 2},
                "a": [ {"y": 3, "x": 4} ],
                "c": "ok"
            }"#,
        )
        .unwrap();
        let value_two: Value = serde_json::from_str(
            r#"{
                "c": "ok",
                "a": [ {"x": 4, "y": 3} ],
                "b": {"a": 2, "z": 1}
            }"#,
        )
        .unwrap();

        let json_one = canonical_json_bytes(&value_one).unwrap();
        let json_two = canonical_json_bytes(&value_two).unwrap();
        assert_eq!(json_one, json_two, "canonical json must ignore key order");

        let cbor_one = to_deterministic_cbor(&value_one).unwrap();
        let cbor_two = to_deterministic_cbor(&value_two).unwrap();
        assert_eq!(cbor_one, cbor_two, "canonical cbor must ignore key order");
    }

    #[test]
    fn valid_sbom_passes_validation() {
        let sbom = sample_sbom();
        assert!(sbom.validate().is_ok());
    }

    #[test]
    fn sbom_rejects_unknown_dependency_target() {
        let mut sbom = sample_sbom();
        sbom.dependencies[0].depends_on = vec!["does-not-exist".to_string()];
        let result = sbom.validate();
        assert!(
            matches!(result, Err(SupplyChainError::InvalidSbom { .. })),
            "unknown dependency target must be rejected"
        );
    }

    #[test]
    fn sbom_content_hash_deterministic_across_algorithms() {
        let sbom = sample_sbom();

        let blake_a = sbom
            .content_hash(CanonicalEncoding::Json, HashAlgorithm::Blake3_256)
            .unwrap();
        let blake_b = sbom
            .content_hash(CanonicalEncoding::Json, HashAlgorithm::Blake3_256)
            .unwrap();
        assert_eq!(blake_a, blake_b);
        assert!(blake_a.starts_with("blake3-256:"));

        let sha_a = sbom
            .content_hash(CanonicalEncoding::Cbor, HashAlgorithm::Sha256)
            .unwrap();
        let sha_b = sbom
            .content_hash(CanonicalEncoding::Cbor, HashAlgorithm::Sha256)
            .unwrap();
        assert_eq!(sha_a, sha_b);
        assert!(sha_a.starts_with("sha256:"));
    }
}
