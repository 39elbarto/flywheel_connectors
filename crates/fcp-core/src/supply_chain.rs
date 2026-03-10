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
use std::fmt;

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

// ─────────────────────────────────────────────────────────────────────────────
// Supply Chain Verification Policy + Pipeline
// ─────────────────────────────────────────────────────────────────────────────

/// Stable reason codes for verification pipeline decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerificationReasonCode {
    /// Attestation and SBOM verified successfully.
    Verified,
    /// Attestation is missing and policy requires it.
    AttestationMissing,
    /// Attestation failed structural validation.
    AttestationInvalid,
    /// Attestation SLSA level is below the required minimum.
    SlsaLevelInsufficient,
    /// Builder identity is not in the trusted builders list.
    BuilderUntrusted,
    /// Attestation subject digest does not match the artifact digest.
    SubjectDigestMismatch,
    /// Attestation signature envelope is structurally invalid.
    SignatureInvalid,
    /// SBOM is missing and policy requires it.
    SbomMissing,
    /// SBOM failed structural validation.
    SbomInvalid,
    /// Unsigned artifact allowed by explicit policy override.
    AllowedUnsigned,
}

impl fmt::Display for VerificationReasonCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = serde_json::to_value(self)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_else(|| format!("{self:?}"));
        f.write_str(&code)
    }
}

/// Verification pipeline decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationDecision {
    /// Artifact passed all verification checks.
    Allow,
    /// Artifact failed one or more verification checks.
    Deny,
}

/// A single step in the verification evidence trail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationStep {
    /// Step name (e.g., `attestation_presence`, `slsa_level_check`).
    pub step: String,
    /// Whether this step passed.
    pub passed: bool,
    /// Human-readable detail.
    pub detail: String,
}

/// Deterministic verification evidence bundle.
///
/// Produced by the verification pipeline as an audit-ready record
/// of all checks performed, their outcomes, and the final decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationEvidence {
    /// Final decision.
    pub decision: VerificationDecision,
    /// Primary reason code for the decision.
    pub reason_code: VerificationReasonCode,
    /// Digest of the artifact being verified.
    pub artifact_digest: String,
    /// Ordered list of verification steps performed.
    pub steps: Vec<VerificationStep>,
    /// Policy configuration snapshot (for reproducibility).
    pub policy_snapshot: SupplyChainVerificationPolicy,
}

impl VerificationEvidence {
    /// Compute a deterministic content hash of the evidence bundle.
    ///
    /// # Errors
    ///
    /// Returns [`SupplyChainError::CanonicalizationFailed`] on serialization failures.
    pub fn content_hash(&self, algorithm: HashAlgorithm) -> Result<String, SupplyChainError> {
        let bytes = canonical_json_bytes(self)?;
        Ok(hash_bytes(&bytes, algorithm))
    }
}

/// Policy configuration for the supply chain verification pipeline.
///
/// Controls which checks are enforced during connector install/upgrade.
/// Fail-closed by default: missing attestation or SBOM blocks installation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct SupplyChainVerificationPolicy {
    /// Whether an attestation is required (default: `true`).
    pub require_attestation: bool,
    /// Whether an SBOM is required (default: `true`).
    pub require_sbom: bool,
    /// Minimum SLSA level required (0..=4, default: `0`).
    pub min_slsa_level: u8,
    /// Trusted builder identities. Empty means all builders accepted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_builders: Vec<String>,
    /// If `true`, unsigned artifacts are allowed (dev-only override).
    /// Must be explicitly set; default is `false`.
    pub allow_unsigned: bool,
    /// Require subject digest match against provided artifact digest.
    pub require_digest_match: bool,
}

impl Default for SupplyChainVerificationPolicy {
    fn default() -> Self {
        Self {
            require_attestation: true,
            require_sbom: true,
            min_slsa_level: 0,
            trusted_builders: Vec::new(),
            allow_unsigned: false,
            require_digest_match: true,
        }
    }
}

/// Supply chain verification pipeline.
///
/// Verifies attestations and SBOMs against a policy, producing deterministic
/// [`VerificationEvidence`] bundles suitable for audit logging.
pub struct VerificationPipeline {
    policy: SupplyChainVerificationPolicy,
}

impl VerificationPipeline {
    /// Create a new pipeline with the given policy.
    #[must_use]
    pub const fn new(policy: SupplyChainVerificationPolicy) -> Self {
        Self { policy }
    }

    /// Verify a connector artifact's supply chain attestation and SBOM.
    ///
    /// # Arguments
    /// * `artifact_digest` - The digest of the binary artifact to verify.
    /// * `attestation` - Optional supply chain attestation for the artifact.
    /// * `sbom` - Optional software bill of materials for the artifact.
    ///
    /// # Returns
    /// [`VerificationEvidence`] with the decision and audit trail.
    #[must_use]
    pub fn verify(
        &self,
        artifact_digest: &str,
        attestation: Option<&SupplyChainAttestation>,
        sbom: Option<&SoftwareBillOfMaterials>,
    ) -> VerificationEvidence {
        let mut steps = Vec::new();
        let mut first_failure: Option<VerificationReasonCode> = None;

        self.check_attestation(attestation, artifact_digest, &mut steps, &mut first_failure);
        self.check_sbom(sbom, &mut steps, &mut first_failure);

        let (decision, reason_code) = match first_failure {
            Some(code) => (VerificationDecision::Deny, code),
            None if attestation.is_none() && self.policy.allow_unsigned => (
                VerificationDecision::Allow,
                VerificationReasonCode::AllowedUnsigned,
            ),
            None => (
                VerificationDecision::Allow,
                VerificationReasonCode::Verified,
            ),
        };

        VerificationEvidence {
            decision,
            reason_code,
            artifact_digest: artifact_digest.to_string(),
            steps,
            policy_snapshot: self.policy.clone(),
        }
    }

    fn check_attestation(
        &self,
        attestation: Option<&SupplyChainAttestation>,
        artifact_digest: &str,
        steps: &mut Vec<VerificationStep>,
        first_failure: &mut Option<VerificationReasonCode>,
    ) {
        if let Some(att) = attestation {
            steps.push(VerificationStep {
                step: "attestation_presence".to_string(),
                passed: true,
                detail: "attestation provided".to_string(),
            });
            self.validate_attestation(att, artifact_digest, steps, first_failure);
        } else if self.policy.require_attestation {
            self.push_presence_check(
                "attestation_presence",
                "attestation",
                VerificationReasonCode::AttestationMissing,
                steps,
                first_failure,
            );
        }
    }

    fn validate_attestation(
        &self,
        att: &SupplyChainAttestation,
        artifact_digest: &str,
        steps: &mut Vec<VerificationStep>,
        first_failure: &mut Option<VerificationReasonCode>,
    ) {
        match att.validate() {
            Ok(()) => steps.push(VerificationStep {
                step: "attestation_validation".to_string(),
                passed: true,
                detail: "attestation structurally valid".to_string(),
            }),
            Err(err) => {
                steps.push(VerificationStep {
                    step: "attestation_validation".to_string(),
                    passed: false,
                    detail: format!("attestation invalid: {err}"),
                });
                if first_failure.is_none() {
                    *first_failure = Some(VerificationReasonCode::AttestationInvalid);
                }
            }
        }

        let passed = att.slsa_level >= self.policy.min_slsa_level;
        steps.push(VerificationStep {
            step: "slsa_level_check".to_string(),
            passed,
            detail: if passed {
                format!(
                    "SLSA level {} >= required minimum {}",
                    att.slsa_level, self.policy.min_slsa_level
                )
            } else {
                format!(
                    "SLSA level {} < required minimum {}",
                    att.slsa_level, self.policy.min_slsa_level
                )
            },
        });
        if !passed && first_failure.is_none() {
            *first_failure = Some(VerificationReasonCode::SlsaLevelInsufficient);
        }

        if self.policy.trusted_builders.is_empty() {
            steps.push(VerificationStep {
                step: "trusted_builder_check".to_string(),
                passed: true,
                detail: "trusted_builders list empty; all builders accepted".to_string(),
            });
        } else if self.policy.trusted_builders.contains(&att.builder_id) {
            steps.push(VerificationStep {
                step: "trusted_builder_check".to_string(),
                passed: true,
                detail: format!("builder `{}` is trusted", att.builder_id),
            });
        } else {
            steps.push(VerificationStep {
                step: "trusted_builder_check".to_string(),
                passed: false,
                detail: format!(
                    "builder `{}` is not in trusted_builders list",
                    att.builder_id
                ),
            });
            if first_failure.is_none() {
                *first_failure = Some(VerificationReasonCode::BuilderUntrusted);
            }
        }

        if self.policy.require_digest_match {
            let matched = att.subject_digest == artifact_digest;
            steps.push(VerificationStep {
                step: "subject_digest_match".to_string(),
                passed: matched,
                detail: if matched {
                    "subject_digest matches artifact digest".to_string()
                } else {
                    "attestation subject_digest does not match artifact digest".to_string()
                },
            });
            if !matched && first_failure.is_none() {
                *first_failure = Some(VerificationReasonCode::SubjectDigestMismatch);
            }
        }
    }

    fn check_sbom(
        &self,
        sbom: Option<&SoftwareBillOfMaterials>,
        steps: &mut Vec<VerificationStep>,
        first_failure: &mut Option<VerificationReasonCode>,
    ) {
        if let Some(sbom_obj) = sbom {
            steps.push(VerificationStep {
                step: "sbom_presence".to_string(),
                passed: true,
                detail: "SBOM provided".to_string(),
            });
            match sbom_obj.validate() {
                Ok(()) => steps.push(VerificationStep {
                    step: "sbom_validation".to_string(),
                    passed: true,
                    detail: "SBOM structurally valid".to_string(),
                }),
                Err(err) => {
                    steps.push(VerificationStep {
                        step: "sbom_validation".to_string(),
                        passed: false,
                        detail: format!("SBOM invalid: {err}"),
                    });
                    if first_failure.is_none() {
                        *first_failure = Some(VerificationReasonCode::SbomInvalid);
                    }
                }
            }
        } else if self.policy.require_sbom {
            self.push_presence_check(
                "sbom_presence",
                "SBOM",
                VerificationReasonCode::SbomMissing,
                steps,
                first_failure,
            );
        }
    }

    fn push_presence_check(
        &self,
        step_name: &str,
        label: &str,
        fail_code: VerificationReasonCode,
        steps: &mut Vec<VerificationStep>,
        first_failure: &mut Option<VerificationReasonCode>,
    ) {
        if self.policy.allow_unsigned {
            steps.push(VerificationStep {
                step: step_name.to_string(),
                passed: true,
                detail: format!("{label} missing but allow_unsigned is set"),
            });
        } else {
            steps.push(VerificationStep {
                step: step_name.to_string(),
                passed: false,
                detail: format!("{label} required but not provided"),
            });
            if first_failure.is_none() {
                *first_failure = Some(fail_code);
            }
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

    // ─────────────────────────────────────────────────────────────────────────
    // Attestation Validation: Error Path Coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn attestation_rejects_wrong_format() {
        let mut att = sample_attestation();
        att.format = "wrong-format".to_string();
        let err = att.validate().unwrap_err();
        assert!(matches!(err, SupplyChainError::InvalidAttestation { .. }));
        assert!(err.to_string().contains("format must be"));
    }

    #[test]
    fn attestation_rejects_wrong_schema_version() {
        let mut att = sample_attestation();
        att.schema_version = "2.0".to_string();
        let err = att.validate().unwrap_err();
        assert!(matches!(err, SupplyChainError::InvalidAttestation { .. }));
        assert!(err.to_string().contains("schema_version must be"));
    }

    #[test]
    fn attestation_rejects_empty_builder_id() {
        let mut att = sample_attestation();
        att.builder_id = "  ".to_string();
        let err = att.validate().unwrap_err();
        assert!(matches!(err, SupplyChainError::InvalidAttestation { .. }));
        assert!(err.to_string().contains("builder_id cannot be empty"));
    }

    #[test]
    fn attestation_rejects_empty_build_type() {
        let mut att = sample_attestation();
        att.build_type = String::new();
        let err = att.validate().unwrap_err();
        assert!(matches!(err, SupplyChainError::InvalidAttestation { .. }));
        assert!(err.to_string().contains("build_type cannot be empty"));
    }

    #[test]
    fn attestation_rejects_invalid_subject_digest_missing_prefix() {
        let mut att = sample_attestation();
        att.subject_digest = "a".repeat(64);
        let err = att.validate().unwrap_err();
        assert!(matches!(err, SupplyChainError::InvalidAttestation { .. }));
        assert!(err.to_string().contains("subject_digest"));
    }

    #[test]
    fn attestation_rejects_invalid_subject_digest_wrong_algorithm() {
        let mut att = sample_attestation();
        att.subject_digest = format!("sha256:{}", "a".repeat(64));
        let err = att.validate().unwrap_err();
        assert!(matches!(err, SupplyChainError::InvalidAttestation { .. }));
        assert!(err.to_string().contains("subject_digest"));
    }

    #[test]
    fn attestation_rejects_invalid_subject_digest_short_hex() {
        let mut att = sample_attestation();
        att.subject_digest = format!("blake3-256:{}", "a".repeat(32));
        let err = att.validate().unwrap_err();
        assert!(matches!(err, SupplyChainError::InvalidAttestation { .. }));
    }

    #[test]
    fn attestation_rejects_invalid_subject_digest_uppercase_hex() {
        let mut att = sample_attestation();
        att.subject_digest = format!("blake3-256:{}", "A".repeat(64));
        let err = att.validate().unwrap_err();
        assert!(matches!(err, SupplyChainError::InvalidAttestation { .. }));
    }

    #[test]
    fn attestation_rejects_invalid_provenance_hash() {
        let mut att = sample_attestation();
        att.provenance_hash = "not-a-digest".to_string();
        let err = att.validate().unwrap_err();
        assert!(matches!(err, SupplyChainError::InvalidAttestation { .. }));
        assert!(err.to_string().contains("provenance_hash"));
    }

    #[test]
    fn attestation_rejects_empty_materials() {
        let mut att = sample_attestation();
        att.materials = vec![];
        let err = att.validate().unwrap_err();
        assert!(matches!(err, SupplyChainError::InvalidAttestation { .. }));
        assert!(err.to_string().contains("materials cannot be empty"));
    }

    #[test]
    fn attestation_rejects_material_with_empty_uri() {
        let mut att = sample_attestation();
        att.materials[0].uri = "  ".to_string();
        let err = att.validate().unwrap_err();
        assert!(matches!(err, SupplyChainError::InvalidAttestation { .. }));
        assert!(err.to_string().contains("materials.uri cannot be empty"));
    }

    #[test]
    fn attestation_rejects_material_with_bad_digest() {
        let mut att = sample_attestation();
        att.materials[0].digest = "md5:abc".to_string();
        let err = att.validate().unwrap_err();
        assert!(matches!(err, SupplyChainError::InvalidAttestation { .. }));
        assert!(err.to_string().contains("materials.digest"));
    }

    #[test]
    fn attestation_rejects_metadata_finished_before_started() {
        let mut att = sample_attestation();
        att.metadata.build_finished_at =
            Utc.with_ymd_and_hms(2026, 2, 1, 11, 0, 0).single().unwrap();
        let err = att.validate().unwrap_err();
        assert!(matches!(err, SupplyChainError::InvalidAttestation { .. }));
        assert!(err.to_string().contains("build_finished_at"));
    }

    #[test]
    fn attestation_rejects_empty_invocation_id() {
        let mut att = sample_attestation();
        att.metadata.invocation_id = Some("  ".to_string());
        let err = att.validate().unwrap_err();
        assert!(matches!(err, SupplyChainError::InvalidAttestation { .. }));
        assert!(err.to_string().contains("invocation_id"));
    }

    #[test]
    fn attestation_accepts_none_invocation_id() {
        let mut att = sample_attestation();
        att.metadata.invocation_id = None;
        assert!(att.validate().is_ok());
    }

    #[test]
    fn attestation_rejects_slsa_level_above_4() {
        let mut att = sample_attestation();
        att.slsa_level = 5;
        let err = att.validate().unwrap_err();
        assert!(matches!(err, SupplyChainError::InvalidAttestation { .. }));
        assert!(err.to_string().contains("slsa_level"));
    }

    #[test]
    fn attestation_accepts_slsa_level_0() {
        let mut att = sample_attestation();
        att.slsa_level = 0;
        assert!(att.validate().is_ok());
    }

    #[test]
    fn attestation_accepts_slsa_level_4() {
        let mut att = sample_attestation();
        att.slsa_level = 4;
        assert!(att.validate().is_ok());
    }

    #[test]
    fn attestation_rejects_empty_entry_in_builder_allowlist() {
        let mut att = sample_attestation();
        att.builder_allowlist.push("  ".to_string());
        let err = att.validate().unwrap_err();
        assert!(matches!(err, SupplyChainError::InvalidAttestation { .. }));
        assert!(err.to_string().contains("builder_allowlist"));
    }

    #[test]
    fn attestation_accepts_empty_builder_allowlist() {
        let mut att = sample_attestation();
        att.builder_allowlist = vec![];
        assert!(att.validate().is_ok());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Attestation: Trust Root Validation
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn attestation_rejects_empty_trust_root_id() {
        let mut att = sample_attestation();
        att.trust_root.root_id = String::new();
        let err = att.validate().unwrap_err();
        assert!(matches!(err, SupplyChainError::InvalidTrustRoot { .. }));
        assert!(err.to_string().contains("root_id cannot be empty"));
    }

    #[test]
    fn attestation_rejects_invalid_trust_root_type() {
        let mut att = sample_attestation();
        att.trust_root.root_type = "custom".to_string();
        let err = att.validate().unwrap_err();
        assert!(matches!(err, SupplyChainError::InvalidTrustRoot { .. }));
        assert!(err.to_string().contains("root_type must be one of"));
    }

    #[test]
    fn attestation_accepts_tuf_trust_root() {
        let mut att = sample_attestation();
        att.trust_root.root_type = "tuf".to_string();
        assert!(att.validate().is_ok());
    }

    #[test]
    fn attestation_accepts_manual_trust_root() {
        let mut att = sample_attestation();
        att.trust_root.root_type = "manual".to_string();
        assert!(att.validate().is_ok());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Attestation: Signature Validation
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn attestation_rejects_non_ed25519_algorithm() {
        let mut att = sample_attestation();
        att.signature.algorithm = "rsa256".to_string();
        let err = att.validate().unwrap_err();
        assert!(matches!(err, SupplyChainError::InvalidSignature { .. }));
        assert!(err.to_string().contains("algorithm must be `ed25519`"));
    }

    #[test]
    fn attestation_rejects_empty_key_id() {
        let mut att = sample_attestation();
        att.signature.key_id = String::new();
        let err = att.validate().unwrap_err();
        assert!(matches!(err, SupplyChainError::InvalidSignature { .. }));
        assert!(err.to_string().contains("key_id cannot be empty"));
    }

    #[test]
    fn attestation_rejects_empty_signature_data() {
        let mut att = sample_attestation();
        att.signature.signature = "  ".to_string();
        let err = att.validate().unwrap_err();
        assert!(matches!(err, SupplyChainError::InvalidSignature { .. }));
        assert!(err.to_string().contains("signature cannot be empty"));
    }

    #[test]
    fn attestation_rejects_wrong_signed_fields() {
        let mut att = sample_attestation();
        att.signature.signed_fields = vec!["format".to_string(), "schema_version".to_string()];
        let err = att.validate().unwrap_err();
        assert!(matches!(err, SupplyChainError::InvalidSignature { .. }));
        assert!(err.to_string().contains("signed_fields must exactly match"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Attestation: Canonical Encoding & Hashing
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn attestation_content_hash_cbor_is_deterministic() {
        let att = sample_attestation();
        let hash_a = att
            .content_hash(CanonicalEncoding::Cbor, HashAlgorithm::Blake3_256)
            .unwrap();
        let hash_b = att
            .content_hash(CanonicalEncoding::Cbor, HashAlgorithm::Blake3_256)
            .unwrap();
        assert_eq!(hash_a, hash_b);
        assert!(hash_a.starts_with("blake3-256:"));
        assert_eq!(hash_a.len(), "blake3-256:".len() + 64);
    }

    #[test]
    fn attestation_content_hash_json_is_deterministic() {
        let att = sample_attestation();
        let hash_a = att
            .content_hash(CanonicalEncoding::Json, HashAlgorithm::Sha256)
            .unwrap();
        let hash_b = att
            .content_hash(CanonicalEncoding::Json, HashAlgorithm::Sha256)
            .unwrap();
        assert_eq!(hash_a, hash_b);
        assert!(hash_a.starts_with("sha256:"));
    }

    #[test]
    fn attestation_cbor_and_json_hashes_differ() {
        let att = sample_attestation();
        let cbor_hash = att
            .content_hash(CanonicalEncoding::Cbor, HashAlgorithm::Blake3_256)
            .unwrap();
        let json_hash = att
            .content_hash(CanonicalEncoding::Json, HashAlgorithm::Blake3_256)
            .unwrap();
        assert_ne!(
            cbor_hash, json_hash,
            "CBOR and JSON encodings should produce different hashes"
        );
    }

    #[test]
    fn attestation_canonical_bytes_cbor_nonempty() {
        let att = sample_attestation();
        let bytes = att.canonical_bytes(CanonicalEncoding::Cbor).unwrap();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn attestation_canonical_bytes_json_nonempty() {
        let att = sample_attestation();
        let bytes = att.canonical_bytes(CanonicalEncoding::Json).unwrap();
        assert!(!bytes.is_empty());
        // JSON canonical bytes should parse as valid JSON
        let _: Value = serde_json::from_slice(&bytes).expect("should be valid JSON");
    }

    #[test]
    fn attestation_signing_bytes_include_domain_separator() {
        let att = sample_attestation();
        let bytes = att.signing_bytes().unwrap();
        // canonical_signing_bytes prefixes with schema ID — verify non-trivial length
        assert!(
            bytes.len() > 100,
            "signing bytes should include domain prefix + CBOR payload"
        );
    }

    #[test]
    fn attestation_signing_bytes_differ_for_different_subjects() {
        let att_a = sample_attestation();
        let mut att_b = sample_attestation();
        att_b.subject_digest = format!("blake3-256:{}", "f".repeat(64));

        let bytes_a = att_a.signing_bytes().unwrap();
        let bytes_b = att_b.signing_bytes().unwrap();
        assert_ne!(bytes_a, bytes_b);
    }

    #[test]
    fn attestation_uses_in_toto_predicate() {
        let mut att = sample_attestation();
        att.predicate_type = AttestationPredicateType::InTotoStatementV1;
        assert!(att.validate().is_ok());

        // Signing bytes differ between predicate types
        let slsa = sample_attestation().signing_bytes().unwrap();
        let intoto = att.signing_bytes().unwrap();
        assert_ne!(slsa, intoto);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Attestation: Serde Round-Trip
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn attestation_json_roundtrip() {
        let att = sample_attestation();
        let json = serde_json::to_string(&att).unwrap();
        let deserialized: SupplyChainAttestation = serde_json::from_str(&json).unwrap();
        assert_eq!(att, deserialized);
    }

    #[test]
    fn attestation_predicate_type_serde_urls() {
        let slsa = serde_json::to_string(&AttestationPredicateType::SlsaProvenanceV1).unwrap();
        assert_eq!(slsa, "\"https://slsa.dev/provenance/v1\"");

        let intoto = serde_json::to_string(&AttestationPredicateType::InTotoStatementV1).unwrap();
        assert_eq!(intoto, "\"https://in-toto.io/Statement/v1\"");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SBOM Validation: Error Path Coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn sbom_rejects_wrong_format() {
        let mut sbom = sample_sbom();
        sbom.format = "wrong".to_string();
        let err = sbom.validate().unwrap_err();
        assert!(matches!(err, SupplyChainError::InvalidSbom { .. }));
        assert!(err.to_string().contains("format must be"));
    }

    #[test]
    fn sbom_rejects_wrong_schema_version() {
        let mut sbom = sample_sbom();
        sbom.schema_version = "0.9".to_string();
        let err = sbom.validate().unwrap_err();
        assert!(matches!(err, SupplyChainError::InvalidSbom { .. }));
        assert!(err.to_string().contains("schema_version must be"));
    }

    #[test]
    fn sbom_rejects_empty_bom_version() {
        let mut sbom = sample_sbom();
        sbom.bom_version = "  ".to_string();
        let err = sbom.validate().unwrap_err();
        assert!(matches!(err, SupplyChainError::InvalidSbom { .. }));
        assert!(err.to_string().contains("bom_version cannot be empty"));
    }

    #[test]
    fn sbom_rejects_empty_tool_chain() {
        let mut sbom = sample_sbom();
        sbom.tool_chain = vec![];
        let err = sbom.validate().unwrap_err();
        assert!(matches!(err, SupplyChainError::InvalidSbom { .. }));
        assert!(err.to_string().contains("tool_chain cannot be empty"));
    }

    #[test]
    fn sbom_rejects_empty_entry_in_tool_chain() {
        let mut sbom = sample_sbom();
        sbom.tool_chain.push("  ".to_string());
        let err = sbom.validate().unwrap_err();
        assert!(matches!(err, SupplyChainError::InvalidSbom { .. }));
        assert!(
            err.to_string()
                .contains("tool_chain cannot contain empty values")
        );
    }

    #[test]
    fn sbom_rejects_empty_components() {
        let mut sbom = sample_sbom();
        sbom.components = vec![];
        let err = sbom.validate().unwrap_err();
        assert!(matches!(err, SupplyChainError::InvalidSbom { .. }));
        assert!(err.to_string().contains("components cannot be empty"));
    }

    #[test]
    fn sbom_rejects_component_with_empty_id() {
        let mut sbom = sample_sbom();
        sbom.components[0].component_id = String::new();
        let err = sbom.validate().unwrap_err();
        assert!(matches!(err, SupplyChainError::InvalidSbom { .. }));
        assert!(
            err.to_string()
                .contains("components.component_id cannot be empty")
        );
    }

    #[test]
    fn sbom_rejects_component_with_empty_name() {
        let mut sbom = sample_sbom();
        sbom.components[0].name = "  ".to_string();
        let err = sbom.validate().unwrap_err();
        assert!(matches!(err, SupplyChainError::InvalidSbom { .. }));
        assert!(err.to_string().contains("components.name cannot be empty"));
    }

    #[test]
    fn sbom_rejects_component_with_empty_version() {
        let mut sbom = sample_sbom();
        sbom.components[0].version = String::new();
        let err = sbom.validate().unwrap_err();
        assert!(matches!(err, SupplyChainError::InvalidSbom { .. }));
        assert!(
            err.to_string()
                .contains("components.version cannot be empty")
        );
    }

    #[test]
    fn sbom_rejects_component_with_empty_hashes() {
        let mut sbom = sample_sbom();
        sbom.components[0].hashes = vec![];
        let err = sbom.validate().unwrap_err();
        assert!(matches!(err, SupplyChainError::InvalidSbom { .. }));
        assert!(
            err.to_string()
                .contains("components.hashes cannot be empty")
        );
    }

    #[test]
    fn sbom_rejects_component_with_unsupported_hash_algorithm() {
        let mut sbom = sample_sbom();
        sbom.components[0].hashes = vec!["md5:abc123".to_string()];
        let err = sbom.validate().unwrap_err();
        assert!(matches!(err, SupplyChainError::InvalidSbom { .. }));
        assert!(err.to_string().contains("components.hashes value"));
    }

    #[test]
    fn sbom_rejects_component_with_empty_licenses() {
        let mut sbom = sample_sbom();
        sbom.components[0].licenses = vec![];
        let err = sbom.validate().unwrap_err();
        assert!(matches!(err, SupplyChainError::InvalidSbom { .. }));
        assert!(
            err.to_string()
                .contains("components.licenses cannot be empty")
        );
    }

    #[test]
    fn sbom_rejects_component_with_empty_license_entry() {
        let mut sbom = sample_sbom();
        sbom.components[0].licenses = vec!["MIT".to_string(), "  ".to_string()];
        let err = sbom.validate().unwrap_err();
        assert!(matches!(err, SupplyChainError::InvalidSbom { .. }));
        assert!(
            err.to_string()
                .contains("components.licenses cannot contain empty values")
        );
    }

    #[test]
    fn sbom_rejects_duplicate_component_ids() {
        let mut sbom = sample_sbom();
        sbom.components[1].component_id = "connector-root".to_string();
        let err = sbom.validate().unwrap_err();
        assert!(matches!(err, SupplyChainError::InvalidSbom { .. }));
        assert!(err.to_string().contains("duplicate component_id"));
    }

    #[test]
    fn sbom_rejects_dependency_with_empty_component_id() {
        let mut sbom = sample_sbom();
        sbom.dependencies[0].component_id = "  ".to_string();
        let err = sbom.validate().unwrap_err();
        assert!(matches!(err, SupplyChainError::InvalidSbom { .. }));
        assert!(
            err.to_string()
                .contains("dependencies.component_id cannot be empty")
        );
    }

    #[test]
    fn sbom_rejects_dependency_referencing_unknown_component() {
        let mut sbom = sample_sbom();
        sbom.dependencies[0].component_id = "ghost-component".to_string();
        let err = sbom.validate().unwrap_err();
        assert!(matches!(err, SupplyChainError::InvalidSbom { .. }));
        assert!(err.to_string().contains("not found in components"));
    }

    #[test]
    fn sbom_rejects_duplicate_dependency_entries() {
        let mut sbom = sample_sbom();
        sbom.dependencies.push(SbomDependency {
            component_id: "connector-root".to_string(),
            depends_on: vec![],
        });
        let err = sbom.validate().unwrap_err();
        assert!(matches!(err, SupplyChainError::InvalidSbom { .. }));
        assert!(err.to_string().contains("duplicate component_id"));
    }

    #[test]
    fn sbom_rejects_empty_dependency_target() {
        let mut sbom = sample_sbom();
        sbom.dependencies[0].depends_on = vec![String::new()];
        let err = sbom.validate().unwrap_err();
        assert!(matches!(err, SupplyChainError::InvalidSbom { .. }));
        assert!(err.to_string().contains("empty target"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SBOM: Trust Root & Signature Validation
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn sbom_rejects_invalid_trust_root_type() {
        let mut sbom = sample_sbom();
        sbom.trust_root.root_type = "unknown".to_string();
        let err = sbom.validate().unwrap_err();
        assert!(matches!(err, SupplyChainError::InvalidTrustRoot { .. }));
    }

    #[test]
    fn sbom_rejects_wrong_signature_signed_fields() {
        let mut sbom = sample_sbom();
        sbom.signature.signed_fields = vec!["format".to_string()];
        let err = sbom.validate().unwrap_err();
        assert!(matches!(err, SupplyChainError::InvalidSignature { .. }));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SBOM: Canonical Encoding & Hashing
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn sbom_signing_bytes_are_deterministic() {
        let sbom = sample_sbom();
        let bytes_a = sbom.signing_bytes().unwrap();
        let bytes_b = sbom.signing_bytes().unwrap();
        assert_eq!(bytes_a, bytes_b);
    }

    #[test]
    fn sbom_signing_bytes_differ_for_different_content() {
        let sbom_a = sample_sbom();
        let mut sbom_b = sample_sbom();
        sbom_b.bom_version = "2.0".to_string();

        let bytes_a = sbom_a.signing_bytes().unwrap();
        let bytes_b = sbom_b.signing_bytes().unwrap();
        assert_ne!(bytes_a, bytes_b);
    }

    #[test]
    fn sbom_canonical_bytes_json_is_valid_json() {
        let sbom = sample_sbom();
        let bytes = sbom.canonical_bytes(CanonicalEncoding::Json).unwrap();
        let _: Value = serde_json::from_slice(&bytes).expect("should be valid JSON");
    }

    #[test]
    fn sbom_cbor_and_json_hashes_differ() {
        let sbom = sample_sbom();
        let cbor_hash = sbom
            .content_hash(CanonicalEncoding::Cbor, HashAlgorithm::Blake3_256)
            .unwrap();
        let json_hash = sbom
            .content_hash(CanonicalEncoding::Json, HashAlgorithm::Blake3_256)
            .unwrap();
        assert_ne!(cbor_hash, json_hash);
    }

    #[test]
    fn sbom_json_roundtrip() {
        let sbom = sample_sbom();
        let json = serde_json::to_string(&sbom).unwrap();
        let deserialized: SoftwareBillOfMaterials = serde_json::from_str(&json).unwrap();
        assert_eq!(sbom, deserialized);
    }

    #[test]
    fn sbom_uses_spdx_format() {
        let mut sbom = sample_sbom();
        sbom.bom_format = SbomFormat::Spdx;
        assert!(sbom.validate().is_ok());

        let json = serde_json::to_string(&sbom.bom_format).unwrap();
        assert_eq!(json, "\"spdx\"");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helper Functions: Edge Cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn is_lower_hex_64_rejects_empty() {
        assert!(!is_lower_hex_64(""));
    }

    #[test]
    fn is_lower_hex_64_rejects_short() {
        assert!(!is_lower_hex_64(&"a".repeat(63)));
    }

    #[test]
    fn is_lower_hex_64_rejects_long() {
        assert!(!is_lower_hex_64(&"a".repeat(65)));
    }

    #[test]
    fn is_lower_hex_64_rejects_uppercase() {
        assert!(!is_lower_hex_64(&"A".repeat(64)));
    }

    #[test]
    fn is_lower_hex_64_rejects_non_hex() {
        assert!(!is_lower_hex_64(&"g".repeat(64)));
    }

    #[test]
    fn is_lower_hex_64_accepts_valid() {
        assert!(is_lower_hex_64(&"a".repeat(64)));
        assert!(is_lower_hex_64(&"0123456789abcdef".repeat(4)));
    }

    #[test]
    fn digest_is_supported_accepts_blake3_256() {
        assert!(digest_is_supported(&format!(
            "blake3-256:{}",
            "a".repeat(64)
        )));
    }

    #[test]
    fn digest_is_supported_accepts_sha256() {
        assert!(digest_is_supported(&format!("sha256:{}", "f".repeat(64))));
    }

    #[test]
    fn digest_is_supported_rejects_unknown_algorithm() {
        assert!(!digest_is_supported(&format!("md5:{}", "a".repeat(64))));
    }

    #[test]
    fn digest_is_supported_rejects_no_colon() {
        assert!(!digest_is_supported("no_colon_here"));
    }

    #[test]
    fn digest_is_supported_rejects_uppercase_hex() {
        assert!(!digest_is_supported(&format!(
            "blake3-256:{}",
            "A".repeat(64)
        )));
    }

    #[test]
    fn hash_algorithm_as_str_values() {
        assert_eq!(HashAlgorithm::Blake3_256.as_str(), "blake3-256");
        assert_eq!(HashAlgorithm::Sha256.as_str(), "sha256");
    }

    #[test]
    fn hash_algorithm_default_is_blake3() {
        assert_eq!(HashAlgorithm::default(), HashAlgorithm::Blake3_256);
    }

    #[test]
    fn hash_bytes_blake3_produces_prefixed_output() {
        let result = hash_bytes(b"test data", HashAlgorithm::Blake3_256);
        assert!(result.starts_with("blake3-256:"));
        assert_eq!(result.len(), "blake3-256:".len() + 64);
    }

    #[test]
    fn hash_bytes_sha256_produces_prefixed_output() {
        let result = hash_bytes(b"test data", HashAlgorithm::Sha256);
        assert!(result.starts_with("sha256:"));
        assert_eq!(result.len(), "sha256:".len() + 64);
    }

    #[test]
    fn hash_bytes_different_algorithms_produce_different_hashes() {
        let blake = hash_bytes(b"same input", HashAlgorithm::Blake3_256);
        let sha = hash_bytes(b"same input", HashAlgorithm::Sha256);
        assert_ne!(blake, sha);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SupplyChainSignature Constructor
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn signature_new_sets_ed25519_algorithm() {
        let sig = SupplyChainSignature::new("key-1", "data", vec!["f1".to_string()]);
        assert_eq!(sig.algorithm, "ed25519");
        assert_eq!(sig.key_id, "key-1");
        assert_eq!(sig.signature, "data");
        assert_eq!(sig.signed_fields, vec!["f1".to_string()]);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Canonical JSON: Deep Nesting
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn canonicalize_json_sorts_nested_objects() {
        let input: Value =
            serde_json::from_str(r#"{"z": {"b": 1, "a": 2}, "a": {"y": {"c": 3, "b": 4}}}"#)
                .unwrap();
        let canonical = canonicalize_json_value(input);
        let keys: Vec<&String> = canonical.as_object().unwrap().keys().collect();
        assert_eq!(keys, vec!["a", "z"], "top-level keys must be sorted");

        let nested = canonical["a"]["y"].as_object().unwrap();
        let nested_keys: Vec<&String> = nested.keys().collect();
        assert_eq!(nested_keys, vec!["b", "c"], "nested keys must be sorted");
    }

    #[test]
    fn canonicalize_json_preserves_array_order() {
        let input: Value = serde_json::from_str(r#"{"arr": [3, 1, 2]}"#).unwrap();
        let canonical = canonicalize_json_value(input);
        let arr: Vec<i64> = canonical["arr"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_i64().unwrap())
            .collect();
        assert_eq!(arr, vec![3, 1, 2], "array element order must be preserved");
    }

    #[test]
    fn canonicalize_json_handles_scalars() {
        assert_eq!(
            canonicalize_json_value(Value::String("hello".into())),
            Value::String("hello".into())
        );
        assert_eq!(
            canonicalize_json_value(Value::Bool(true)),
            Value::Bool(true)
        );
        assert_eq!(canonicalize_json_value(Value::Null), Value::Null);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Cross-Cutting: Attestation vs SBOM Signing Bytes Differ
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn attestation_and_sbom_signing_bytes_use_different_domains() {
        let att_bytes = sample_attestation().signing_bytes().unwrap();
        let sbom_bytes = sample_sbom().signing_bytes().unwrap();
        assert_ne!(
            att_bytes, sbom_bytes,
            "attestation and sbom must use different schema domain separators"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Error Type Display
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn error_display_messages() {
        let err = SupplyChainError::InvalidAttestation {
            reason: "test".to_string(),
        };
        assert_eq!(err.to_string(), "invalid attestation: test");

        let err = SupplyChainError::InvalidSbom {
            reason: "bad".to_string(),
        };
        assert_eq!(err.to_string(), "invalid sbom: bad");

        let err = SupplyChainError::InvalidSignature {
            reason: "sig".to_string(),
        };
        assert_eq!(err.to_string(), "invalid signature: sig");

        let err = SupplyChainError::InvalidTrustRoot {
            reason: "root".to_string(),
        };
        assert_eq!(err.to_string(), "invalid trust root: root");

        let err = SupplyChainError::CanonicalizationFailed {
            reason: "enc".to_string(),
        };
        assert_eq!(err.to_string(), "canonicalization failed: enc");
    }

    // ── Verification Pipeline tests ───────────────────────────────────────

    fn default_pipeline() -> VerificationPipeline {
        VerificationPipeline::new(SupplyChainVerificationPolicy::default())
    }

    fn artifact_digest() -> String {
        // Must match sample_attestation().subject_digest
        format!("blake3-256:{}", "a".repeat(64))
    }

    #[test]
    fn pipeline_allows_valid_attestation_and_sbom() {
        let pipeline = default_pipeline();
        let att = sample_attestation();
        let sbom = sample_sbom();
        let evidence = pipeline.verify(&artifact_digest(), Some(&att), Some(&sbom));

        assert_eq!(evidence.decision, VerificationDecision::Allow);
        assert_eq!(evidence.reason_code, VerificationReasonCode::Verified);
        assert!(evidence.steps.iter().all(|s| s.passed));
    }

    #[test]
    fn pipeline_denies_missing_attestation() {
        let pipeline = default_pipeline();
        let sbom = sample_sbom();
        let evidence = pipeline.verify(&artifact_digest(), None, Some(&sbom));

        assert_eq!(evidence.decision, VerificationDecision::Deny);
        assert_eq!(
            evidence.reason_code,
            VerificationReasonCode::AttestationMissing
        );
        assert!(!evidence.steps[0].passed);
    }

    #[test]
    fn pipeline_allows_unsigned_when_policy_permits() {
        let policy = SupplyChainVerificationPolicy {
            allow_unsigned: true,
            ..Default::default()
        };
        let pipeline = VerificationPipeline::new(policy);
        let evidence = pipeline.verify(&artifact_digest(), None, None);

        assert_eq!(evidence.decision, VerificationDecision::Allow);
        assert_eq!(
            evidence.reason_code,
            VerificationReasonCode::AllowedUnsigned
        );
    }

    #[test]
    fn pipeline_denies_slsa_level_below_minimum() {
        let policy = SupplyChainVerificationPolicy {
            min_slsa_level: 4,
            ..Default::default()
        };
        let pipeline = VerificationPipeline::new(policy);
        let att = sample_attestation(); // slsa_level = 3
        let sbom = sample_sbom();
        let evidence = pipeline.verify(&artifact_digest(), Some(&att), Some(&sbom));

        assert_eq!(evidence.decision, VerificationDecision::Deny);
        assert_eq!(
            evidence.reason_code,
            VerificationReasonCode::SlsaLevelInsufficient
        );
    }

    #[test]
    fn pipeline_denies_untrusted_builder() {
        let policy = SupplyChainVerificationPolicy {
            trusted_builders: vec!["builder://other-ci".to_string()],
            ..Default::default()
        };
        let pipeline = VerificationPipeline::new(policy);
        let att = sample_attestation(); // builder_id = "builder://github/actions"
        let sbom = sample_sbom();
        let evidence = pipeline.verify(&artifact_digest(), Some(&att), Some(&sbom));

        assert_eq!(evidence.decision, VerificationDecision::Deny);
        assert_eq!(
            evidence.reason_code,
            VerificationReasonCode::BuilderUntrusted
        );
    }

    #[test]
    fn pipeline_allows_when_trusted_builders_empty() {
        // Empty trusted_builders list means all builders are accepted
        let policy = SupplyChainVerificationPolicy {
            trusted_builders: vec![],
            ..Default::default()
        };
        let pipeline = VerificationPipeline::new(policy);
        let att = sample_attestation();
        let sbom = sample_sbom();
        let evidence = pipeline.verify(&artifact_digest(), Some(&att), Some(&sbom));

        assert_eq!(evidence.decision, VerificationDecision::Allow);
        assert_eq!(evidence.reason_code, VerificationReasonCode::Verified);
    }

    #[test]
    fn pipeline_denies_subject_digest_mismatch() {
        let pipeline = default_pipeline();
        let att = sample_attestation();
        let sbom = sample_sbom();
        let mismatched_digest = format!("blake3-256:{}", "x".repeat(64));
        let evidence = pipeline.verify(&mismatched_digest, Some(&att), Some(&sbom));

        assert_eq!(evidence.decision, VerificationDecision::Deny);
        assert_eq!(
            evidence.reason_code,
            VerificationReasonCode::SubjectDigestMismatch
        );
    }

    #[test]
    fn pipeline_denies_missing_sbom() {
        let pipeline = default_pipeline();
        let att = sample_attestation();
        let evidence = pipeline.verify(&artifact_digest(), Some(&att), None);

        assert_eq!(evidence.decision, VerificationDecision::Deny);
        assert_eq!(evidence.reason_code, VerificationReasonCode::SbomMissing);
    }

    #[test]
    fn pipeline_denies_invalid_attestation() {
        let pipeline = default_pipeline();
        let mut att = sample_attestation();
        // Break structural validation: empty builder_id
        att.builder_id = String::new();
        let sbom = sample_sbom();
        let evidence = pipeline.verify(&artifact_digest(), Some(&att), Some(&sbom));

        assert_eq!(evidence.decision, VerificationDecision::Deny);
        assert_eq!(
            evidence.reason_code,
            VerificationReasonCode::AttestationInvalid
        );
    }

    #[test]
    fn pipeline_denies_invalid_sbom() {
        let pipeline = default_pipeline();
        let att = sample_attestation();
        let mut sbom = sample_sbom();
        // Break structural validation: empty components
        sbom.components.clear();
        let evidence = pipeline.verify(&artifact_digest(), Some(&att), Some(&sbom));

        assert_eq!(evidence.decision, VerificationDecision::Deny);
        assert_eq!(evidence.reason_code, VerificationReasonCode::SbomInvalid);
    }

    #[test]
    fn pipeline_captures_all_steps_on_success() {
        let policy = SupplyChainVerificationPolicy {
            trusted_builders: vec!["builder://github/actions".to_string()],
            ..Default::default()
        };
        let pipeline = VerificationPipeline::new(policy);
        let att = sample_attestation();
        let sbom = sample_sbom();
        let evidence = pipeline.verify(&artifact_digest(), Some(&att), Some(&sbom));

        // Should have: attestation_presence, attestation_validation,
        // slsa_level_check, trusted_builder_check, subject_digest_match,
        // sbom_presence, sbom_validation = 7 steps
        assert_eq!(evidence.steps.len(), 7);
        let step_names: Vec<&str> = evidence.steps.iter().map(|s| s.step.as_str()).collect();
        assert_eq!(
            step_names,
            vec![
                "attestation_presence",
                "attestation_validation",
                "slsa_level_check",
                "trusted_builder_check",
                "subject_digest_match",
                "sbom_presence",
                "sbom_validation",
            ]
        );
    }

    #[test]
    fn pipeline_snapshots_policy_in_evidence() {
        let policy = SupplyChainVerificationPolicy {
            min_slsa_level: 2,
            trusted_builders: vec!["builder://github/actions".to_string()],
            ..Default::default()
        };
        let pipeline = VerificationPipeline::new(policy.clone());
        let att = sample_attestation();
        let sbom = sample_sbom();
        let evidence = pipeline.verify(&artifact_digest(), Some(&att), Some(&sbom));

        assert_eq!(evidence.policy_snapshot, policy);
    }

    #[test]
    fn pipeline_evidence_hash_is_deterministic() {
        let pipeline = default_pipeline();
        let att = sample_attestation();
        let sbom = sample_sbom();

        let e1 = pipeline.verify(&artifact_digest(), Some(&att), Some(&sbom));
        let e2 = pipeline.verify(&artifact_digest(), Some(&att), Some(&sbom));

        let h1 = e1.content_hash(HashAlgorithm::Sha256).unwrap();
        let h2 = e2.content_hash(HashAlgorithm::Sha256).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn pipeline_reports_first_failure_as_reason_code() {
        // Both SLSA too low AND untrusted builder — should report SLSA first
        let policy = SupplyChainVerificationPolicy {
            min_slsa_level: 4,
            trusted_builders: vec!["builder://other-ci".to_string()],
            ..Default::default()
        };
        let pipeline = VerificationPipeline::new(policy);
        let att = sample_attestation(); // slsa=3, builder="builder://github/actions"
        let sbom = sample_sbom();
        let evidence = pipeline.verify(&artifact_digest(), Some(&att), Some(&sbom));

        assert_eq!(evidence.decision, VerificationDecision::Deny);
        // SLSA check runs before builder check → first failure
        assert_eq!(
            evidence.reason_code,
            VerificationReasonCode::SlsaLevelInsufficient
        );
        // Both should still be recorded as failed steps
        let failed: Vec<&str> = evidence
            .steps
            .iter()
            .filter(|s| !s.passed)
            .map(|s| s.step.as_str())
            .collect();
        assert_eq!(failed, vec!["slsa_level_check", "trusted_builder_check"]);
    }

    #[test]
    fn pipeline_skips_attestation_checks_when_not_required() {
        let policy = SupplyChainVerificationPolicy {
            require_attestation: false,
            require_sbom: false,
            ..Default::default()
        };
        let pipeline = VerificationPipeline::new(policy);
        let evidence = pipeline.verify(&artifact_digest(), None, None);

        assert_eq!(evidence.decision, VerificationDecision::Allow);
        assert_eq!(evidence.reason_code, VerificationReasonCode::Verified);
        assert!(evidence.steps.is_empty());
    }

    #[test]
    fn verification_reason_code_display() {
        // Display uses serde's SCREAMING_SNAKE_CASE representation
        assert_eq!(VerificationReasonCode::Verified.to_string(), "VERIFIED");
        assert_eq!(
            VerificationReasonCode::AttestationMissing.to_string(),
            "ATTESTATION_MISSING"
        );
        assert_eq!(
            VerificationReasonCode::SlsaLevelInsufficient.to_string(),
            "SLSA_LEVEL_INSUFFICIENT"
        );
        assert_eq!(
            VerificationReasonCode::BuilderUntrusted.to_string(),
            "BUILDER_UNTRUSTED"
        );
        assert_eq!(
            VerificationReasonCode::SubjectDigestMismatch.to_string(),
            "SUBJECT_DIGEST_MISMATCH"
        );
        assert_eq!(
            VerificationReasonCode::SbomMissing.to_string(),
            "SBOM_MISSING"
        );
        assert_eq!(
            VerificationReasonCode::AllowedUnsigned.to_string(),
            "ALLOWED_UNSIGNED"
        );
    }

    #[test]
    fn verification_decision_serde_roundtrip() {
        let allow = serde_json::to_string(&VerificationDecision::Allow).unwrap();
        assert_eq!(allow, "\"allow\"");
        let deny = serde_json::to_string(&VerificationDecision::Deny).unwrap();
        assert_eq!(deny, "\"deny\"");

        let roundtrip: VerificationDecision = serde_json::from_str(&allow).unwrap();
        assert_eq!(roundtrip, VerificationDecision::Allow);
    }

    #[test]
    fn verification_reason_code_serde_roundtrip() {
        let code = VerificationReasonCode::SlsaLevelInsufficient;
        let json = serde_json::to_string(&code).unwrap();
        assert_eq!(json, "\"SLSA_LEVEL_INSUFFICIENT\"");

        let roundtrip: VerificationReasonCode = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip, code);
    }

    #[test]
    fn verification_evidence_serde_roundtrip() {
        let pipeline = default_pipeline();
        let att = sample_attestation();
        let sbom = sample_sbom();
        let evidence = pipeline.verify(&artifact_digest(), Some(&att), Some(&sbom));

        let json = serde_json::to_string_pretty(&evidence).unwrap();
        let roundtrip: VerificationEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip, evidence);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: Constants coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn supply_chain_attestation_constants_are_stable() {
        assert_eq!(
            SUPPLY_CHAIN_ATTESTATION_FORMAT,
            "fcp-supply-chain-attestation"
        );
        assert_eq!(SUPPLY_CHAIN_ATTESTATION_SCHEMA_VERSION, "1.0");
        assert_eq!(
            SUPPLY_CHAIN_ATTESTATION_SCHEMA_ID,
            "fcp://schemas/supply-chain-attestation/v1"
        );
    }

    #[test]
    fn sbom_constants_are_stable() {
        assert_eq!(SBOM_FORMAT, "fcp-sbom");
        assert_eq!(SBOM_SCHEMA_VERSION, "1.0");
        assert_eq!(SBOM_SCHEMA_ID, "fcp://schemas/sbom/v1");
    }

    #[test]
    fn attestation_signed_fields_are_ordered() {
        assert_eq!(SUPPLY_CHAIN_ATTESTATION_SIGNED_FIELDS.len(), 12);
        assert_eq!(SUPPLY_CHAIN_ATTESTATION_SIGNED_FIELDS[0], "format");
        assert_eq!(
            SUPPLY_CHAIN_ATTESTATION_SIGNED_FIELDS[11],
            "builder_allowlist"
        );
    }

    #[test]
    fn sbom_signed_fields_are_ordered() {
        assert_eq!(SBOM_SIGNED_FIELDS.len(), 8);
        assert_eq!(SBOM_SIGNED_FIELDS[0], "format");
        assert_eq!(SBOM_SIGNED_FIELDS[7], "trust_root");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: CanonicalEncoding coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn canonical_encoding_clone_and_eq() {
        let cbor = CanonicalEncoding::Cbor;
        let cloned = cbor;
        assert_eq!(cbor, cloned);

        let json = CanonicalEncoding::Json;
        assert_ne!(cbor, json);
    }

    #[test]
    fn canonical_encoding_debug() {
        let dbg = format!("{:?}", CanonicalEncoding::Cbor);
        assert!(dbg.contains("Cbor"));
        let dbg = format!("{:?}", CanonicalEncoding::Json);
        assert!(dbg.contains("Json"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: HashAlgorithm serde roundtrip
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn hash_algorithm_serde_roundtrip_blake3() {
        let algo = HashAlgorithm::Blake3_256;
        let json = serde_json::to_string(&algo).unwrap();
        assert_eq!(json, "\"blake3-256\"");
        let roundtrip: HashAlgorithm = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip, algo);
    }

    #[test]
    fn hash_algorithm_serde_roundtrip_sha256() {
        let algo = HashAlgorithm::Sha256;
        let json = serde_json::to_string(&algo).unwrap();
        assert_eq!(json, "\"sha256\"");
        let roundtrip: HashAlgorithm = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip, algo);
    }

    #[test]
    fn hash_algorithm_clone_and_copy() {
        let algo = HashAlgorithm::Blake3_256;
        let copied = algo;
        assert_eq!(algo, copied);
    }

    #[test]
    fn hash_algorithm_debug() {
        let dbg = format!("{:?}", HashAlgorithm::Blake3_256);
        assert!(dbg.contains("Blake3_256"));
        let dbg = format!("{:?}", HashAlgorithm::Sha256);
        assert!(dbg.contains("Sha256"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: SbomFormat serde roundtrip
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn sbom_format_serde_roundtrip_cyclonedx() {
        let fmt = SbomFormat::Cyclonedx;
        let json = serde_json::to_string(&fmt).unwrap();
        assert_eq!(json, "\"cyclonedx\"");
        let roundtrip: SbomFormat = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip, fmt);
    }

    #[test]
    fn sbom_format_serde_roundtrip_spdx() {
        let fmt = SbomFormat::Spdx;
        let json = serde_json::to_string(&fmt).unwrap();
        assert_eq!(json, "\"spdx\"");
        let roundtrip: SbomFormat = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip, fmt);
    }

    #[test]
    fn sbom_format_debug() {
        let dbg = format!("{:?}", SbomFormat::Cyclonedx);
        assert!(dbg.contains("Cyclonedx"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: AttestationPredicateType additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn attestation_predicate_type_serde_roundtrip_slsa() {
        let pt = AttestationPredicateType::SlsaProvenanceV1;
        let json = serde_json::to_string(&pt).unwrap();
        let roundtrip: AttestationPredicateType = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip, pt);
    }

    #[test]
    fn attestation_predicate_type_serde_roundtrip_intoto() {
        let pt = AttestationPredicateType::InTotoStatementV1;
        let json = serde_json::to_string(&pt).unwrap();
        let roundtrip: AttestationPredicateType = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip, pt);
    }

    #[test]
    fn attestation_predicate_type_debug() {
        let dbg = format!("{:?}", AttestationPredicateType::SlsaProvenanceV1);
        assert!(dbg.contains("SlsaProvenanceV1"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: AttestationMaterial clone and debug
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn attestation_material_clone() {
        let mat = AttestationMaterial {
            uri: "git+https://example.com".to_string(),
            digest: format!("blake3-256:{}", "a".repeat(64)),
        };
        let cloned = mat.clone();
        assert_eq!(mat.uri, cloned.uri);
        assert_eq!(mat.digest, cloned.digest);
    }

    #[test]
    fn attestation_material_debug() {
        let mat = AttestationMaterial {
            uri: "test-uri".to_string(),
            digest: format!("blake3-256:{}", "b".repeat(64)),
        };
        let dbg = format!("{mat:?}");
        assert!(dbg.contains("test-uri"));
    }

    #[test]
    fn attestation_material_serde_roundtrip() {
        let mat = AttestationMaterial {
            uri: "git+https://example.com/repo".to_string(),
            digest: format!("blake3-256:{}", "c".repeat(64)),
        };
        let json = serde_json::to_string(&mat).unwrap();
        let roundtrip: AttestationMaterial = serde_json::from_str(&json).unwrap();
        assert_eq!(mat, roundtrip);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: AttestationMetadata edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn attestation_metadata_equal_start_finish_is_valid() {
        let ts = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).single().unwrap();
        let meta = AttestationMetadata {
            build_started_at: ts,
            build_finished_at: ts,
            invocation_id: None,
        };
        assert!(meta.validate().is_ok());
    }

    #[test]
    fn attestation_metadata_clone() {
        let meta = AttestationMetadata {
            build_started_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).single().unwrap(),
            build_finished_at: Utc.with_ymd_and_hms(2026, 1, 1, 1, 0, 0).single().unwrap(),
            invocation_id: Some("run-99".to_string()),
        };
        let cloned = meta.clone();
        assert_eq!(meta.build_started_at, cloned.build_started_at);
        assert_eq!(meta.invocation_id, cloned.invocation_id);
    }

    #[test]
    fn attestation_metadata_serde_roundtrip() {
        let meta = AttestationMetadata {
            build_started_at: Utc.with_ymd_and_hms(2026, 3, 1, 10, 0, 0).single().unwrap(),
            build_finished_at: Utc.with_ymd_and_hms(2026, 3, 1, 10, 5, 0).single().unwrap(),
            invocation_id: Some("ci-123".to_string()),
        };
        let json = serde_json::to_string(&meta).unwrap();
        let roundtrip: AttestationMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(meta, roundtrip);
    }

    #[test]
    fn attestation_metadata_serde_skips_none_invocation_id() {
        let meta = AttestationMetadata {
            build_started_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).single().unwrap(),
            build_finished_at: Utc.with_ymd_and_hms(2026, 1, 1, 1, 0, 0).single().unwrap(),
            invocation_id: None,
        };
        let json = serde_json::to_string(&meta).unwrap();
        assert!(!json.contains("invocation_id"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: TrustRootBinding coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn trust_root_binding_clone() {
        let root = TrustRootBinding {
            root_type: "tuf".to_string(),
            root_id: "tuf-root-001".to_string(),
        };
        let cloned = root.clone();
        assert_eq!(root.root_type, cloned.root_type);
        assert_eq!(root.root_id, cloned.root_id);
    }

    #[test]
    fn trust_root_binding_serde_roundtrip() {
        let root = TrustRootBinding {
            root_type: "manual".to_string(),
            root_id: "manual-root-42".to_string(),
        };
        let json = serde_json::to_string(&root).unwrap();
        let roundtrip: TrustRootBinding = serde_json::from_str(&json).unwrap();
        assert_eq!(root, roundtrip);
    }

    #[test]
    fn trust_root_binding_rejects_whitespace_only_root_id() {
        let root = TrustRootBinding {
            root_type: "sigstore".to_string(),
            root_id: "   ".to_string(),
        };
        let err = root.validate().unwrap_err();
        assert!(matches!(err, SupplyChainError::InvalidTrustRoot { .. }));
    }

    #[test]
    fn trust_root_binding_all_valid_types() {
        for rt in &["sigstore", "tuf", "manual"] {
            let root = TrustRootBinding {
                root_type: rt.to_string(),
                root_id: "test-id".to_string(),
            };
            assert!(root.validate().is_ok(), "root_type `{rt}` should be valid");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: SupplyChainSignature coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn signature_clone() {
        let sig = SupplyChainSignature::new("k1", "s1", vec!["f".to_string()]);
        let cloned = sig.clone();
        assert_eq!(sig.algorithm, cloned.algorithm);
        assert_eq!(sig.key_id, cloned.key_id);
        assert_eq!(sig.signature, cloned.signature);
        assert_eq!(sig.signed_fields, cloned.signed_fields);
    }

    #[test]
    fn signature_serde_roundtrip() {
        let sig = SupplyChainSignature::new(
            "key-abc",
            "sig-xyz",
            vec!["field_a".to_string(), "field_b".to_string()],
        );
        let json = serde_json::to_string(&sig).unwrap();
        let roundtrip: SupplyChainSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(sig, roundtrip);
    }

    #[test]
    fn signature_validate_rejects_whitespace_key_id() {
        let sig = SupplyChainSignature {
            algorithm: "ed25519".to_string(),
            key_id: "   ".to_string(),
            signature: "data".to_string(),
            signed_fields: vec!["format".to_string()],
        };
        let err = sig.validate(&["format"]).unwrap_err();
        assert!(matches!(err, SupplyChainError::InvalidSignature { .. }));
        assert!(err.to_string().contains("key_id"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: SbomComponent edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn sbom_component_accepts_sha256_hash() {
        let comp = SbomComponent {
            component_id: "comp-1".to_string(),
            name: "test-lib".to_string(),
            version: "0.1.0".to_string(),
            hashes: vec![format!("sha256:{}", "a".repeat(64))],
            licenses: vec!["MIT".to_string()],
        };
        assert!(comp.validate().is_ok());
    }

    #[test]
    fn sbom_component_accepts_mixed_hash_algorithms() {
        let comp = SbomComponent {
            component_id: "comp-2".to_string(),
            name: "mixed-lib".to_string(),
            version: "2.0.0".to_string(),
            hashes: vec![
                format!("blake3-256:{}", "b".repeat(64)),
                format!("sha256:{}", "c".repeat(64)),
            ],
            licenses: vec!["Apache-2.0".to_string()],
        };
        assert!(comp.validate().is_ok());
    }

    #[test]
    fn sbom_component_clone() {
        let comp = SbomComponent {
            component_id: "comp-3".to_string(),
            name: "cloneable".to_string(),
            version: "1.0.0".to_string(),
            hashes: vec![format!("sha256:{}", "d".repeat(64))],
            licenses: vec!["BSD-3-Clause".to_string()],
        };
        let cloned = comp.clone();
        assert_eq!(comp.component_id, cloned.component_id);
        assert_eq!(comp.name, cloned.name);
    }

    #[test]
    fn sbom_component_serde_roundtrip() {
        let comp = SbomComponent {
            component_id: "comp-rt".to_string(),
            name: "roundtrip-lib".to_string(),
            version: "3.2.1".to_string(),
            hashes: vec![format!("blake3-256:{}", "e".repeat(64))],
            licenses: vec!["MIT".to_string(), "Apache-2.0".to_string()],
        };
        let json = serde_json::to_string(&comp).unwrap();
        let roundtrip: SbomComponent = serde_json::from_str(&json).unwrap();
        assert_eq!(comp, roundtrip);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: SbomDependency coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn sbom_dependency_leaf_node_no_depends_on() {
        let dep = SbomDependency {
            component_id: "leaf".to_string(),
            depends_on: vec![],
        };
        let json = serde_json::to_string(&dep).unwrap();
        assert!(!json.contains("depends_on"));
        let roundtrip: SbomDependency = serde_json::from_str(&json).unwrap();
        assert!(roundtrip.depends_on.is_empty());
    }

    #[test]
    fn sbom_dependency_serde_roundtrip_with_deps() {
        let dep = SbomDependency {
            component_id: "parent".to_string(),
            depends_on: vec!["child-a".to_string(), "child-b".to_string()],
        };
        let json = serde_json::to_string(&dep).unwrap();
        let roundtrip: SbomDependency = serde_json::from_str(&json).unwrap();
        assert_eq!(dep, roundtrip);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: SupplyChainError coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn supply_chain_error_clone() {
        let err = SupplyChainError::InvalidAttestation {
            reason: "cloneable".to_string(),
        };
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn supply_chain_error_debug() {
        let err = SupplyChainError::CanonicalizationFailed {
            reason: "debug-test".to_string(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("CanonicalizationFailed"));
        assert!(dbg.contains("debug-test"));
    }

    #[test]
    fn supply_chain_error_eq() {
        let a = SupplyChainError::InvalidSbom {
            reason: "same".to_string(),
        };
        let b = SupplyChainError::InvalidSbom {
            reason: "same".to_string(),
        };
        let c = SupplyChainError::InvalidSbom {
            reason: "different".to_string(),
        };
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn supply_chain_error_variants_are_distinct() {
        let att = SupplyChainError::InvalidAttestation {
            reason: "x".to_string(),
        };
        let sbom = SupplyChainError::InvalidSbom {
            reason: "x".to_string(),
        };
        let sig = SupplyChainError::InvalidSignature {
            reason: "x".to_string(),
        };
        let root = SupplyChainError::InvalidTrustRoot {
            reason: "x".to_string(),
        };
        let canon = SupplyChainError::CanonicalizationFailed {
            reason: "x".to_string(),
        };
        assert_ne!(att, sbom);
        assert_ne!(sbom, sig);
        assert_ne!(sig, root);
        assert_ne!(root, canon);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: VerificationReasonCode Display for remaining variants
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn verification_reason_code_display_attestation_invalid() {
        assert_eq!(
            VerificationReasonCode::AttestationInvalid.to_string(),
            "ATTESTATION_INVALID"
        );
    }

    #[test]
    fn verification_reason_code_display_signature_invalid() {
        assert_eq!(
            VerificationReasonCode::SignatureInvalid.to_string(),
            "SIGNATURE_INVALID"
        );
    }

    #[test]
    fn verification_reason_code_display_sbom_invalid() {
        assert_eq!(
            VerificationReasonCode::SbomInvalid.to_string(),
            "SBOM_INVALID"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: VerificationReasonCode serde roundtrip for all variants
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn verification_reason_code_all_variants_serde_roundtrip() {
        let codes = [
            VerificationReasonCode::Verified,
            VerificationReasonCode::AttestationMissing,
            VerificationReasonCode::AttestationInvalid,
            VerificationReasonCode::SlsaLevelInsufficient,
            VerificationReasonCode::BuilderUntrusted,
            VerificationReasonCode::SubjectDigestMismatch,
            VerificationReasonCode::SignatureInvalid,
            VerificationReasonCode::SbomMissing,
            VerificationReasonCode::SbomInvalid,
            VerificationReasonCode::AllowedUnsigned,
        ];
        for code in codes {
            let json = serde_json::to_string(&code).unwrap();
            let roundtrip: VerificationReasonCode = serde_json::from_str(&json).unwrap();
            assert_eq!(roundtrip, code);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: VerificationStep serde roundtrip
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn verification_step_serde_roundtrip() {
        let step = VerificationStep {
            step: "test_step".to_string(),
            passed: true,
            detail: "all good".to_string(),
        };
        let json = serde_json::to_string(&step).unwrap();
        let roundtrip: VerificationStep = serde_json::from_str(&json).unwrap();
        assert_eq!(step, roundtrip);
    }

    #[test]
    fn verification_step_clone() {
        let step = VerificationStep {
            step: "clone_test".to_string(),
            passed: false,
            detail: "failed step".to_string(),
        };
        let cloned = step.clone();
        assert_eq!(step.step, cloned.step);
        assert_eq!(step.passed, cloned.passed);
        assert_eq!(step.detail, cloned.detail);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: SupplyChainVerificationPolicy coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn verification_policy_default_values() {
        let p = SupplyChainVerificationPolicy::default();
        assert!(p.require_attestation);
        assert!(p.require_sbom);
        assert_eq!(p.min_slsa_level, 0);
        assert!(p.trusted_builders.is_empty());
        assert!(!p.allow_unsigned);
        assert!(p.require_digest_match);
    }

    #[test]
    fn verification_policy_serde_roundtrip() {
        let p = SupplyChainVerificationPolicy {
            require_attestation: false,
            require_sbom: true,
            min_slsa_level: 3,
            trusted_builders: vec!["builder-a".to_string(), "builder-b".to_string()],
            allow_unsigned: true,
            require_digest_match: false,
        };
        let json = serde_json::to_string(&p).unwrap();
        let roundtrip: SupplyChainVerificationPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(p, roundtrip);
    }

    #[test]
    fn verification_policy_skips_empty_trusted_builders_in_json() {
        let p = SupplyChainVerificationPolicy::default();
        let json = serde_json::to_string(&p).unwrap();
        assert!(!json.contains("trusted_builders"));
    }

    #[test]
    fn verification_policy_clone() {
        let p = SupplyChainVerificationPolicy {
            min_slsa_level: 2,
            trusted_builders: vec!["x".to_string()],
            ..Default::default()
        };
        let cloned = p.clone();
        assert_eq!(p.min_slsa_level, cloned.min_slsa_level);
        assert_eq!(p.trusted_builders, cloned.trusted_builders);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: Pipeline additional scenarios
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn pipeline_both_missing_without_allow_unsigned() {
        let pipeline = default_pipeline();
        let evidence = pipeline.verify(&artifact_digest(), None, None);
        assert_eq!(evidence.decision, VerificationDecision::Deny);
        // First failure is attestation missing (checked before SBOM)
        assert_eq!(
            evidence.reason_code,
            VerificationReasonCode::AttestationMissing
        );
    }

    #[test]
    fn pipeline_attestation_not_required_sbom_missing() {
        let policy = SupplyChainVerificationPolicy {
            require_attestation: false,
            require_sbom: true,
            ..Default::default()
        };
        let pipeline = VerificationPipeline::new(policy);
        let evidence = pipeline.verify(&artifact_digest(), None, None);
        assert_eq!(evidence.decision, VerificationDecision::Deny);
        assert_eq!(evidence.reason_code, VerificationReasonCode::SbomMissing);
    }

    #[test]
    fn pipeline_sbom_not_required_attestation_missing() {
        let policy = SupplyChainVerificationPolicy {
            require_attestation: true,
            require_sbom: false,
            ..Default::default()
        };
        let pipeline = VerificationPipeline::new(policy);
        let evidence = pipeline.verify(&artifact_digest(), None, None);
        assert_eq!(evidence.decision, VerificationDecision::Deny);
        assert_eq!(
            evidence.reason_code,
            VerificationReasonCode::AttestationMissing
        );
    }

    #[test]
    fn pipeline_allow_unsigned_with_attestation_required_but_missing() {
        let policy = SupplyChainVerificationPolicy {
            require_attestation: true,
            require_sbom: true,
            allow_unsigned: true,
            ..Default::default()
        };
        let pipeline = VerificationPipeline::new(policy);
        let evidence = pipeline.verify(&artifact_digest(), None, None);
        // allow_unsigned overrides presence check
        assert_eq!(evidence.decision, VerificationDecision::Allow);
        assert_eq!(
            evidence.reason_code,
            VerificationReasonCode::AllowedUnsigned
        );
        assert!(evidence.steps.iter().all(|s| s.passed));
    }

    #[test]
    fn pipeline_slsa_level_exact_match_passes() {
        let policy = SupplyChainVerificationPolicy {
            min_slsa_level: 3,
            ..Default::default()
        };
        let pipeline = VerificationPipeline::new(policy);
        let att = sample_attestation(); // slsa_level = 3
        let sbom = sample_sbom();
        let evidence = pipeline.verify(&artifact_digest(), Some(&att), Some(&sbom));
        assert_eq!(evidence.decision, VerificationDecision::Allow);
    }

    #[test]
    fn pipeline_slsa_level_above_minimum_passes() {
        let policy = SupplyChainVerificationPolicy {
            min_slsa_level: 1,
            ..Default::default()
        };
        let pipeline = VerificationPipeline::new(policy);
        let att = sample_attestation(); // slsa_level = 3
        let sbom = sample_sbom();
        let evidence = pipeline.verify(&artifact_digest(), Some(&att), Some(&sbom));
        assert_eq!(evidence.decision, VerificationDecision::Allow);
    }

    #[test]
    fn pipeline_trusted_builder_match_passes() {
        let policy = SupplyChainVerificationPolicy {
            trusted_builders: vec![
                "builder://other-ci".to_string(),
                "builder://github/actions".to_string(),
            ],
            ..Default::default()
        };
        let pipeline = VerificationPipeline::new(policy);
        let att = sample_attestation();
        let sbom = sample_sbom();
        let evidence = pipeline.verify(&artifact_digest(), Some(&att), Some(&sbom));
        assert_eq!(evidence.decision, VerificationDecision::Allow);
    }

    #[test]
    fn pipeline_digest_match_disabled_allows_mismatch() {
        let policy = SupplyChainVerificationPolicy {
            require_digest_match: false,
            ..Default::default()
        };
        let pipeline = VerificationPipeline::new(policy);
        let att = sample_attestation();
        let sbom = sample_sbom();
        let wrong_digest = format!("blake3-256:{}", "z".repeat(64));
        let evidence = pipeline.verify(&wrong_digest, Some(&att), Some(&sbom));
        // No subject_digest_match step should be present
        assert_eq!(evidence.decision, VerificationDecision::Allow);
        assert!(
            !evidence
                .steps
                .iter()
                .any(|s| s.step == "subject_digest_match"),
            "should skip digest match when not required"
        );
    }

    #[test]
    fn pipeline_evidence_captures_artifact_digest() {
        let pipeline = default_pipeline();
        let att = sample_attestation();
        let sbom = sample_sbom();
        let digest = artifact_digest();
        let evidence = pipeline.verify(&digest, Some(&att), Some(&sbom));
        assert_eq!(evidence.artifact_digest, digest);
    }

    #[test]
    fn pipeline_evidence_content_hash_blake3() {
        let pipeline = default_pipeline();
        let att = sample_attestation();
        let sbom = sample_sbom();
        let evidence = pipeline.verify(&artifact_digest(), Some(&att), Some(&sbom));
        let hash = evidence.content_hash(HashAlgorithm::Blake3_256).unwrap();
        assert!(hash.starts_with("blake3-256:"));
        assert_eq!(hash.len(), "blake3-256:".len() + 64);
    }

    #[test]
    fn pipeline_evidence_content_hash_differs_for_different_decisions() {
        let pipeline = default_pipeline();
        let att = sample_attestation();
        let sbom = sample_sbom();

        let allow_evidence = pipeline.verify(&artifact_digest(), Some(&att), Some(&sbom));
        let deny_evidence = pipeline.verify(&artifact_digest(), None, None);

        let h1 = allow_evidence.content_hash(HashAlgorithm::Sha256).unwrap();
        let h2 = deny_evidence.content_hash(HashAlgorithm::Sha256).unwrap();
        assert_ne!(h1, h2);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: VerificationDecision Debug and Copy
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn verification_decision_debug() {
        let dbg = format!("{:?}", VerificationDecision::Allow);
        assert!(dbg.contains("Allow"));
        let dbg = format!("{:?}", VerificationDecision::Deny);
        assert!(dbg.contains("Deny"));
    }

    #[test]
    fn verification_decision_copy() {
        let d = VerificationDecision::Allow;
        let copied = d;
        assert_eq!(d, copied);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: Attestation content hash with different data
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn attestation_content_hash_changes_with_modified_builder() {
        let att_a = sample_attestation();
        let mut att_b = sample_attestation();
        att_b.builder_id = "builder://other-ci".to_string();
        att_b.builder_allowlist = vec!["builder://other-ci".to_string()];

        let h_a = att_a
            .content_hash(CanonicalEncoding::Json, HashAlgorithm::Blake3_256)
            .unwrap();
        let h_b = att_b
            .content_hash(CanonicalEncoding::Json, HashAlgorithm::Blake3_256)
            .unwrap();
        assert_ne!(h_a, h_b);
    }

    #[test]
    fn attestation_all_slsa_levels_valid() {
        for level in 0..=4u8 {
            let mut att = sample_attestation();
            att.slsa_level = level;
            assert!(att.validate().is_ok(), "SLSA level {level} should be valid");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: SBOM with SPDX format signing bytes differ from CycloneDX
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn sbom_signing_bytes_differ_for_different_bom_format() {
        let sbom_a = sample_sbom(); // CycloneDX
        let mut sbom_b = sample_sbom();
        sbom_b.bom_format = SbomFormat::Spdx;

        let bytes_a = sbom_a.signing_bytes().unwrap();
        let bytes_b = sbom_b.signing_bytes().unwrap();
        assert_ne!(bytes_a, bytes_b);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: Hash bytes determinism
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn hash_bytes_empty_input() {
        let blake = hash_bytes(b"", HashAlgorithm::Blake3_256);
        assert!(blake.starts_with("blake3-256:"));

        let sha = hash_bytes(b"", HashAlgorithm::Sha256);
        assert!(sha.starts_with("sha256:"));

        // Both should produce valid 64-char hex
        let blake_hex = blake.split(':').nth(1).unwrap();
        assert_eq!(blake_hex.len(), 64);
        let sha_hex = sha.split(':').nth(1).unwrap();
        assert_eq!(sha_hex.len(), 64);
    }

    #[test]
    fn hash_bytes_deterministic_same_input() {
        let input = b"determinism test data";
        let h1 = hash_bytes(input, HashAlgorithm::Blake3_256);
        let h2 = hash_bytes(input, HashAlgorithm::Blake3_256);
        assert_eq!(h1, h2);

        let h3 = hash_bytes(input, HashAlgorithm::Sha256);
        let h4 = hash_bytes(input, HashAlgorithm::Sha256);
        assert_eq!(h3, h4);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: validate_digest_with_algo edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn validate_digest_with_algo_rejects_no_colon() {
        let result = validate_digest_with_algo("nocolon", "field", HashAlgorithm::Blake3_256);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("format"));
    }

    #[test]
    fn validate_digest_with_algo_rejects_wrong_algo() {
        let digest = format!("sha256:{}", "a".repeat(64));
        let result = validate_digest_with_algo(&digest, "field", HashAlgorithm::Blake3_256);
        assert!(result.is_err());
    }

    #[test]
    fn validate_digest_with_algo_accepts_correct() {
        let digest = format!("blake3-256:{}", "a".repeat(64));
        let result = validate_digest_with_algo(&digest, "field", HashAlgorithm::Blake3_256);
        assert!(result.is_ok());

        let digest = format!("sha256:{}", "b".repeat(64));
        let result = validate_digest_with_algo(&digest, "field", HashAlgorithm::Sha256);
        assert!(result.is_ok());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: Canonicalize JSON edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn canonicalize_json_empty_object() {
        let input: Value = serde_json::from_str("{}").unwrap();
        let canonical = canonicalize_json_value(input.clone());
        assert_eq!(canonical, input);
    }

    #[test]
    fn canonicalize_json_empty_array() {
        let input: Value = serde_json::from_str("[]").unwrap();
        let canonical = canonicalize_json_value(input.clone());
        assert_eq!(canonical, input);
    }

    #[test]
    fn canonicalize_json_deeply_nested() {
        let input: Value = serde_json::from_str(r#"{"z":{"y":{"x":{"w":1}}}}"#).unwrap();
        let canonical = canonicalize_json_value(input);
        // Should still navigate all the way down
        assert_eq!(canonical["z"]["y"]["x"]["w"], 1);
    }

    #[test]
    fn canonicalize_json_array_of_objects_sorted_keys() {
        let input: Value = serde_json::from_str(r#"[{"b":2,"a":1},{"d":4,"c":3}]"#).unwrap();
        let canonical = canonicalize_json_value(input);
        let arr = canonical.as_array().unwrap();
        let keys0: Vec<&String> = arr[0].as_object().unwrap().keys().collect();
        assert_eq!(keys0, vec!["a", "b"]);
        let keys1: Vec<&String> = arr[1].as_object().unwrap().keys().collect();
        assert_eq!(keys1, vec!["c", "d"]);
    }

    #[test]
    fn canonicalize_json_number_values_preserved() {
        let input: Value = serde_json::from_str(r#"{"val":42,"neg":-1}"#).unwrap();
        let canonical = canonicalize_json_value(input);
        assert_eq!(canonical["neg"], -1);
        assert_eq!(canonical["val"], 42);
    }
}
