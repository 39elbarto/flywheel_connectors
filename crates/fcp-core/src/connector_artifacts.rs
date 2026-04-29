//! Canonical connector artifact objects for durable registry and install flows.
//!
//! These types give registry/store layers a shared `fcp-core` schema surface for
//! mirrored connector manifests, binaries, and repair descriptors.

use fcp_cbor::{CanonicalSerializer, SchemaId, SerializationError};
use fcp_crypto::{Ed25519Signature, Ed25519SigningKey, Ed25519VerifyingKey, KeyId};
use semver::Version;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

use crate::{ConnectorId, FcpError, FcpResult, ObjectId};

/// Semantic version for connector manifest compatibility checks.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ManifestVersion(Version);

/// Semantic version for connector artifact ordering and compatibility checks.
pub type ConnectorVersion = ManifestVersion;

impl ManifestVersion {
    /// Parse a manifest version from its semantic-version string form.
    ///
    /// # Errors
    ///
    /// Returns [`semver::Error`] if `input` is not a valid semantic version.
    pub fn parse(input: &str) -> Result<Self, semver::Error> {
        Version::parse(input).map(Self)
    }

    /// Borrow the underlying semantic version.
    #[must_use]
    pub const fn as_semver(&self) -> &Version {
        &self.0
    }

    /// Return whether this manifest version satisfies a required version.
    ///
    /// Compatibility is intentionally stricter than plain semantic-version
    /// ordering: the major version must match exactly, and the candidate must
    /// not be lower than the required version. This accepts same-major forward
    /// evolution while rejecting cross-major changes and pre-release downgrades.
    #[must_use]
    pub fn is_compatible_with(&self, required: &Self) -> bool {
        self.0.major == required.0.major
            && !matches!(self.0.cmp(&required.0), std::cmp::Ordering::Less)
    }
}

impl From<Version> for ManifestVersion {
    fn from(version: Version) -> Self {
        Self(version)
    }
}

impl From<ManifestVersion> for Version {
    fn from(version: ManifestVersion) -> Self {
        version.0
    }
}

impl FromStr for ManifestVersion {
    type Err = semver::Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse(input)
    }
}

impl fmt::Display for ManifestVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Operating system + CPU architecture pairing.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

/// Portable transmission descriptor for mirrored connector binaries.
///
/// This intentionally mirrors the symbol-layer `OTI` fields without depending on
/// `fcp-store`, so durable descriptors can live in `fcp-core`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorBinaryTransmissionInfo {
    /// Transfer length (object size in bytes).
    pub transfer_length: u64,
    /// Symbol size in bytes.
    pub symbol_size: u16,
    /// Number of source blocks.
    pub source_blocks: u8,
    /// Number of sub-blocks.
    pub sub_blocks: u16,
    /// Symbol alignment.
    pub alignment: u8,
    /// Optional end-to-end payload hash used to reject false-positive decodes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_hash: Option<[u8; 32]>,
}

impl ConnectorBinaryTransmissionInfo {
    #[must_use]
    pub const fn new(
        transfer_length: u64,
        symbol_size: u16,
        source_blocks: u8,
        sub_blocks: u16,
        alignment: u8,
    ) -> Self {
        Self {
            transfer_length,
            symbol_size,
            source_blocks,
            sub_blocks,
            alignment,
            payload_hash: None,
        }
    }

    #[must_use]
    pub const fn with_payload_hash(mut self, payload_hash: [u8; 32]) -> Self {
        self.payload_hash = Some(payload_hash);
        self
    }
}

/// Canonical durable manifest object stored in the mesh object store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorManifestObject {
    pub manifest_toml: String,
    pub manifest_hash: String,
}

impl ConnectorManifestObject {
    /// Canonical schema identifier for mirrored connector manifests.
    #[must_use]
    pub fn schema() -> SchemaId {
        SchemaId::new("fcp.core", "ConnectorManifestObject", Version::new(1, 0, 0))
    }
}

/// Canonical durable binary object stored in the mesh object store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorBinaryObject {
    pub target: ConnectorTarget,
    pub binary_hash: String,
    pub binary: Vec<u8>,
}

impl ConnectorBinaryObject {
    /// Canonical schema identifier for mirrored connector binaries.
    #[must_use]
    pub fn schema() -> SchemaId {
        SchemaId::new("fcp.core", "ConnectorBinaryObject", Version::new(1, 0, 0))
    }
}

/// Canonical durable descriptor for a repairable binary symbol set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorBinarySymbolSet {
    pub manifest_object_id: ObjectId,
    pub binary_object_id: ObjectId,
    pub target: ConnectorTarget,
    pub binary_hash: String,
    pub encoded_body_hash: String,
    pub oti: ConnectorBinaryTransmissionInfo,
    pub source_symbols: u32,
    pub total_symbols: u32,
    pub mirrored_at: u64,
}

impl ConnectorBinarySymbolSet {
    /// Canonical schema identifier for repair descriptors.
    #[must_use]
    pub fn schema() -> SchemaId {
        SchemaId::new(
            "fcp.core",
            "ConnectorBinarySymbolSet",
            Version::new(1, 0, 0),
        )
    }
}

/// Connector bundle fetched from or emitted by a registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorBundle {
    pub manifest_toml: String,
    pub binary: Vec<u8>,
    pub target: ConnectorTarget,
}

impl ConnectorBundle {
    /// Construct a connector bundle from its manifest text, binary payload, and target.
    #[must_use]
    pub fn new(
        manifest_toml: impl Into<String>,
        binary: impl Into<Vec<u8>>,
        target: ConnectorTarget,
    ) -> Self {
        Self {
            manifest_toml: manifest_toml.into(),
            binary: binary.into(),
            target,
        }
    }
}

impl fmt::Display for ConnectorBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} connector bundle (manifest_toml={} bytes, binary={} bytes)",
            self.target.as_string(),
            self.manifest_toml.len(),
            self.binary.len()
        )
    }
}

/// Canonical registry entry for a mirrored connector package.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RegistryEntry {
    pub connector_id: ConnectorId,
    pub version: ConnectorVersion,
    pub target: ConnectorTarget,
    pub manifest_object_id: ObjectId,
    pub binary_object_id: ObjectId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbol_set_object_id: Option<ObjectId>,
}

impl RegistryEntry {
    /// Construct a registry entry for a mirrored connector package.
    #[must_use]
    pub fn new(
        connector_id: ConnectorId,
        version: ConnectorVersion,
        target: ConnectorTarget,
        manifest_object_id: ObjectId,
        binary_object_id: ObjectId,
    ) -> Self {
        Self {
            connector_id,
            version,
            target,
            manifest_object_id,
            binary_object_id,
            symbol_set_object_id: None,
        }
    }

    /// Attach the optional repair-symbol descriptor object id.
    #[must_use]
    pub fn with_symbol_set_object_id(mut self, symbol_set_object_id: ObjectId) -> Self {
        self.symbol_set_object_id = Some(symbol_set_object_id);
        self
    }
}

/// Canonical schema used when computing manifest signing bytes.
#[must_use]
pub fn connector_manifest_signing_view_schema() -> SchemaId {
    SchemaId::new(
        "fcp.core",
        "ConnectorManifestSigningView",
        Version::new(1, 0, 0),
    )
}

/// Signature domain separator for canonical signed manifests.
pub const SIGNED_MANIFEST_SIGNATURE_CONTEXT: &[u8] = b"FCP2-SIGNED-MANIFEST-V1";

/// Manifest signature algorithm tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ManifestSignature {
    /// Ed25519 manifest signature.
    Ed25519,
    /// RSA-PSS manifest signature.
    RsaPss,
    /// ECDSA P-256 manifest signature.
    EcdsaP256,
}

/// Canonical signed manifest envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedManifest<T> {
    /// Schema used to produce the canonical payload bytes.
    pub payload_schema: SchemaId,
    /// Manifest payload.
    pub payload: T,
    /// Key identifier for the signing key.
    pub signer_kid: KeyId,
    /// Ed25519 signature over the canonical payload bytes.
    pub signature: Ed25519Signature,
}

impl<T> SignedManifest<T> {
    /// Canonical schema identifier for signed manifest envelopes.
    #[must_use]
    pub fn schema() -> SchemaId {
        SchemaId::new("fcp.core", "SignedManifest", Version::new(1, 0, 0))
    }
}

impl<T: Serialize> SignedManifest<T> {
    /// Canonical bytes for the manifest payload.
    ///
    /// # Errors
    ///
    /// Returns a serialization error if the payload cannot be encoded as
    /// deterministic CBOR with the declared schema.
    pub fn canonical_payload_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        CanonicalSerializer::serialize(&self.payload, &self.payload_schema)
    }

    /// Sign a manifest payload using deterministic canonical payload bytes.
    ///
    /// # Errors
    ///
    /// Returns a serialization error if the payload cannot be encoded as
    /// deterministic CBOR with the declared schema.
    pub fn sign(
        payload_schema: SchemaId,
        payload: T,
        signing_key: &Ed25519SigningKey,
    ) -> Result<Self, SerializationError> {
        let payload_bytes = CanonicalSerializer::serialize(&payload, &payload_schema)?;
        let signature =
            signing_key.sign_with_context(SIGNED_MANIFEST_SIGNATURE_CONTEXT, &payload_bytes);

        Ok(Self {
            payload_schema,
            payload,
            signer_kid: signing_key.key_id(),
            signature,
        })
    }

    /// Verify the manifest signature against the supplied public key.
    ///
    /// # Errors
    ///
    /// Returns [`FcpError::InvalidSignature`] if the signer key id or signature
    /// does not match. Returns [`FcpError::Internal`] if the payload cannot be
    /// re-encoded for verification.
    pub fn verify(&self, verifying_key: &Ed25519VerifyingKey) -> FcpResult<()> {
        if self.signer_kid != verifying_key.key_id() {
            return Err(FcpError::InvalidSignature);
        }

        let payload_bytes = self
            .canonical_payload_bytes()
            .map_err(|err| FcpError::Internal {
                message: format!("failed to encode signed manifest payload: {err}"),
            })?;

        verifying_key
            .verify_with_context(
                SIGNED_MANIFEST_SIGNATURE_CONTEXT,
                &payload_bytes,
                &self.signature,
            )
            .map_err(|_| FcpError::InvalidSignature)
    }
}

impl<T: Serialize + DeserializeOwned> SignedManifest<T> {
    /// Serialize the signed manifest envelope using its canonical schema.
    ///
    /// # Errors
    ///
    /// Returns a serialization error if the envelope cannot be encoded.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        CanonicalSerializer::serialize(self, &Self::schema())
    }

    /// Deserialize a signed manifest envelope using its canonical schema.
    ///
    /// # Errors
    ///
    /// Returns a serialization error if the envelope is malformed, has the
    /// wrong schema hash, or is not canonically encoded.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, SerializationError> {
        CanonicalSerializer::deserialize(bytes, &Self::schema())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connector_target_from_env_is_non_empty() {
        let target = ConnectorTarget::from_env();
        assert!(!target.os.is_empty());
        assert!(!target.arch.is_empty());
    }

    #[test]
    fn artifact_schemas_use_core_namespace() {
        assert_eq!(ConnectorManifestObject::schema().namespace, "fcp.core");
        assert_eq!(ConnectorBinaryObject::schema().namespace, "fcp.core");
        assert_eq!(ConnectorBinarySymbolSet::schema().namespace, "fcp.core");
        assert_eq!(
            connector_manifest_signing_view_schema().namespace,
            "fcp.core"
        );
    }

    #[test]
    fn connector_binary_symbol_set_serde_roundtrip() {
        let descriptor = ConnectorBinarySymbolSet {
            manifest_object_id: ObjectId::from_bytes([0x11; 32]),
            binary_object_id: ObjectId::from_bytes([0x22; 32]),
            target: ConnectorTarget {
                os: "linux".into(),
                arch: "arm64".into(),
            },
            binary_hash: "sha256:abc".into(),
            encoded_body_hash: "sha256:def".into(),
            oti: ConnectorBinaryTransmissionInfo::new(4096, 128, 1, 1, 8)
                .with_payload_hash([0xAB; 32]),
            source_symbols: 32,
            total_symbols: 48,
            mirrored_at: 1_700_000_000,
        };

        let json = serde_json::to_string(&descriptor).expect("serialize");
        let roundtrip: ConnectorBinarySymbolSet = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(roundtrip, descriptor);
    }

    #[test]
    fn connector_binary_transmission_info_defaults_missing_payload_hash() {
        let json = r#"{
            "transfer_length": 4096,
            "symbol_size": 128,
            "source_blocks": 1,
            "sub_blocks": 1,
            "alignment": 8
        }"#;
        let info: ConnectorBinaryTransmissionInfo =
            serde_json::from_str(json).expect("deserialize");
        assert_eq!(
            info,
            ConnectorBinaryTransmissionInfo::new(4096, 128, 1, 1, 8)
        );
    }
}
