//! Canonical connector artifact objects for durable registry and install flows.
//!
//! These types give registry/store layers a shared `fcp-core` schema surface for
//! mirrored connector manifests, binaries, and repair descriptors.

use fcp_cbor::SchemaId;
use semver::Version;
use serde::{Deserialize, Serialize};

use crate::ObjectId;

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
        }
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

/// Canonical schema used when computing manifest signing bytes.
#[must_use]
pub fn connector_manifest_signing_view_schema() -> SchemaId {
    SchemaId::new(
        "fcp.core",
        "ConnectorManifestSigningView",
        Version::new(1, 0, 0),
    )
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
            oti: ConnectorBinaryTransmissionInfo::new(4096, 128, 1, 1, 8),
            source_symbols: 32,
            total_symbols: 48,
            mirrored_at: 1_700_000_000,
        };

        let json = serde_json::to_string(&descriptor).expect("serialize");
        let roundtrip: ConnectorBinarySymbolSet = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(roundtrip, descriptor);
    }
}
