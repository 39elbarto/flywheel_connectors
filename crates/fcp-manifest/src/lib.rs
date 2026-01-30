//! FCP2 connector manifest parsing and validation.
//!
//! This crate provides a strict, machine-checkable interpretation of the
//! connector manifest contract in `FCP_Specification_V2.md` §11 and
//! `docs/fcp_model_connectors_rust.md` §11.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::net::IpAddr;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use fcp_core::{
    ApprovalMode as CoreApprovalMode, CapabilityId, ConnectorId, IdValidationError,
    IdempotencyClass, RateLimitDeclarationError, RateLimitDeclarations, RateLimitPool, RiskLevel,
    SafetyTier, ZoneId, ZoneIdError, validate_canonical_id,
};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

const MANIFEST_FORMAT: &str = "fcp-connector-manifest";
const INTERFACE_HASH_DOMAIN: &str = "fcp.interface.v2";

#[derive(Debug, Serialize)]
struct InterfaceDescriptorV2<'a> {
    connector_id: &'a str,
    archetypes: Vec<&'a str>,
    state: EffectiveStateModel<'a>,
    capabilities: InterfaceCapabilitiesDescriptor<'a>,
    operations: Vec<InterfaceOperationDescriptor<'a>>,
}

#[derive(Debug, Serialize)]
struct InterfaceCapabilitiesDescriptor<'a> {
    required: Vec<&'a str>,
    optional: Vec<&'a str>,
    forbidden: Vec<&'a str>,
}

#[derive(Debug, Serialize)]
struct InterfaceOperationDescriptor<'a> {
    id: &'a str,
    capability: &'a str,
    description: &'a str,
    risk_level: RiskLevel,
    safety_tier: SafetyTier,
    requires_approval: ManifestApprovalMode,
    idempotency: IdempotencyClass,
    #[serde(skip_serializing_if = "Option::is_none")]
    rate_limit: Option<&'a RateLimit>,
    input_schema: &'a serde_json::Value,
    output_schema: &'a serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    network_constraints: Option<InterfaceNetworkConstraints<'a>>,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Serialize)]
struct InterfaceNetworkConstraints<'a> {
    host_allow: Vec<&'a str>,
    port_allow: Vec<u16>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    ip_allow: Vec<IpAddr>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    cidr_deny: Vec<&'a str>,
    deny_localhost: bool,
    deny_private_ranges: bool,
    deny_tailnet_ranges: bool,
    require_sni: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    spki_pins: Vec<&'a Base64Bytes>,
    deny_ip_literals: bool,
    require_host_canonicalization: bool,
    dns_max_ips: u16,
    max_redirects: u8,
    connect_timeout_ms: u32,
    total_timeout_ms: u32,
    max_response_bytes: u64,
}

/// Connector manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorManifest {
    pub manifest: ManifestSection,
    pub connector: ConnectorSection,
    pub zones: ZonesSection,
    pub capabilities: CapabilitiesSection,
    pub provides: ProvidesSection,
    #[serde(default)]
    pub event_caps: Option<EventCapsSection>,
    pub sandbox: SandboxSection,
    #[serde(default)]
    pub rate_limits: Option<RateLimitsSection>,
    #[serde(default)]
    pub signatures: Option<SignaturesSection>,
    #[serde(default)]
    pub supply_chain: Option<SupplyChainSection>,
    #[serde(default)]
    pub policy: Option<PolicySection>,
}

impl ConnectorManifest {
    /// Parse a manifest from TOML and validate it (NORMATIVE: fail closed).
    ///
    /// # Errors
    /// Returns an error if TOML parsing fails or if validation fails.
    pub fn parse_str(input: &str) -> Result<Self, ManifestError> {
        let parsed = Self::parse_str_unchecked(input)?;
        parsed.validate()?;
        Ok(parsed)
    }

    /// Parse a manifest from TOML without validation.
    ///
    /// Useful for computing the interface hash before validation.
    ///
    /// # Errors
    /// Returns an error if TOML parsing fails.
    pub fn parse_str_unchecked(input: &str) -> Result<Self, ManifestError> {
        Ok(toml::from_str(input)?)
    }

    /// Validate the manifest for internal consistency.
    ///
    /// # Errors
    /// Returns an error if any NORMATIVE requirement is violated.
    pub fn validate(&self) -> Result<(), ManifestError> {
        self.manifest.validate()?;
        self.connector.validate()?;
        self.zones.validate()?;
        self.capabilities.validate()?;
        self.provides.validate()?;
        if let Some(ref caps) = self.event_caps {
            caps.validate()?;
        }
        self.sandbox.validate()?;
        if let Some(ref rate_limits) = self.rate_limits {
            rate_limits.validate()?;
        }
        if let Some(ref sigs) = self.signatures {
            sigs.validate()?;
        }
        if let Some(ref supply_chain) = self.supply_chain {
            supply_chain.validate()?;
        }
        if let Some(ref policy) = self.policy {
            policy.validate()?;
        }

        if self.zones.forbidden.iter().any(|z| z == &self.zones.home) {
            return Err(ManifestError::Invalid {
                field: "zones.forbidden",
                message: "home zone must not be forbidden".into(),
            });
        }

        // NORMATIVE: Host restrictions MUST NOT be encoded in capability IDs.
        // Enforce for the `network.*` capability family.
        self.capabilities.validate_no_network_host_restrictions()?;

        // Lint: reject capability IDs embedding hostnames, ports, URLs, or IPs.
        self.capabilities.validate_no_hostname_port_url_patterns()?;

        // Also lint capability IDs declared in individual operations.
        for (op_id, op) in &self.provides.operations {
            lint_capability_id_no_network_addressing(
                op.capability.as_str(),
                "provides.operations.*.capability",
            )
            .map_err(|e| ManifestError::Invalid {
                field: "provides.operations.*.capability",
                message: format!("operation `{op_id}`: {e}"),
            })?;
        }

        // NORMATIVE: interface_hash must be well-formed and match computed value.
        let expected = self.compute_interface_hash()?;
        if self.manifest.interface_hash != expected {
            return Err(ManifestError::InterfaceHashMismatch {
                expected: expected.to_string(),
                found: self.manifest.interface_hash.to_string(),
            });
        }

        Ok(())
    }

    /// Compute the deterministic interface hash from the declared API surface.
    ///
    /// This intentionally excludes supply-chain metadata (`[signatures]`,
    /// `[supply_chain]`, `[policy]`) so provenance updates do not change the
    /// connector's mechanical interface.
    ///
    /// # Errors
    /// Returns an error if canonical serialization fails.
    #[allow(clippy::too_many_lines)]
    pub fn compute_interface_hash(&self) -> Result<InterfaceHash, ManifestError> {
        let mut archetypes: Vec<&str> = self
            .connector
            .archetypes
            .iter()
            .map(ConnectorArchetype::as_str)
            .collect();
        archetypes.sort_unstable();
        archetypes.dedup();

        let state = self.connector.effective_state_model()?;

        let mut required: Vec<&str> = self
            .capabilities
            .required
            .iter()
            .map(CapabilityId::as_str)
            .collect();
        required.sort_unstable();
        required.dedup();

        let mut optional: Vec<&str> = self
            .capabilities
            .optional
            .iter()
            .map(CapabilityId::as_str)
            .collect();
        optional.sort_unstable();
        optional.dedup();

        let mut forbidden: Vec<&str> = self
            .capabilities
            .forbidden
            .iter()
            .map(CapabilityId::as_str)
            .collect();
        forbidden.sort_unstable();
        forbidden.dedup();

        let mut operations: Vec<InterfaceOperationDescriptor<'_>> = self
            .provides
            .operations
            .iter()
            .map(|(id, op)| {
                let network_constraints = op.network_constraints.as_ref().map(|nc| {
                    let mut host_allow: Vec<&str> =
                        nc.host_allow.iter().map(String::as_str).collect();
                    host_allow.sort_unstable();

                    let mut port_allow = nc.port_allow.clone();
                    port_allow.sort_unstable();

                    let mut ip_allow = nc.ip_allow.clone();
                    ip_allow.sort_unstable();

                    let mut cidr_deny: Vec<&str> =
                        nc.cidr_deny.iter().map(String::as_str).collect();
                    cidr_deny.sort_unstable();

                    let mut spki_pins: Vec<&Base64Bytes> = nc.spki_pins.iter().collect();
                    spki_pins.sort_unstable();

                    InterfaceNetworkConstraints {
                        host_allow,
                        port_allow,
                        ip_allow,
                        cidr_deny,
                        deny_localhost: nc.deny_localhost,
                        deny_private_ranges: nc.deny_private_ranges,
                        deny_tailnet_ranges: nc.deny_tailnet_ranges,
                        require_sni: nc.require_sni,
                        spki_pins,
                        deny_ip_literals: nc.deny_ip_literals,
                        require_host_canonicalization: nc.require_host_canonicalization,
                        dns_max_ips: nc.dns_max_ips,
                        max_redirects: nc.max_redirects,
                        connect_timeout_ms: nc.connect_timeout_ms,
                        total_timeout_ms: nc.total_timeout_ms,
                        max_response_bytes: nc.max_response_bytes,
                    }
                });

                InterfaceOperationDescriptor {
                    id,
                    capability: op.capability.as_str(),
                    description: op.description.as_str(),
                    risk_level: op.risk_level,
                    safety_tier: op.safety_tier,
                    requires_approval: op.requires_approval,
                    idempotency: op.idempotency,
                    rate_limit: op.rate_limit.as_ref(),
                    input_schema: &op.input_schema,
                    output_schema: &op.output_schema,
                    network_constraints,
                }
            })
            .collect();
        operations.sort_unstable_by(|a, b| a.id.cmp(b.id));

        let descriptor = InterfaceDescriptorV2 {
            connector_id: self.connector.id.as_str(),
            archetypes,
            state,
            capabilities: InterfaceCapabilitiesDescriptor {
                required,
                optional,
                forbidden,
            },
            operations,
        };

        let canonical = fcp_cbor::to_canonical_cbor(&descriptor)?;
        let mut h = blake3::Hasher::new();
        h.update(b"FCP2-INTERFACE-V1");
        h.update(&canonical);
        Ok(InterfaceHash::new_blake3_256(
            INTERFACE_HASH_DOMAIN,
            *h.finalize().as_bytes(),
        ))
    }
}

/// Errors returned by manifest parsing/validation.
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("failed to parse manifest TOML: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("invalid identifier: {0}")]
    Id(#[from] IdValidationError),

    #[error("invalid zone id: {0}")]
    ZoneId(#[from] ZoneIdError),

    #[error("invalid canonical CBOR: {0}")]
    CanonicalCbor(#[from] fcp_cbor::SerializationError),

    #[error("invalid manifest field `{field}`: {message}")]
    Invalid {
        field: &'static str,
        message: String,
    },

    #[error("interface hash mismatch (expected {expected}, found {found})")]
    InterfaceHashMismatch { expected: String, found: String },

    #[error("invalid rate limit: {0}")]
    RateLimit(#[from] fcp_core::RateLimitValidationError),

    #[error("invalid rate limit declaration: {0}")]
    RateLimitDeclaration(#[from] RateLimitDeclarationError),
}

/// `[manifest]` section (NORMATIVE).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestSection {
    pub format: String,
    pub schema_version: ManifestSchemaVersion,
    pub min_mesh_version: semver::Version,
    pub min_protocol: ProtocolRequirement,
    #[serde(default)]
    pub protocol_features: Vec<FeatureId>,
    pub max_datagram_bytes: u16,
    pub interface_hash: InterfaceHash,
}

impl ManifestSection {
    fn validate(&self) -> Result<(), ManifestError> {
        if self.format != MANIFEST_FORMAT {
            return Err(ManifestError::Invalid {
                field: "manifest.format",
                message: format!("must be `{MANIFEST_FORMAT}`"),
            });
        }

        if self.schema_version.major != 2 {
            return Err(ManifestError::Invalid {
                field: "manifest.schema_version",
                message: "unsupported manifest schema major version".into(),
            });
        }

        if self.max_datagram_bytes == 0 {
            return Err(ManifestError::Invalid {
                field: "manifest.max_datagram_bytes",
                message: "must be > 0".into(),
            });
        }

        Ok(())
    }
}

/// Manifest schema version as `MAJOR.MINOR` (e.g., `"2.1"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ManifestSchemaVersion {
    pub major: u16,
    pub minor: u16,
}

impl fmt::Display for ManifestSchemaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

impl TryFrom<String> for ManifestSchemaVersion {
    type Error = ManifestError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let (major, minor) = value
            .split_once('.')
            .ok_or_else(|| ManifestError::Invalid {
                field: "manifest.schema_version",
                message: "must be in MAJOR.MINOR format".into(),
            })?;
        let major: u16 = major.parse().map_err(|_| ManifestError::Invalid {
            field: "manifest.schema_version",
            message: "major version must be an integer".into(),
        })?;
        let minor: u16 = minor.parse().map_err(|_| ManifestError::Invalid {
            field: "manifest.schema_version",
            message: "minor version must be an integer".into(),
        })?;
        Ok(Self { major, minor })
    }
}

impl From<ManifestSchemaVersion> for String {
    fn from(value: ManifestSchemaVersion) -> Self {
        value.to_string()
    }
}

impl<'de> Deserialize<'de> for ManifestSchemaVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::try_from(s).map_err(serde::de::Error::custom)
    }
}

impl Serialize for ManifestSchemaVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

/// Minimum protocol requirement (NORMATIVE): `name/MAJOR.MINOR`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProtocolRequirement {
    pub name: String,
    pub version: ProtocolVersion,
}

impl fmt::Display for ProtocolRequirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.name, self.version)
    }
}

impl TryFrom<String> for ProtocolRequirement {
    type Error = ManifestError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let (name, version) = value
            .split_once('/')
            .ok_or_else(|| ManifestError::Invalid {
                field: "manifest.min_protocol",
                message: "must include a version component (e.g. \"fcp2-sym/2.0\")".into(),
            })?;
        if name.is_empty() {
            return Err(ManifestError::Invalid {
                field: "manifest.min_protocol",
                message: "protocol name must not be empty".into(),
            });
        }
        Ok(Self {
            name: name.to_string(),
            version: ProtocolVersion::try_from(version.to_string())?,
        })
    }
}

impl From<ProtocolRequirement> for String {
    fn from(value: ProtocolRequirement) -> Self {
        value.to_string()
    }
}

impl<'de> Deserialize<'de> for ProtocolRequirement {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::try_from(s).map_err(serde::de::Error::custom)
    }
}

impl Serialize for ProtocolRequirement {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

/// Protocol version as `MAJOR.MINOR` (e.g., `"2.0"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

impl TryFrom<String> for ProtocolVersion {
    type Error = ManifestError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let (major, minor) = value
            .split_once('.')
            .ok_or_else(|| ManifestError::Invalid {
                field: "manifest.min_protocol",
                message: "protocol version must be in MAJOR.MINOR format".into(),
            })?;
        let major: u16 = major.parse().map_err(|_| ManifestError::Invalid {
            field: "manifest.min_protocol",
            message: "protocol major version must be an integer".into(),
        })?;
        let minor: u16 = minor.parse().map_err(|_| ManifestError::Invalid {
            field: "manifest.min_protocol",
            message: "protocol minor version must be an integer".into(),
        })?;
        Ok(Self { major, minor })
    }
}

/// Canonical feature identifier (validated using the canonical id rules).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FeatureId(String);

impl FeatureId {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for FeatureId {
    type Error = ManifestError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        validate_canonical_id(&value)?;
        Ok(Self(value))
    }
}

impl From<FeatureId> for String {
    fn from(value: FeatureId) -> Self {
        value.0
    }
}

impl<'de> Deserialize<'de> for FeatureId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::try_from(s).map_err(serde::de::Error::custom)
    }
}

impl Serialize for FeatureId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

/// Interface hash (NORMATIVE): `algorithm:domain:digest_hex`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InterfaceHash {
    pub algorithm: InterfaceHashAlgorithm,
    pub domain: &'static str,
    pub digest: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InterfaceHashAlgorithm {
    Blake3_256,
}

impl InterfaceHash {
    #[must_use]
    pub const fn new_blake3_256(domain: &'static str, digest: [u8; 32]) -> Self {
        Self {
            algorithm: InterfaceHashAlgorithm::Blake3_256,
            domain,
            digest,
        }
    }
}

impl fmt::Display for InterfaceHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let algorithm = match self.algorithm {
            InterfaceHashAlgorithm::Blake3_256 => "blake3-256",
        };
        write!(
            f,
            "{}:{}:{}",
            algorithm,
            self.domain,
            hex::encode(self.digest)
        )
    }
}

impl TryFrom<String> for InterfaceHash {
    type Error = ManifestError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let mut parts = value.splitn(3, ':');
        let algorithm = parts.next().unwrap_or_default();
        let domain = parts.next().unwrap_or_default();
        let digest = parts.next().unwrap_or_default();

        let algorithm = match algorithm {
            "blake3-256" => InterfaceHashAlgorithm::Blake3_256,
            _ => {
                return Err(ManifestError::Invalid {
                    field: "manifest.interface_hash",
                    message: "unsupported interface hash algorithm".into(),
                });
            }
        };

        if domain != INTERFACE_HASH_DOMAIN {
            return Err(ManifestError::Invalid {
                field: "manifest.interface_hash",
                message: format!("unsupported interface hash domain `{domain}`"),
            });
        }

        if digest.chars().any(|c| c.is_ascii_uppercase()) {
            return Err(ManifestError::Invalid {
                field: "manifest.interface_hash",
                message: "digest must be lowercase hex".into(),
            });
        }

        let digest_bytes = hex::decode(digest).map_err(|_| ManifestError::Invalid {
            field: "manifest.interface_hash",
            message: "digest must be valid hex".into(),
        })?;
        let digest: [u8; 32] = digest_bytes
            .try_into()
            .map_err(|_| ManifestError::Invalid {
                field: "manifest.interface_hash",
                message: "digest must be 32 bytes (64 hex chars)".into(),
            })?;

        Ok(Self {
            algorithm,
            domain: INTERFACE_HASH_DOMAIN,
            digest,
        })
    }
}

impl From<InterfaceHash> for String {
    fn from(value: InterfaceHash) -> Self {
        value.to_string()
    }
}

impl<'de> Deserialize<'de> for InterfaceHash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::try_from(s).map_err(serde::de::Error::custom)
    }
}

impl Serialize for InterfaceHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

/// `[connector]` section.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorSection {
    pub id: ConnectorId,
    pub name: String,
    pub version: semver::Version,
    pub description: String,
    pub archetypes: Vec<ConnectorArchetype>,
    pub format: ConnectorRuntimeFormat,
    #[serde(default)]
    pub singleton_writer: Option<bool>,
    #[serde(default)]
    pub state: Option<ConnectorStateSection>,
}

impl ConnectorSection {
    fn validate(&self) -> Result<(), ManifestError> {
        if self.name.trim().is_empty() {
            return Err(ManifestError::Invalid {
                field: "connector.name",
                message: "must not be empty".into(),
            });
        }
        if self.description.trim().is_empty() {
            return Err(ManifestError::Invalid {
                field: "connector.description",
                message: "must not be empty".into(),
            });
        }
        if self.archetypes.is_empty() {
            return Err(ManifestError::Invalid {
                field: "connector.archetypes",
                message: "must list at least one archetype".into(),
            });
        }

        // Validate state model consistency (legacy singleton_writer flag).
        let _ = self.effective_state_model()?;
        Ok(())
    }

    fn effective_state_model(&self) -> Result<EffectiveStateModel<'_>, ManifestError> {
        let legacy_singleton = self.singleton_writer.unwrap_or(false);
        let Some(ref state) = self.state else {
            return Ok(if legacy_singleton {
                EffectiveStateModel::SingletonWriter {
                    state_schema_version: None,
                    migration_hint: None,
                    crdt_type: None,
                    snapshot_every_updates: None,
                    snapshot_every_bytes: None,
                }
            } else {
                EffectiveStateModel::Stateless
            });
        };

        state.validate()?;

        if legacy_singleton && state.model != StateModelKind::SingletonWriter {
            return Err(ManifestError::Invalid {
                field: "connector.singleton_writer",
                message: "conflicts with connector.state.model (must be singleton_writer)".into(),
            });
        }

        // Convert TOML model + crdt_type to rich ConnectorStateModel
        let model = state.to_state_model()?;

        Ok(match model {
            ConnectorStateModel::Stateless => EffectiveStateModel::Stateless,
            ConnectorStateModel::SingletonWriter => EffectiveStateModel::SingletonWriter {
                state_schema_version: Some(state.state_schema_version.as_str()),
                migration_hint: state.migration_hint.as_deref(),
                crdt_type: None,
                snapshot_every_updates: None,
                snapshot_every_bytes: None,
            },
            ConnectorStateModel::Crdt { crdt_type } => EffectiveStateModel::Crdt {
                state_schema_version: Some(state.state_schema_version.as_str()),
                migration_hint: state.migration_hint.as_deref(),
                crdt_type: Some(crdt_type.as_str()),
                snapshot_every_updates: state.snapshot_every_updates,
                snapshot_every_bytes: state.snapshot_every_bytes,
            },
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorArchetype {
    Bidirectional,
    Streaming,
    Operational,
    Storage,
    Knowledge,
}

impl ConnectorArchetype {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Bidirectional => "bidirectional",
            Self::Streaming => "streaming",
            Self::Operational => "operational",
            Self::Storage => "storage",
            Self::Knowledge => "knowledge",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorRuntimeFormat {
    Native,
    Wasi,
}

/// Simple state model kind for TOML parsing (unit variants only).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StateModelKind {
    Stateless,
    SingletonWriter,
    Crdt,
}

/// Connector state section `[connector.state]` (model-guide aligned).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorStateSection {
    model: StateModelKind,
    pub state_schema_version: String,
    #[serde(default)]
    pub migration_hint: Option<String>,
    #[serde(default)]
    pub crdt_type: Option<ConnectorCrdtType>,
    #[serde(default)]
    pub snapshot_every_updates: Option<u64>,
    #[serde(default)]
    pub snapshot_every_bytes: Option<u64>,
}

impl ConnectorStateSection {
    fn validate(&self) -> Result<(), ManifestError> {
        if self.state_schema_version.trim().is_empty() {
            return Err(ManifestError::Invalid {
                field: "connector.state.state_schema_version",
                message: "must not be empty".into(),
            });
        }
        Ok(())
    }

    /// Convert to the public `ConnectorStateModel` enum.
    ///
    /// # Errors
    ///
    /// Returns `ManifestError::Invalid` if `model` is `Crdt` but `crdt_type` is `None`.
    pub fn to_state_model(&self) -> Result<ConnectorStateModel, ManifestError> {
        match self.model {
            StateModelKind::Stateless => Ok(ConnectorStateModel::Stateless),
            StateModelKind::SingletonWriter => Ok(ConnectorStateModel::SingletonWriter),
            StateModelKind::Crdt => {
                let crdt_type = self.crdt_type.ok_or_else(|| ManifestError::Invalid {
                    field: "connector.state.crdt_type",
                    message: "required when model = \"crdt\"".into(),
                })?;
                Ok(ConnectorStateModel::Crdt { crdt_type })
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ConnectorStateModel {
    /// No persistent state.
    #[default]
    Stateless,
    /// Single-writer with lease-based fencing.
    SingletonWriter,
    /// CRDT-based collaborative state.
    Crdt {
        /// The CRDT type determining merge semantics.
        crdt_type: ConnectorCrdtType,
    },
}

impl ConnectorStateModel {
    /// Returns `true` if this is the stateless model.
    #[must_use]
    pub const fn is_stateless(&self) -> bool {
        matches!(self, Self::Stateless)
    }

    /// Returns `true` if this is the singleton-writer model.
    #[must_use]
    pub const fn is_singleton_writer(&self) -> bool {
        matches!(self, Self::SingletonWriter)
    }

    /// Returns `true` if this is a CRDT model.
    #[must_use]
    pub const fn is_crdt(&self) -> bool {
        matches!(self, Self::Crdt { .. })
    }

    /// Returns the CRDT type if this is a CRDT model.
    #[must_use]
    pub const fn crdt_type(&self) -> Option<ConnectorCrdtType> {
        match self {
            Self::Crdt { crdt_type } => Some(*crdt_type),
            _ => None,
        }
    }
}

impl std::fmt::Display for ConnectorStateModel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stateless => write!(f, "stateless"),
            Self::SingletonWriter => write!(f, "singleton_writer"),
            Self::Crdt { crdt_type } => write!(f, "crdt({})", crdt_type.as_str()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorCrdtType {
    /// Last-writer-wins map.
    LwwMap,
    /// Observed-remove set.
    OrSet,
    /// Grow-only counter.
    GCounter,
    /// Positive-negative counter.
    PnCounter,
}

impl ConnectorCrdtType {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::LwwMap => "lww_map",
            Self::OrSet => "or_set",
            Self::GCounter => "g_counter",
            Self::PnCounter => "pn_counter",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(tag = "model", rename_all = "snake_case")]
enum EffectiveStateModel<'a> {
    Stateless,
    SingletonWriter {
        #[serde(skip_serializing_if = "Option::is_none")]
        state_schema_version: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        migration_hint: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        crdt_type: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        snapshot_every_updates: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        snapshot_every_bytes: Option<u64>,
    },
    Crdt {
        #[serde(skip_serializing_if = "Option::is_none")]
        state_schema_version: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        migration_hint: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        crdt_type: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        snapshot_every_updates: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        snapshot_every_bytes: Option<u64>,
    },
}

/// `[zones]` section.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZonesSection {
    pub home: ZoneId,
    #[serde(default)]
    pub allowed_sources: Vec<ZoneId>,
    #[serde(default)]
    pub allowed_targets: Vec<ZoneId>,
    #[serde(default)]
    pub forbidden: Vec<ZoneId>,
}

impl ZonesSection {
    fn validate(&self) -> Result<(), ManifestError> {
        if self.home.as_str().is_empty() {
            return Err(ManifestError::Invalid {
                field: "zones.home",
                message: "must not be empty".into(),
            });
        }
        Ok(())
    }
}

/// `[capabilities]` section.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitiesSection {
    #[serde(default)]
    pub required: Vec<CapabilityId>,
    #[serde(default)]
    pub optional: Vec<CapabilityId>,
    #[serde(default)]
    pub forbidden: Vec<CapabilityId>,
}

impl CapabilitiesSection {
    fn validate(&self) -> Result<(), ManifestError> {
        let mut seen = HashSet::new();
        for (field, caps) in [
            ("capabilities.required", &self.required),
            ("capabilities.optional", &self.optional),
            ("capabilities.forbidden", &self.forbidden),
        ] {
            for cap in caps {
                let inserted = seen.insert(cap.as_str().to_owned());
                if !inserted {
                    return Err(ManifestError::Invalid {
                        field,
                        message: format!("duplicate capability id `{}`", cap.as_str()),
                    });
                }
            }
        }
        let exec_forbidden = self
            .forbidden
            .iter()
            .any(|cap| cap.as_str() == "system.exec");
        if !exec_forbidden {
            return Err(ManifestError::Invalid {
                field: "capabilities.forbidden",
                message: "must include system.exec (default-deny execution)".into(),
            });
        }
        Ok(())
    }

    fn validate_no_network_host_restrictions(&self) -> Result<(), ManifestError> {
        for (field, caps) in [
            ("capabilities.required", &self.required),
            ("capabilities.optional", &self.optional),
            ("capabilities.forbidden", &self.forbidden),
        ] {
            for cap in caps {
                let s = cap.as_str();
                if s.starts_with("network.") && s.contains(':') {
                    return Err(ManifestError::Invalid {
                        field,
                        message: format!(
                            "network capability id `{s}` appears to encode host restrictions; use `network_constraints` instead"
                        ),
                    });
                }
            }
        }
        Ok(())
    }

    /// Lint: reject capability IDs that embed hostnames, ports, or URL-like
    /// patterns. FCP2 requires that all network addressing live in
    /// `network_constraints`, not in capability identifiers.
    ///
    /// Detected patterns:
    /// - URL schemes: `http:`, `https:`, `ftp:`, `ws:`, `wss:`
    /// - Port suffixes: `:<digits>` (2–5 digits resembling a TCP/UDP port)
    /// - Hostname TLD endings: `.com`, `.org`, `.net`, `.edu`, `.gov`, `.mil`
    /// - IPv4 address fragments: four consecutive all-digit dot-segments
    fn validate_no_hostname_port_url_patterns(&self) -> Result<(), ManifestError> {
        for (field, caps) in [
            ("capabilities.required", &self.required),
            ("capabilities.optional", &self.optional),
            ("capabilities.forbidden", &self.forbidden),
        ] {
            for cap in caps {
                lint_capability_id_no_network_addressing(cap.as_str(), field)?;
            }
        }
        Ok(())
    }
}

/// Well-known TLDs that are unlikely to appear as legitimate capability
/// namespace segments. Kept deliberately conservative to avoid false positives.
const KNOWN_TLDS: &[&str] = &["com", "org", "net", "edu", "gov", "mil"];

/// URL schemes that must never appear at the start of a capability ID.
const URL_SCHEMES: &[&str] = &["http:", "https:", "ftp:", "ws:", "wss:"];

/// Check a single capability ID for network-addressing patterns.
///
/// Returns `Ok(())` when the ID looks like a clean capability namespace
/// (e.g. `telegram.send_message`, `network.egress`). Returns an error when
/// the ID embeds hostnames, ports, URL schemes, or IP addresses.
fn lint_capability_id_no_network_addressing(
    id: &str,
    field: &'static str,
) -> Result<(), ManifestError> {
    // 1. URL scheme prefix
    for scheme in URL_SCHEMES {
        if id.starts_with(scheme) {
            return Err(ManifestError::Invalid {
                field,
                message: format!(
                    "capability id `{id}` contains URL scheme `{scheme}`; \
                     network addressing belongs in `network_constraints`"
                ),
            });
        }
    }

    let segments: Vec<&str> = id.split('.').collect();

    // 2. Port-like suffix: colon followed by 2–5 digits within any segment.
    for segment in &segments {
        if let Some(colon_idx) = segment.rfind(':') {
            let after = &segment[colon_idx + 1..];
            if (2..=5).contains(&after.len()) && after.bytes().all(|b| b.is_ascii_digit()) {
                if let Ok(port) = after.parse::<u32>() {
                    if port > 0 && port <= 65535 {
                        return Err(ManifestError::Invalid {
                            field,
                            message: format!(
                                "capability id `{id}` contains port number `:{after}`; \
                                 network addressing belongs in `network_constraints`"
                            ),
                        });
                    }
                }
            }
        }
    }

    // 3. Hostname TLD ending: the last dot-segment (ignoring any trailing
    //    port) matches a well-known TLD and there are at least 2 segments.
    if segments.len() >= 2 {
        let last = segments[segments.len() - 1];
        // Strip trailing port if present (e.g. "org:443" → "org")
        let tld_candidate = last.split(':').next().unwrap_or(last);
        if KNOWN_TLDS.contains(&tld_candidate) {
            return Err(ManifestError::Invalid {
                field,
                message: format!(
                    "capability id `{id}` appears to contain a hostname \
                     (ends with `.{tld_candidate}`); \
                     network addressing belongs in `network_constraints`"
                ),
            });
        }
    }

    // 4. IPv4 address pattern: four consecutive all-digit segments (1–3 chars each).
    if segments.len() >= 4 {
        for window in segments.windows(4) {
            if window
                .iter()
                .all(|s| !s.is_empty() && s.len() <= 3 && s.bytes().all(|b| b.is_ascii_digit()))
            {
                return Err(ManifestError::Invalid {
                    field,
                    message: format!(
                        "capability id `{id}` appears to contain an IPv4 address; \
                         network addressing belongs in `network_constraints`"
                    ),
                });
            }
        }
    }

    Ok(())
}

/// `[provides]` section.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvidesSection {
    pub operations: BTreeMap<String, OperationSection>,
}

impl ProvidesSection {
    fn validate(&self) -> Result<(), ManifestError> {
        if self.operations.is_empty() {
            return Err(ManifestError::Invalid {
                field: "provides.operations",
                message: "must declare at least one operation".into(),
            });
        }
        for (op_id, op) in &self.operations {
            validate_canonical_id(op_id)?;
            op.validate()?;
        }
        Ok(())
    }
}

/// `[provides.operations.<id>]` section.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationSection {
    pub description: String,
    pub capability: CapabilityId,
    pub risk_level: RiskLevel,
    pub safety_tier: SafetyTier,
    pub requires_approval: ManifestApprovalMode,
    pub rate_limit: Option<RateLimit>,
    pub idempotency: IdempotencyClass,
    pub input_schema: serde_json::Value,
    pub output_schema: serde_json::Value,
    #[serde(default)]
    pub network_constraints: Option<NetworkConstraints>,
    #[serde(default)]
    pub ai_hints: fcp_core::AgentHint,
}

impl OperationSection {
    fn validate(&self) -> Result<(), ManifestError> {
        if self.description.trim().is_empty() {
            return Err(ManifestError::Invalid {
                field: "provides.operations.*.description",
                message: "must not be empty".into(),
            });
        }
        if let Some(ref rate_limit) = self.rate_limit {
            rate_limit.as_inner().validate()?;
        }
        if let Some(ref nc) = self.network_constraints {
            nc.validate()?;
        }
        Ok(())
    }
}

/// Approval mode as expressed in manifests.
///
/// Note: the spec historically used `"approval_required"`; the core currently uses
/// `"elevation_token"`. This type accepts both and normalizes deterministically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestApprovalMode {
    None,
    Policy,
    Interactive,
    ElevationToken,
}

impl From<ManifestApprovalMode> for CoreApprovalMode {
    fn from(value: ManifestApprovalMode) -> Self {
        match value {
            ManifestApprovalMode::None => Self::None,
            ManifestApprovalMode::Policy => Self::Policy,
            ManifestApprovalMode::Interactive => Self::Interactive,
            ManifestApprovalMode::ElevationToken => Self::ElevationToken,
        }
    }
}

impl<'de> Deserialize<'de> for ManifestApprovalMode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "none" => Ok(Self::None),
            "policy" => Ok(Self::Policy),
            "interactive" => Ok(Self::Interactive),
            "elevation_token" | "approval_required" => Ok(Self::ElevationToken),
            _ => Err(serde::de::Error::custom(
                "invalid approval mode (expected: none|policy|interactive|elevation_token)",
            )),
        }
    }
}

/// Rate limit (manifest-friendly).
///
/// Supports either a shorthand string (e.g. `"60/min"`) or a structured object matching
/// `fcp_core::RateLimit`. The value is normalized to the structured form for hashing.
#[derive(Debug, Clone)]
pub struct RateLimit(pub fcp_core::RateLimit);

impl RateLimit {
    #[must_use]
    pub const fn as_inner(&self) -> &fcp_core::RateLimit {
        &self.0
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RateLimitRepr {
    Shorthand(String),
    Structured(fcp_core::RateLimit),
}

impl<'de> Deserialize<'de> for RateLimit {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let repr = RateLimitRepr::deserialize(deserializer)?;
        let rate = match repr {
            RateLimitRepr::Shorthand(s) => parse_rate_limit_shorthand(&s)
                .map_err(|e| serde::de::Error::custom(format!("invalid rate_limit: {e}")))?,
            RateLimitRepr::Structured(v) => v,
        };
        Ok(Self(rate))
    }
}

impl Serialize for RateLimit {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

fn parse_rate_limit_shorthand(input: &str) -> Result<fcp_core::RateLimit, &'static str> {
    let (max, unit) = input
        .split_once('/')
        .ok_or("expected format like \"60/min\"")?;
    let max: u32 = max.parse().map_err(|_| "max must be an integer")?;
    let per_ms = match unit {
        "sec" | "s" => 1_000_u64,
        "min" | "m" => 60_000_u64,
        "hour" | "h" => 3_600_000_u64,
        "day" | "d" => 86_400_000_u64,
        _ => return Err("unknown period unit (expected sec|min|hour|day)"),
    };
    Ok(fcp_core::RateLimit {
        max,
        per_ms,
        burst: None,
        scope: None,
        pool_name: None,
    })
}

/// `[event_caps]` section.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventCapsSection {
    pub streaming: bool,
    pub replay: bool,
    pub min_buffer_events: u32,
}

impl EventCapsSection {
    fn validate(&self) -> Result<(), ManifestError> {
        if self.streaming && self.min_buffer_events == 0 {
            return Err(ManifestError::Invalid {
                field: "event_caps.min_buffer_events",
                message: "must be > 0 when streaming is enabled".into(),
            });
        }
        Ok(())
    }
}

/// `[rate_limits]` section for connector-level rate limit pool declarations.
///
/// Defines named rate limit pools that can be referenced by operations to share
/// quota buckets across multiple operations.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitsSection {
    /// Named rate limit pools with configuration.
    #[serde(default)]
    pub pools: Vec<RateLimitPoolSection>,
    /// Map of operation names to pool IDs they consume.
    /// Operations can consume from multiple pools (e.g., both RPM and token limits).
    #[serde(default)]
    pub operation_pools: std::collections::HashMap<String, Vec<String>>,
}

impl RateLimitsSection {
    fn validate(&self) -> Result<(), ManifestError> {
        // Convert to fcp_core declarations and validate
        let decls = self.to_declarations();
        decls.validate()?;
        Ok(())
    }

    /// Convert to the canonical `RateLimitDeclarations` type.
    #[must_use]
    pub fn to_declarations(&self) -> RateLimitDeclarations {
        use fcp_core::{RateLimitConfig, RateLimitEnforcement, RateLimitScope, RateLimitUnit};
        use std::time::Duration;

        let limits =
            self.pools
                .iter()
                .map(|pool| RateLimitPool {
                    id: pool.id.clone(),
                    description: pool.description.clone().unwrap_or_default(),
                    config: RateLimitConfig {
                        requests: pool.requests,
                        window: Duration::from_millis(pool.window_ms),
                        burst: pool.burst,
                        unit: pool.unit.as_ref().map_or(RateLimitUnit::Requests, |u| {
                            match u.as_str() {
                                "tokens" => RateLimitUnit::Tokens,
                                "bytes" => RateLimitUnit::Bytes,
                                "custom" => RateLimitUnit::Custom,
                                _ => RateLimitUnit::Requests,
                            }
                        }),
                    },
                    enforcement: pool.enforcement.as_ref().map_or(
                        RateLimitEnforcement::Hard,
                        |e| match e.as_str() {
                            "soft" => RateLimitEnforcement::Soft,
                            "advisory" => RateLimitEnforcement::Advisory,
                            _ => RateLimitEnforcement::Hard,
                        },
                    ),
                    scope: pool.scope.as_ref().map_or(RateLimitScope::Instance, |s| {
                        match s.as_str() {
                            "credential" => RateLimitScope::Credential,
                            "global" => RateLimitScope::Global,
                            _ => RateLimitScope::Instance,
                        }
                    }),
                })
                .collect();

        RateLimitDeclarations {
            limits,
            tool_pool_map: self.operation_pools.clone(),
        }
    }
}

/// A rate limit pool declaration in TOML-friendly format.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitPoolSection {
    /// Unique identifier for this pool (e.g., `api_global`, `openai_tokens`).
    pub id: String,
    /// Human-readable description.
    #[serde(default)]
    pub description: Option<String>,
    /// Maximum requests/tokens/bytes per window (bucket size). Must be > 0.
    pub requests: u32,
    /// Window duration in milliseconds. Must be > 0.
    pub window_ms: u64,
    /// Optional burst allowance (tokens above max that can accumulate).
    #[serde(default)]
    pub burst: Option<u32>,
    /// Unit of measurement: "requests" (default), "tokens", "bytes", "custom".
    #[serde(default)]
    pub unit: Option<String>,
    /// Enforcement: "hard" (default), "soft", "advisory".
    #[serde(default)]
    pub enforcement: Option<String>,
    /// Scope: "instance" (default), "credential", "global".
    #[serde(default)]
    pub scope: Option<String>,
}

/// `[sandbox]` section (NORMATIVE).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxSection {
    pub profile: SandboxProfile,
    pub memory_mb: u32,
    pub cpu_percent: u8,
    pub wall_clock_timeout_ms: u64,
    #[serde(default)]
    pub fs_readonly_paths: Vec<String>,
    #[serde(default)]
    pub fs_writable_paths: Vec<String>,
    pub deny_exec: bool,
    pub deny_ptrace: bool,
}

impl SandboxSection {
    fn validate(&self) -> Result<(), ManifestError> {
        if self.cpu_percent == 0 {
            return Err(ManifestError::Invalid {
                field: "sandbox.cpu_percent",
                message: "must be > 0".into(),
            });
        }
        if self.wall_clock_timeout_ms == 0 {
            return Err(ManifestError::Invalid {
                field: "sandbox.wall_clock_timeout_ms",
                message: "must be > 0".into(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxProfile {
    Strict,
    StrictPlus,
    Moderate,
    Permissive,
}

/// Operation-level network constraints (NORMATIVE).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct NetworkConstraints {
    pub host_allow: Vec<String>,
    pub port_allow: Vec<u16>,
    #[serde(default)]
    pub ip_allow: Vec<IpAddr>,
    #[serde(default)]
    pub cidr_deny: Vec<String>,
    #[serde(default = "default_true")]
    pub deny_localhost: bool,
    #[serde(default = "default_true")]
    pub deny_private_ranges: bool,
    #[serde(default = "default_true")]
    pub deny_tailnet_ranges: bool,
    pub require_sni: bool,
    #[serde(default)]
    pub spki_pins: Vec<Base64Bytes>,
    #[serde(default = "default_true")]
    pub deny_ip_literals: bool,
    #[serde(default = "default_true")]
    pub require_host_canonicalization: bool,
    #[serde(default = "default_dns_max_ips")]
    pub dns_max_ips: u16,
    #[serde(default = "default_max_redirects")]
    pub max_redirects: u8,
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u32,
    #[serde(default = "default_total_timeout_ms")]
    pub total_timeout_ms: u32,
    #[serde(default = "default_max_response_bytes")]
    pub max_response_bytes: u64,
}

const fn default_true() -> bool {
    true
}

const fn default_dns_max_ips() -> u16 {
    16
}

const fn default_max_redirects() -> u8 {
    5
}

const fn default_connect_timeout_ms() -> u32 {
    10_000
}

const fn default_total_timeout_ms() -> u32 {
    60_000
}

const fn default_max_response_bytes() -> u64 {
    10_485_760
}

impl NetworkConstraints {
    fn validate(&self) -> Result<(), ManifestError> {
        if self.host_allow.is_empty() {
            return Err(ManifestError::Invalid {
                field: "provides.operations.*.network_constraints.host_allow",
                message: "must not be empty".into(),
            });
        }
        if self.port_allow.is_empty() {
            return Err(ManifestError::Invalid {
                field: "provides.operations.*.network_constraints.port_allow",
                message: "must not be empty".into(),
            });
        }
        if self.connect_timeout_ms == 0 || self.total_timeout_ms == 0 {
            return Err(ManifestError::Invalid {
                field: "provides.operations.*.network_constraints",
                message: "timeouts must be > 0".into(),
            });
        }
        if self.max_response_bytes == 0 {
            return Err(ManifestError::Invalid {
                field: "provides.operations.*.network_constraints.max_response_bytes",
                message: "must be > 0".into(),
            });
        }

        for host in &self.host_allow {
            validate_host_allow_entry(
                host,
                self.deny_ip_literals,
                self.require_host_canonicalization,
            )?;

            if self.deny_localhost && host == "localhost" {
                return Err(ManifestError::Invalid {
                    field: "provides.operations.*.network_constraints.host_allow",
                    message: "host `localhost` is allowed but `deny_localhost` is true".into(),
                });
            }
        }

        for cidr in &self.cidr_deny {
            cidr.parse::<IpNet>().map_err(|_| ManifestError::Invalid {
                field: "provides.operations.*.network_constraints.cidr_deny",
                message: format!("invalid CIDR `{cidr}`"),
            })?;
        }

        Ok(())
    }
}

fn validate_host_allow_entry(
    host: &str,
    deny_ip_literals: bool,
    require_host_canonicalization: bool,
) -> Result<(), ManifestError> {
    if host.is_empty() {
        return Err(ManifestError::Invalid {
            field: "provides.operations.*.network_constraints.host_allow",
            message: "host entries must not be empty".into(),
        });
    }

    if deny_ip_literals && host.parse::<IpAddr>().is_ok() {
        return Err(ManifestError::Invalid {
            field: "provides.operations.*.network_constraints.host_allow",
            message: format!("IP literals are not allowed in host_allow (`{host}`)"),
        });
    }

    if require_host_canonicalization {
        if !host.is_ascii() {
            return Err(ManifestError::Invalid {
                field: "provides.operations.*.network_constraints.host_allow",
                message: format!("host must be ASCII (already canonicalized): `{host}`"),
            });
        }
        if host.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err(ManifestError::Invalid {
                field: "provides.operations.*.network_constraints.host_allow",
                message: format!("host must be lowercase: `{host}`"),
            });
        }
        if host.ends_with('.') {
            return Err(ManifestError::Invalid {
                field: "provides.operations.*.network_constraints.host_allow",
                message: format!("host must not have trailing dot: `{host}`"),
            });
        }
    }

    if host.contains('*') {
        // NORMATIVE: only allow `*.example.com` wildcard form.
        if !host.starts_with("*.") || host.matches('*').count() != 1 {
            return Err(ManifestError::Invalid {
                field: "provides.operations.*.network_constraints.host_allow",
                message: format!(
                    "invalid wildcard pattern `{host}` (only `*.example.com` allowed)"
                ),
            });
        }
        // Require at least two labels after the wildcard (e.g. `*.example.com`)
        // `*.com` (2 parts) is rejected. `*.co.uk` (3 parts) is allowed but risky?
        // Let's enforce at least 3 parts total (wildcard + 2 labels).
        // `host.split('.').count()`
        if host.split('.').count() < 3 {
            return Err(ManifestError::Invalid {
                field: "provides.operations.*.network_constraints.host_allow",
                message: format!("invalid wildcard pattern `{host}` (too broad)"),
            });
        }
    }

    Ok(())
}

/// `[signatures]` section.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignaturesSection {
    #[serde(default)]
    pub publisher_signatures: Vec<SignatureEntry>,
    pub publisher_threshold: Option<SignatureThreshold>,
    pub registry_signature: Option<SignatureEntry>,
    pub transparency_log_entry: Option<ObjectIdRef>,
}

impl SignaturesSection {
    fn validate(&self) -> Result<(), ManifestError> {
        if !self.publisher_signatures.is_empty() && self.publisher_threshold.is_none() {
            return Err(ManifestError::Invalid {
                field: "signatures.publisher_threshold",
                message: "required when publisher_signatures is non-empty".into(),
            });
        }
        if let Some(threshold) = self.publisher_threshold {
            threshold.validate(self.publisher_signatures.len())?;
        }
        let mut seen = HashSet::new();
        for sig in &self.publisher_signatures {
            if !seen.insert(sig.kid.clone()) {
                return Err(ManifestError::Invalid {
                    field: "signatures.publisher_signatures",
                    message: format!("duplicate kid `{}`", sig.kid),
                });
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureEntry {
    pub kid: String,
    pub sig: Base64Bytes,
}

/// Signature threshold string (e.g., `"2-of-3"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignatureThreshold {
    pub k: u8,
    pub n: u8,
}

impl SignatureThreshold {
    fn validate(self, signatures_present: usize) -> Result<(), ManifestError> {
        if self.k == 0 || self.n == 0 || self.k > self.n {
            return Err(ManifestError::Invalid {
                field: "signatures.publisher_threshold",
                message: "invalid threshold (k-of-n)".into(),
            });
        }
        if usize::from(self.k) > signatures_present {
            return Err(ManifestError::Invalid {
                field: "signatures.publisher_signatures",
                message: "insufficient signatures for publisher_threshold".into(),
            });
        }
        Ok(())
    }
}

impl fmt::Display for SignatureThreshold {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-of-{}", self.k, self.n)
    }
}

impl TryFrom<String> for SignatureThreshold {
    type Error = ManifestError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let (k, n) = value
            .split_once("-of-")
            .ok_or_else(|| ManifestError::Invalid {
                field: "signatures.publisher_threshold",
                message: "expected format like \"2-of-3\"".into(),
            })?;
        let k: u8 = k.parse().map_err(|_| ManifestError::Invalid {
            field: "signatures.publisher_threshold",
            message: "k must be an integer".into(),
        })?;
        let n: u8 = n.parse().map_err(|_| ManifestError::Invalid {
            field: "signatures.publisher_threshold",
            message: "n must be an integer".into(),
        })?;
        Ok(Self { k, n })
    }
}

impl From<SignatureThreshold> for String {
    fn from(value: SignatureThreshold) -> Self {
        value.to_string()
    }
}

impl<'de> Deserialize<'de> for SignatureThreshold {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::try_from(s).map_err(serde::de::Error::custom)
    }
}

impl Serialize for SignatureThreshold {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

/// `[supply_chain]` section.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupplyChainSection {
    #[serde(default)]
    pub attestations: Vec<SupplyChainAttestationRef>,
}

impl SupplyChainSection {
    fn validate(&self) -> Result<(), ManifestError> {
        let mut seen = HashSet::new();
        for att in &self.attestations {
            if !seen.insert(att.object_id) {
                return Err(ManifestError::Invalid {
                    field: "supply_chain.attestations",
                    message: format!("duplicate attestation object id `{}`", att.object_id),
                });
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupplyChainAttestationRef {
    #[serde(rename = "type")]
    pub attestation_type: AttestationType,
    pub object_id: ObjectIdRef,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttestationType {
    InToto,
    ReproducibleBuild,
    CodeReview,
}

impl<'de> Deserialize<'de> for AttestationType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "in-toto" => Ok(Self::InToto),
            "reproducible-build" => Ok(Self::ReproducibleBuild),
            "code-review" => Ok(Self::CodeReview),
            _ => Err(serde::de::Error::custom(
                "invalid attestation type (expected: in-toto|reproducible-build|code-review)",
            )),
        }
    }
}

/// `[policy]` section.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySection {
    #[serde(default)]
    pub require_transparency_log: bool,
    #[serde(default)]
    pub require_attestation_types: Vec<AttestationType>,
    #[serde(default)]
    pub min_slsa_level: Option<u8>,
    #[serde(default)]
    pub trusted_builders: Vec<String>,
}

impl PolicySection {
    fn validate(&self) -> Result<(), ManifestError> {
        if let Some(level) = self.min_slsa_level {
            if level > 4 {
                return Err(ManifestError::Invalid {
                    field: "policy.min_slsa_level",
                    message: "must be in range 0..=4".into(),
                });
            }
        }
        Ok(())
    }
}

/// Raw base64 bytes (requires the `base64:` prefix).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Base64Bytes(Vec<u8>);

impl Base64Bytes {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<String> for Base64Bytes {
    type Error = ManifestError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let body = value
            .strip_prefix("base64:")
            .ok_or_else(|| ManifestError::Invalid {
                field: "base64",
                message: "expected `base64:` prefix".into(),
            })?;
        let decoded = BASE64_STANDARD
            .decode(body)
            .map_err(|_| ManifestError::Invalid {
                field: "base64",
                message: "invalid base64".into(),
            })?;
        Ok(Self(decoded))
    }
}

impl From<Base64Bytes> for String {
    fn from(value: Base64Bytes) -> Self {
        format!("base64:{}", BASE64_STANDARD.encode(value.0))
    }
}

impl<'de> Deserialize<'de> for Base64Bytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::try_from(s).map_err(serde::de::Error::custom)
    }
}

impl Serialize for Base64Bytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&String::from(self.clone()))
    }
}

/// Reference to an `ObjectId` in `objectid:<hex>` form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObjectIdRef([u8; 32]);

impl fmt::Display for ObjectIdRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "objectid:{}", hex::encode(self.0))
    }
}

impl TryFrom<String> for ObjectIdRef {
    type Error = ManifestError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let hex_str = value.strip_prefix("objectid:").unwrap_or(value.as_str());
        let bytes = hex::decode(hex_str).map_err(|_| ManifestError::Invalid {
            field: "objectid",
            message: "object id must be hex".into(),
        })?;
        let id: [u8; 32] = bytes.try_into().map_err(|_| ManifestError::Invalid {
            field: "objectid",
            message: "object id must be 32 bytes".into(),
        })?;
        Ok(Self(id))
    }
}

impl From<ObjectIdRef> for String {
    fn from(value: ObjectIdRef) -> Self {
        value.to_string()
    }
}

impl<'de> Deserialize<'de> for ObjectIdRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::try_from(s).map_err(serde::de::Error::custom)
    }
}

impl Serialize for ObjectIdRef {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

/// Embed a connector manifest in the output binary (NORMATIVE).
///
/// Connectors MUST embed the manifest in a platform-specific section so it can be extracted
/// without executing the connector:
/// - ELF: `.fcp_manifest`
/// - Mach-O: `__FCP,__manifest`
/// - PE: `.fcpmanifest`
#[macro_export]
macro_rules! embed_manifest {
    ($path:literal) => {
        #[cfg_attr(target_os = "macos", link_section = "__FCP,__manifest")]
        #[cfg_attr(target_os = "windows", link_section = ".fcpmanifest")]
        #[cfg_attr(
            all(not(target_os = "macos"), not(target_os = "windows")),
            link_section = ".fcp_manifest"
        )]
        #[used]
        static FCP_MANIFEST_BYTES: [u8; include_bytes!($path).len()] = *include_bytes!($path);

        #[must_use]
        pub fn embedded_manifest_bytes() -> &'static [u8] {
            &FCP_MANIFEST_BYTES
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde_json::json;
    use std::path::Path;
    use std::time::Instant;
    use uuid::Uuid;

    const PLACEHOLDER_HASH: &str = "blake3-256:fcp.interface.v2:0000000000000000000000000000000000000000000000000000000000000000";
    const EMBEDDED_MINIMAL_MANIFEST: &[u8] =
        include_bytes!("../../../tests/vectors/manifest/manifest_minimal.toml");

    struct TestLog {
        test_name: &'static str,
        module: &'static str,
        correlation_id: String,
        started_at: Instant,
        connector_id: Option<&'static str>,
        version: Option<&'static str>,
        capabilities_count: Option<usize>,
    }

    impl TestLog {
        fn new(
            test_name: &'static str,
            module: &'static str,
            connector_id: Option<&'static str>,
            version: Option<&'static str>,
            capabilities_count: Option<usize>,
        ) -> Self {
            let correlation_id = Uuid::new_v4().to_string();
            let log = Self {
                test_name,
                module,
                correlation_id,
                started_at: Instant::now(),
                connector_id,
                version,
                capabilities_count,
            };
            log.emit("execute", Some("start"), 0);
            log
        }

        fn emit(&self, phase: &str, result: Option<&str>, duration_ms: u128) {
            let payload = json!({
                "timestamp": Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                "test_name": self.test_name,
                "module": self.module,
                "phase": phase,
                "correlation_id": self.correlation_id,
                "connector_id": self.connector_id,
                "version": self.version,
                "capabilities_count": self.capabilities_count,
                "duration_ms": duration_ms,
                "result": result,
            });
            println!("{payload}");
        }
    }

    impl Drop for TestLog {
        fn drop(&mut self) {
            let duration_ms = self.started_at.elapsed().as_millis();
            let result = if std::thread::panicking() {
                "fail"
            } else {
                "pass"
            };
            self.emit("verify", Some(result), duration_ms);
        }
    }

    fn test_manifest_toml(interface_hash: &str) -> String {
        format!(
            r#"[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"
min_mesh_version = "2.0.0"
min_protocol = "fcp2-sym/2.0"
protocol_features = ["fcps.aead.xchacha20poly1305"]
max_datagram_bytes = 1200
interface_hash = "{interface_hash}"

[connector]
id = "fcp.telegram"
name = "Telegram Connector"
version = "2026.1.0"
description = "Secure Telegram Bot API integration"
archetypes = ["bidirectional", "streaming"]
format = "native"

[connector.state]
model = "stateless"
state_schema_version = "1"

[zones]
home = "z:community"
allowed_sources = ["z:owner", "z:private", "z:work", "z:community"]
allowed_targets = ["z:community"]
forbidden = ["z:public"]

[capabilities]
required = ["ipc.gateway", "network.dns", "network.egress", "network.tls.sni"]
optional = ["media.download"]
forbidden = ["system.exec"]

[provides.operations.telegram_send_message]
description = "Send a message to a Telegram chat"
capability = "telegram.send_message"
risk_level = "medium"
safety_tier = "risky"
requires_approval = "policy"
rate_limit = "60/min"
idempotency = "best_effort"
input_schema = {{ type = "object", required = ["chat_resource", "text"] }}
output_schema = {{ type = "object", required = ["message_id"] }}
network_constraints = {{ host_allow = ["api.telegram.org"], port_allow = [443], require_sni = true }}

[provides.operations.telegram_send_message.ai_hints]
when_to_use = "Use to post updates to approved chats."
common_mistakes = ["Sending secrets"]

[event_caps]
streaming = true
replay = true
min_buffer_events = 10000

[sandbox]
profile = "strict"
memory_mb = 256
cpu_percent = 50
wall_clock_timeout_ms = 30000
fs_readonly_paths = ["/usr", "/lib"]
fs_writable_paths = ["$CONNECTOR_STATE"]
deny_exec = true
deny_ptrace = true
"#
        )
    }

    fn vector_manifest_path(name: &str) -> std::path::PathBuf {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        root.join("../../tests/vectors/manifest").join(name)
    }

    fn read_vector_manifest(name: &str) -> String {
        let path = vector_manifest_path(name);
        std::fs::read_to_string(&path).unwrap_or_else(|err| {
            panic!("failed to read manifest vector {}: {err}", path.display())
        })
    }

    fn with_computed_hash(raw: &str) -> String {
        let unchecked =
            ConnectorManifest::parse_str_unchecked(raw).expect("vector must parse unchecked");
        let computed = unchecked
            .compute_interface_hash()
            .expect("compute interface hash");
        raw.replace(PLACEHOLDER_HASH, &computed.to_string())
    }

    #[test]
    fn manifest_parses_and_validates_with_computed_interface_hash() {
        let _log = TestLog::new(
            "manifest_parses_and_validates_with_computed_interface_hash",
            "fcp-manifest",
            Some("fcp.telegram"),
            Some("2026.1.0"),
            Some(4),
        );
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let unchecked = ConnectorManifest::parse_str_unchecked(&test_manifest_toml(&placeholder))
            .expect("unchecked parse");
        let computed = unchecked.compute_interface_hash().expect("compute hash");

        let parsed =
            ConnectorManifest::parse_str(&test_manifest_toml(&computed.to_string())).unwrap();
        assert_eq!(parsed.manifest.interface_hash, computed);
    }

    #[test]
    fn rejects_uppercase_interface_hash() {
        let _log = TestLog::new(
            "rejects_uppercase_interface_hash",
            "fcp-manifest",
            Some("fcp.telegram"),
            Some("2026.1.0"),
            Some(4),
        );
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let unchecked = ConnectorManifest::parse_str_unchecked(&test_manifest_toml(&placeholder))
            .expect("unchecked parse");
        let computed = unchecked.compute_interface_hash().expect("compute hash");

        // Only uppercase the digest part
        let s = computed.to_string();
        let (prefix, digest) = s.rsplit_once(':').unwrap();
        let bad = format!("{}:{}", prefix, digest.to_ascii_uppercase());

        let err = ConnectorManifest::parse_str(&test_manifest_toml(&bad)).unwrap_err();
        // Since deserialization happens during TOML parsing, custom errors are wrapped in Toml error
        assert!(matches!(err, ManifestError::Toml(_)));
        assert!(err.to_string().contains("digest must be lowercase hex"));
    }

    #[test]
    fn rejects_interface_hash_mismatch() {
        let _log = TestLog::new(
            "rejects_interface_hash_mismatch",
            "fcp-manifest",
            Some("fcp.telegram"),
            Some("2026.1.0"),
            Some(4),
        );
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let unchecked = ConnectorManifest::parse_str_unchecked(&test_manifest_toml(&placeholder))
            .expect("unchecked parse");
        let computed = unchecked.compute_interface_hash().expect("compute hash");
        let mut bad = computed.to_string();
        bad.pop();
        bad.push('0');

        let err = ConnectorManifest::parse_str(&test_manifest_toml(&bad)).unwrap_err();
        assert!(matches!(err, ManifestError::InterfaceHashMismatch { .. }));
    }

    #[test]
    fn rejects_network_capability_host_restrictions() {
        let _log = TestLog::new(
            "rejects_network_capability_host_restrictions",
            "fcp-manifest",
            Some("fcp.telegram"),
            Some("2026.1.0"),
            Some(4),
        );
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let mut toml = test_manifest_toml(&placeholder);
        toml = toml.replace("network.egress", "network.egress:api.telegram.org:443");

        let unchecked = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse");
        let hash = unchecked.compute_interface_hash().expect("compute hash");
        let with_hash = test_manifest_toml(&hash.to_string())
            .replace("network.egress", "network.egress:api.telegram.org:443");

        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(matches!(err, ManifestError::Invalid { .. }));
    }

    #[test]
    fn rejects_missing_forbidden_system_exec() {
        let _log = TestLog::new(
            "rejects_missing_forbidden_system_exec",
            "fcp-manifest",
            Some("fcp.telegram"),
            Some("2026.1.0"),
            Some(4),
        );
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let toml = test_manifest_toml(&placeholder)
            .replace("forbidden = [\"system.exec\"]", "forbidden = []");

        let unchecked = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse");
        let hash = unchecked.compute_interface_hash().expect("compute hash");
        let with_hash = test_manifest_toml(&hash.to_string())
            .replace("forbidden = [\"system.exec\"]", "forbidden = []");

        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(
            matches!(err, ManifestError::Invalid { field, .. } if field == "capabilities.forbidden")
        );
        assert!(err.to_string().contains("system.exec"));
    }

    #[test]
    fn rejects_invalid_min_protocol() {
        let _log = TestLog::new(
            "rejects_invalid_min_protocol",
            "fcp-manifest",
            Some("fcp.telegram"),
            Some("2026.1.0"),
            Some(4),
        );
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let toml = test_manifest_toml(&placeholder).replace("fcp2-sym/2.0", "fcp2-sym");
        let err = ConnectorManifest::parse_str_unchecked(&toml).unwrap_err();
        assert!(err.to_string().contains("min_protocol"));
    }

    #[test]
    fn rejects_bad_host_allow_wildcard() {
        let _log = TestLog::new(
            "rejects_bad_host_allow_wildcard",
            "fcp-manifest",
            Some("fcp.telegram"),
            Some("2026.1.0"),
            Some(4),
        );
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let toml =
            test_manifest_toml(&placeholder).replace("api.telegram.org", "*api.telegram.org");
        let unchecked = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse");
        let hash = unchecked.compute_interface_hash().expect("compute hash");
        let with_hash =
            test_manifest_toml(&hash.to_string()).replace("api.telegram.org", "*api.telegram.org");

        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(matches!(err, ManifestError::Invalid { .. }));
    }

    #[test]
    fn rejects_localhost_when_denied() {
        let _log = TestLog::new(
            "rejects_localhost_when_denied",
            "fcp-manifest",
            Some("fcp.telegram"),
            Some("2026.1.0"),
            Some(4),
        );
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        // deny_localhost is true by default
        let toml = test_manifest_toml(&placeholder).replace("api.telegram.org", "localhost");

        let unchecked = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse");
        let hash = unchecked.compute_interface_hash().expect("compute hash");
        let with_hash =
            test_manifest_toml(&hash.to_string()).replace("api.telegram.org", "localhost");

        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(
            err.to_string()
                .contains("host `localhost` is allowed but `deny_localhost` is true")
        );
    }

    #[test]
    fn rejects_broad_wildcard() {
        let _log = TestLog::new(
            "rejects_broad_wildcard",
            "fcp-manifest",
            Some("fcp.telegram"),
            Some("2026.1.0"),
            Some(4),
        );
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        // *.com is too broad (only 2 parts)
        let toml = test_manifest_toml(&placeholder).replace("api.telegram.org", "*.com");

        let unchecked = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse");
        let hash = unchecked.compute_interface_hash().expect("compute hash");
        let with_hash = test_manifest_toml(&hash.to_string()).replace("api.telegram.org", "*.com");

        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(err.to_string().contains("too broad"));
    }

    #[test]
    fn vector_manifest_valid_parses() {
        let _log = TestLog::new(
            "vector_manifest_valid_parses",
            "fcp-manifest",
            Some("fcp.valid"),
            Some("1.2.3"),
            Some(3),
        );
        let raw = read_vector_manifest("manifest_valid.toml");
        let with_hash = with_computed_hash(&raw);
        let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid manifest");
        assert_eq!(parsed.connector.id.as_str(), "fcp.valid");
        assert_eq!(parsed.provides.operations.len(), 1);
    }

    #[test]
    fn vector_manifest_minimal_parses() {
        let _log = TestLog::new(
            "vector_manifest_minimal_parses",
            "fcp-manifest",
            Some("fcp.minimal"),
            Some("0.1.0"),
            Some(1),
        );
        let raw = read_vector_manifest("manifest_minimal.toml");
        let with_hash = with_computed_hash(&raw);
        let parsed = ConnectorManifest::parse_str(&with_hash).expect("minimal manifest");
        assert_eq!(parsed.connector.id.as_str(), "fcp.minimal");
        assert_eq!(parsed.capabilities.required.len(), 1);
    }

    #[test]
    fn vector_manifest_invalid_version_rejected() {
        let _log = TestLog::new(
            "vector_manifest_invalid_version_rejected",
            "fcp-manifest",
            Some("fcp.invalid"),
            None,
            Some(1),
        );
        let raw = read_vector_manifest("manifest_invalid_version.toml");
        let err = ConnectorManifest::parse_str_unchecked(&raw).unwrap_err();
        assert!(matches!(err, ManifestError::Toml(_)));
    }

    #[test]
    fn vector_manifest_dangerous_caps_rejected() {
        let _log = TestLog::new(
            "vector_manifest_dangerous_caps_rejected",
            "fcp-manifest",
            Some("fcp.dangerous"),
            Some("0.1.0"),
            Some(2),
        );
        let raw = read_vector_manifest("manifest_dangerous_caps.toml");
        let with_hash = with_computed_hash(&raw);
        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(matches!(err, ManifestError::Invalid { .. }));
    }

    #[test]
    fn rejects_event_caps_without_buffer() {
        let _log = TestLog::new(
            "rejects_event_caps_without_buffer",
            "fcp-manifest",
            Some("fcp.telegram"),
            Some("2026.1.0"),
            Some(4),
        );
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let mut toml = test_manifest_toml(&placeholder);
        toml = toml.replace("min_buffer_events = 10000", "min_buffer_events = 0");
        let unchecked = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse");
        let hash = unchecked.compute_interface_hash().expect("compute hash");
        let with_hash = test_manifest_toml(&hash.to_string())
            .replace("min_buffer_events = 10000", "min_buffer_events = 0");
        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(
            matches!(err, ManifestError::Invalid { field, .. } if field == "event_caps.min_buffer_events")
        );
    }

    #[test]
    fn rejects_signatures_without_threshold() {
        let _log = TestLog::new(
            "rejects_signatures_without_threshold",
            "fcp-manifest",
            Some("fcp.valid"),
            Some("1.2.3"),
            Some(3),
        );
        let raw = read_vector_manifest("manifest_valid.toml");
        let mut with_hash = with_computed_hash(&raw);
        with_hash = with_hash.replace("publisher_threshold = \"2-of-2\"\n", "");
        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(
            matches!(err, ManifestError::Invalid { field, .. } if field == "signatures.publisher_threshold")
        );
    }

    #[test]
    fn rejects_duplicate_signature_kid() {
        let _log = TestLog::new(
            "rejects_duplicate_signature_kid",
            "fcp-manifest",
            Some("fcp.valid"),
            Some("1.2.3"),
            Some(3),
        );
        let raw = read_vector_manifest("manifest_valid.toml");
        let with_hash = with_computed_hash(&raw).replace("pub2", "pub1");
        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(
            matches!(err, ManifestError::Invalid { field, .. } if field == "signatures.publisher_signatures")
        );
    }

    #[test]
    fn rejects_duplicate_supply_chain_attestations() {
        let _log = TestLog::new(
            "rejects_duplicate_supply_chain_attestations",
            "fcp-manifest",
            Some("fcp.valid"),
            Some("1.2.3"),
            Some(3),
        );
        let raw = read_vector_manifest("manifest_valid.toml");
        let with_hash = with_computed_hash(&raw).replace(
            "objectid:3333333333333333333333333333333333333333333333333333333333333333",
            "objectid:2222222222222222222222222222222222222222222222222222222222222222",
        );
        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(
            matches!(err, ManifestError::Invalid { field, .. } if field == "supply_chain.attestations")
        );
    }

    #[test]
    fn rejects_invalid_slsa_level() {
        let _log = TestLog::new(
            "rejects_invalid_slsa_level",
            "fcp-manifest",
            Some("fcp.valid"),
            Some("1.2.3"),
            Some(3),
        );
        let raw = read_vector_manifest("manifest_valid.toml");
        let with_hash =
            with_computed_hash(&raw).replace("min_slsa_level = 2", "min_slsa_level = 9");
        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(
            matches!(err, ManifestError::Invalid { field, .. } if field == "policy.min_slsa_level")
        );
    }

    #[test]
    fn rejects_invalid_base64_signature() {
        let _log = TestLog::new(
            "rejects_invalid_base64_signature",
            "fcp-manifest",
            Some("fcp.valid"),
            Some("1.2.3"),
            Some(3),
        );
        let raw = read_vector_manifest("manifest_valid.toml");
        let with_hash = with_computed_hash(&raw).replace("base64:Zm9v", "Zm9v");
        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(matches!(err, ManifestError::Toml(_)));
    }

    #[test]
    fn rejects_uppercase_host_allow() {
        let _log = TestLog::new(
            "rejects_uppercase_host_allow",
            "fcp-manifest",
            Some("fcp.valid"),
            Some("1.2.3"),
            Some(3),
        );
        let raw = read_vector_manifest("manifest_valid.toml");
        let with_hash = with_computed_hash(&raw).replace("api.telegram.org", "API.Telegram.org");
        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(
            matches!(err, ManifestError::Invalid { field, .. } if field == "provides.operations.*.network_constraints.host_allow")
        );
    }

    #[test]
    fn rejects_ip_literal_in_host_allow() {
        let _log = TestLog::new(
            "rejects_ip_literal_in_host_allow",
            "fcp-manifest",
            Some("fcp.valid"),
            Some("1.2.3"),
            Some(3),
        );
        let raw = read_vector_manifest("manifest_valid.toml");
        let with_hash = with_computed_hash(&raw).replace("api.telegram.org", "192.0.2.1");
        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(
            matches!(err, ManifestError::Invalid { field, .. } if field == "provides.operations.*.network_constraints.host_allow")
        );
    }

    #[test]
    fn rejects_invalid_rate_limit_shorthand() {
        let _log = TestLog::new(
            "rejects_invalid_rate_limit_shorthand",
            "fcp-manifest",
            Some("fcp.telegram"),
            Some("2026.1.0"),
            Some(4),
        );
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let toml = test_manifest_toml(&placeholder).replace("60/min", "60/fortnight");
        let err = ConnectorManifest::parse_str(&toml).unwrap_err();
        assert!(matches!(err, ManifestError::Toml(_)));
    }

    #[test]
    fn rejects_invalid_signature_threshold() {
        let _log = TestLog::new(
            "rejects_invalid_signature_threshold",
            "fcp-manifest",
            Some("fcp.valid"),
            Some("1.2.3"),
            Some(3),
        );
        let raw = read_vector_manifest("manifest_valid.toml");
        let with_hash = with_computed_hash(&raw).replace(
            "publisher_threshold = \"2-of-2\"",
            "publisher_threshold = \"3-of-2\"",
        );
        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(
            matches!(err, ManifestError::Invalid { field, .. } if field == "signatures.publisher_threshold")
        );
    }

    #[test]
    fn rejects_empty_connector_name() {
        let _log = TestLog::new(
            "rejects_empty_connector_name",
            "fcp-manifest",
            Some("fcp.telegram"),
            Some("2026.1.0"),
            Some(4),
        );
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let toml = test_manifest_toml(&placeholder)
            .replace("name = \"Telegram Connector\"", "name = \"\"");
        let unchecked = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse");
        let hash = unchecked.compute_interface_hash().expect("compute hash");
        let with_hash = test_manifest_toml(&hash.to_string())
            .replace("name = \"Telegram Connector\"", "name = \"\"");
        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(matches!(err, ManifestError::Invalid { field, .. } if field == "connector.name"));
    }

    #[test]
    fn rejects_zero_cpu_percent() {
        let _log = TestLog::new(
            "rejects_zero_cpu_percent",
            "fcp-manifest",
            Some("fcp.telegram"),
            Some("2026.1.0"),
            Some(4),
        );
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let toml = test_manifest_toml(&placeholder).replace("cpu_percent = 50", "cpu_percent = 0");
        let unchecked = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse");
        let hash = unchecked.compute_interface_hash().expect("compute hash");
        let with_hash =
            test_manifest_toml(&hash.to_string()).replace("cpu_percent = 50", "cpu_percent = 0");
        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(
            matches!(err, ManifestError::Invalid { field, .. } if field == "sandbox.cpu_percent")
        );
    }

    #[test]
    fn embedded_manifest_fixture_bytes_match() {
        let _log = TestLog::new(
            "embedded_manifest_fixture_bytes_match",
            "fcp-manifest",
            Some("fcp.minimal"),
            Some("0.1.0"),
            Some(1),
        );
        let path = vector_manifest_path("manifest_minimal.toml");
        let raw = std::fs::read(&path).expect("read manifest fixture");
        assert_eq!(EMBEDDED_MINIMAL_MANIFEST, raw.as_slice());
    }

    // ── Capability-ID lint tests (bd-rk6a / bd-2kt1) ───────────────────

    #[test]
    fn lint_rejects_url_scheme_http() {
        let _log = TestLog::new(
            "lint_rejects_url_scheme_http",
            "fcp-manifest",
            None,
            None,
            None,
        );
        let err = lint_capability_id_no_network_addressing(
            "http:api.example.com",
            "capabilities.required",
        );
        assert!(err.is_err());
        let msg = err.unwrap_err().to_string();
        assert!(msg.contains("URL scheme"));
        assert!(msg.contains("http:"));
    }

    #[test]
    fn lint_rejects_url_scheme_https() {
        let _log = TestLog::new(
            "lint_rejects_url_scheme_https",
            "fcp-manifest",
            None,
            None,
            None,
        );
        let err = lint_capability_id_no_network_addressing(
            "https:api.example.com",
            "capabilities.required",
        );
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("URL scheme"));
    }

    #[test]
    fn lint_rejects_url_scheme_wss() {
        let _log = TestLog::new(
            "lint_rejects_url_scheme_wss",
            "fcp-manifest",
            None,
            None,
            None,
        );
        let err = lint_capability_id_no_network_addressing(
            "wss:stream.example.com",
            "capabilities.optional",
        );
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("URL scheme"));
    }

    #[test]
    fn lint_rejects_port_number_443() {
        let _log = TestLog::new(
            "lint_rejects_port_number_443",
            "fcp-manifest",
            None,
            None,
            None,
        );
        let err =
            lint_capability_id_no_network_addressing("api.example:443", "capabilities.required");
        assert!(err.is_err());
        let msg = err.unwrap_err().to_string();
        assert!(msg.contains("port number"));
        assert!(msg.contains(":443"));
    }

    #[test]
    fn lint_rejects_port_number_8080() {
        let _log = TestLog::new(
            "lint_rejects_port_number_8080",
            "fcp-manifest",
            None,
            None,
            None,
        );
        let err = lint_capability_id_no_network_addressing("service:8080", "capabilities.required");
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("port number"));
    }

    #[test]
    fn lint_rejects_hostname_tld_com() {
        let _log = TestLog::new(
            "lint_rejects_hostname_tld_com",
            "fcp-manifest",
            None,
            None,
            None,
        );
        let err =
            lint_capability_id_no_network_addressing("api.example.com", "capabilities.required");
        assert!(err.is_err());
        let msg = err.unwrap_err().to_string();
        assert!(msg.contains("hostname"));
        assert!(msg.contains(".com"));
    }

    #[test]
    fn lint_rejects_hostname_tld_org() {
        let _log = TestLog::new(
            "lint_rejects_hostname_tld_org",
            "fcp-manifest",
            None,
            None,
            None,
        );
        let err =
            lint_capability_id_no_network_addressing("api.telegram.org", "capabilities.required");
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains(".org"));
    }

    #[test]
    fn lint_rejects_hostname_tld_net() {
        let _log = TestLog::new(
            "lint_rejects_hostname_tld_net",
            "fcp-manifest",
            None,
            None,
            None,
        );
        let err = lint_capability_id_no_network_addressing(
            "service.example.net",
            "capabilities.optional",
        );
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains(".net"));
    }

    #[test]
    fn lint_rejects_hostname_tld_edu() {
        let _log = TestLog::new(
            "lint_rejects_hostname_tld_edu",
            "fcp-manifest",
            None,
            None,
            None,
        );
        let err =
            lint_capability_id_no_network_addressing("api.university.edu", "capabilities.required");
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains(".edu"));
    }

    #[test]
    fn lint_rejects_hostname_port_combo() {
        let _log = TestLog::new(
            "lint_rejects_hostname_port_combo",
            "fcp-manifest",
            None,
            None,
            None,
        );
        // "api.example.org:443" — segments: ["api", "example", "org:443"]
        // Port check catches ":443" inside the last segment.
        let err = lint_capability_id_no_network_addressing(
            "api.example.org:443",
            "capabilities.required",
        );
        assert!(err.is_err());
    }

    #[test]
    fn lint_rejects_ipv4_address() {
        let _log = TestLog::new(
            "lint_rejects_ipv4_address",
            "fcp-manifest",
            None,
            None,
            None,
        );
        let err =
            lint_capability_id_no_network_addressing("connect.127.0.0.1", "capabilities.required");
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("IPv4"));
    }

    #[test]
    fn lint_rejects_ipv4_loopback() {
        let _log = TestLog::new(
            "lint_rejects_ipv4_loopback",
            "fcp-manifest",
            None,
            None,
            None,
        );
        let err = lint_capability_id_no_network_addressing("10.0.0.1", "capabilities.forbidden");
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("IPv4"));
    }

    #[test]
    fn lint_allows_legitimate_capability_ids() {
        let _log = TestLog::new(
            "lint_allows_legitimate_capability_ids",
            "fcp-manifest",
            None,
            None,
            None,
        );
        // All of these should pass the lint without errors.
        let legitimate = [
            "network.dns",
            "network.egress",
            "network.tls.sni",
            "ipc.gateway",
            "media.download",
            "system.exec",
            "telegram.send_message",
            "discord.send_message",
            "twitter.post",
            "github.create_issue",
            "stripe.charge",
            "storage.read",
            "database.query",
            "audit.read",
            "policy.check",
            "connector.health",
            "my.custom.capability",
            "a",
            "x.y",
        ];
        for id in &legitimate {
            let result = lint_capability_id_no_network_addressing(id, "capabilities.required");
            assert!(
                result.is_ok(),
                "expected `{id}` to pass lint, got: {:?}",
                result.unwrap_err()
            );
        }
    }

    #[test]
    fn lint_single_digit_port_not_flagged() {
        let _log = TestLog::new(
            "lint_single_digit_port_not_flagged",
            "fcp-manifest",
            None,
            None,
            None,
        );
        // Single-digit after colon should NOT be flagged as a port
        // (avoids false positives on version-like segments like "v:2").
        let result =
            lint_capability_id_no_network_addressing("priority:3", "capabilities.required");
        assert!(
            result.is_ok(),
            "single-digit colon suffix should not be flagged as port"
        );
    }

    #[test]
    fn rejects_capability_id_with_hostname_in_manifest() {
        let _log = TestLog::new(
            "rejects_capability_id_with_hostname_in_manifest",
            "fcp-manifest",
            Some("fcp.telegram"),
            Some("2026.1.0"),
            Some(4),
        );
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        // Replace a legitimate capability with one containing a hostname.
        let toml = test_manifest_toml(&placeholder).replace("media.download", "api.example.com");

        let unchecked = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse");
        let hash = unchecked.compute_interface_hash().expect("compute hash");
        let with_hash =
            test_manifest_toml(&hash.to_string()).replace("media.download", "api.example.com");

        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(matches!(err, ManifestError::Invalid { .. }));
        assert!(err.to_string().contains("hostname"));
    }

    #[test]
    fn rejects_capability_id_with_url_scheme_in_manifest() {
        let _log = TestLog::new(
            "rejects_capability_id_with_url_scheme_in_manifest",
            "fcp-manifest",
            Some("fcp.telegram"),
            Some("2026.1.0"),
            Some(4),
        );
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let toml =
            test_manifest_toml(&placeholder).replace("media.download", "https:api.telegram.org");

        let unchecked = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse");
        let hash = unchecked.compute_interface_hash().expect("compute hash");
        let with_hash = test_manifest_toml(&hash.to_string())
            .replace("media.download", "https:api.telegram.org");

        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(matches!(err, ManifestError::Invalid { .. }));
        assert!(err.to_string().contains("URL scheme"));
    }

    #[test]
    fn rejects_operation_capability_with_hostname() {
        let _log = TestLog::new(
            "rejects_operation_capability_with_hostname",
            "fcp-manifest",
            Some("fcp.telegram"),
            Some("2026.1.0"),
            Some(4),
        );
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        // Replace the operation's capability field with a hostname pattern.
        let toml = test_manifest_toml(&placeholder).replace(
            "capability = \"telegram.send_message\"",
            "capability = \"api.telegram.org\"",
        );

        let unchecked = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse");
        let hash = unchecked.compute_interface_hash().expect("compute hash");
        let with_hash = test_manifest_toml(&hash.to_string()).replace(
            "capability = \"telegram.send_message\"",
            "capability = \"api.telegram.org\"",
        );

        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(matches!(err, ManifestError::Invalid { .. }));
    }

    #[test]
    fn rejects_capability_id_with_port_in_manifest() {
        let _log = TestLog::new(
            "rejects_capability_id_with_port_in_manifest",
            "fcp-manifest",
            Some("fcp.telegram"),
            Some("2026.1.0"),
            Some(4),
        );
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let toml = test_manifest_toml(&placeholder).replace("media.download", "service:8080");

        let unchecked = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse");
        let hash = unchecked.compute_interface_hash().expect("compute hash");
        let with_hash =
            test_manifest_toml(&hash.to_string()).replace("media.download", "service:8080");

        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(matches!(err, ManifestError::Invalid { .. }));
        assert!(err.to_string().contains("port number"));
    }
}
