//! Capability types and token verification.
//!
//! Capabilities are cryptographically-scoped permissions that grant specific
//! actions to principals within zones. Capability tokens (FCT) carry the
//! cryptographic proof of authorization.

use std::fmt;
use std::time::Duration;

use chrono::Utc;
use fcp_async_core::time;
use fcp_crypto::ed25519::Ed25519VerifyingKey;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

use crate::object::ObjectId;
use crate::policy::pattern_matches;
use crate::{CredentialId, CredentialValidationError, FcpError, FcpResult};
use fcp_crypto::cose::{CoseToken, CwtClaims, fcp2_claims};

/// Canonical identifier validation error (NORMATIVE).
///
/// Applies to the identifier set in `FCP_Specification_V3.md` §3.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IdValidationError {
    #[error("identifier must not be empty")]
    Empty,

    #[error("identifier too long ({len} bytes > {max} bytes)")]
    TooLong { len: usize, max: usize },

    #[error("identifier must be ASCII")]
    NonAscii,

    #[error("identifier contains uppercase ASCII")]
    UppercaseNotAllowed,

    #[error("identifier has invalid start character '{ch}'")]
    InvalidStartChar { ch: char },

    #[error("identifier has invalid character '{ch}' at byte {index}")]
    InvalidChar { ch: char, index: usize },
}

/// Validate identifier canonicity (NORMATIVE).
///
/// Rules:
/// - ASCII only (no Unicode)
/// - lowercase only (no mixed case)
/// - length ≤ 128 bytes
/// - regex: `^[a-z0-9][a-z0-9._:-]*$`
///
/// # Errors
/// Returns an `IdValidationError` if the identifier is not canonical.
pub fn validate_canonical_id(id: &str) -> Result<(), IdValidationError> {
    if id.is_empty() {
        return Err(IdValidationError::Empty);
    }

    if id.len() > 128 {
        return Err(IdValidationError::TooLong {
            len: id.len(),
            max: 128,
        });
    }

    if !id.is_ascii() {
        return Err(IdValidationError::NonAscii);
    }

    if id.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(IdValidationError::UppercaseNotAllowed);
    }

    let mut chars = id.char_indices();
    let Some((_, first)) = chars.next() else {
        return Err(IdValidationError::Empty);
    };
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return Err(IdValidationError::InvalidStartChar { ch: first });
    }

    for (index, ch) in chars {
        let ok =
            ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '.' | '_' | ':' | '-');
        if !ok {
            return Err(IdValidationError::InvalidChar { ch, index });
        }
    }

    Ok(())
}

/// Capability identifier - unique name for a permission.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CapabilityId(std::sync::Arc<str>);

impl CapabilityId {
    /// Create a new capability ID.
    ///
    /// # Errors
    /// Returns an error if the identifier is not canonical.
    pub fn new(id: impl Into<String>) -> Result<Self, IdValidationError> {
        Self::try_from(id.into())
    }

    /// Create a capability ID from a static string literal.
    ///
    /// # Panics
    /// Panics if the identifier is not canonical. Use only for compile-time known values.
    #[must_use]
    pub fn from_static(id: &'static str) -> Self {
        Self::new(id).expect("static capability ID must be canonical")
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for CapabilityId {
    type Error = IdValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        validate_canonical_id(&value)?;
        Ok(Self(value.into()))
    }
}

impl From<CapabilityId> for String {
    fn from(value: CapabilityId) -> Self {
        value.0.to_string()
    }
}

impl std::str::FromStr for CapabilityId {
    type Err = IdValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s.to_owned())
    }
}

impl fmt::Display for CapabilityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl AsRef<str> for CapabilityId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// Connector identifier - unique name for a connector type.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ConnectorId(std::sync::Arc<str>);

impl ConnectorId {
    /// Create a new connector ID with full details.
    ///
    /// # Errors
    /// Returns an error if the constructed identifier is not canonical.
    pub fn new(
        name: impl Into<String>,
        archetype: impl Into<String>,
        version: impl Into<String>,
    ) -> Result<Self, IdValidationError> {
        Self::try_from(format!(
            "{}:{}:{}",
            name.into(),
            archetype.into(),
            version.into()
        ))
    }

    /// Create a connector ID from a static string literal.
    ///
    /// # Panics
    /// Panics if the identifier is not canonical. Use only for compile-time known values.
    #[must_use]
    pub fn from_static(id: &'static str) -> Self {
        id.parse().expect("static connector ID must be canonical")
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ConnectorId {
    type Error = IdValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        validate_canonical_id(&value)?;
        Ok(Self(value.into()))
    }
}

impl From<ConnectorId> for String {
    fn from(value: ConnectorId) -> Self {
        value.0.to_string()
    }
}

impl std::str::FromStr for ConnectorId {
    type Err = IdValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s.to_owned())
    }
}

impl fmt::Display for ConnectorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl AsRef<str> for ConnectorId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// Instance identifier - unique ID for a running connector instance.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct InstanceId(std::sync::Arc<str>);

impl InstanceId {
    /// Generate a new random instance ID.
    #[must_use]
    pub fn new() -> Self {
        Self(format!("inst_{}", Uuid::new_v4()).into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for InstanceId {
    fn default() -> Self {
        Self::new()
    }
}

impl TryFrom<String> for InstanceId {
    type Error = IdValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        validate_canonical_id(&value)?;
        Ok(Self(value.into()))
    }
}

impl From<InstanceId> for String {
    fn from(value: InstanceId) -> Self {
        value.0.to_string()
    }
}

impl std::str::FromStr for InstanceId {
    type Err = IdValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s.to_owned())
    }
}

impl fmt::Display for InstanceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl AsRef<str> for InstanceId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// Operation identifier - name for a connector function.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct OperationId(std::sync::Arc<str>);

impl OperationId {
    /// Create a new operation ID.
    ///
    /// # Errors
    /// Returns an error if the identifier is not canonical.
    pub fn new(id: impl Into<String>) -> Result<Self, IdValidationError> {
        Self::try_from(id.into())
    }

    /// Create an operation ID from a static string literal.
    ///
    /// # Panics
    /// Panics if the identifier is not canonical. Use only for compile-time known values.
    #[must_use]
    pub fn from_static(id: &'static str) -> Self {
        Self::new(id).expect("static operation ID must be canonical")
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for OperationId {
    type Error = IdValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        validate_canonical_id(&value)?;
        Ok(Self(value.into()))
    }
}

impl From<OperationId> for String {
    fn from(value: OperationId) -> Self {
        value.0.to_string()
    }
}

impl std::str::FromStr for OperationId {
    type Err = IdValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s.to_owned())
    }
}

impl fmt::Display for OperationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl AsRef<str> for OperationId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// Zone identifier - name of a trust boundary.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ZoneId(std::sync::Arc<str>);

/// Fixed-size `ZoneId` hash (NORMATIVE).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ZoneIdHash([u8; 32]);

impl ZoneIdHash {
    /// Construct a `ZoneIdHash` from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ZoneIdHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ZoneIdHash")
            .field(&hex::encode(self.0))
            .finish()
    }
}

impl AsRef<[u8]> for ZoneIdHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ZoneIdError {
    #[error("zone id must not be empty")]
    Empty,

    #[error("zone id too long ({len} bytes > {max} bytes)")]
    TooLong { len: usize, max: usize },

    #[error("zone id must be ASCII")]
    NonAscii,

    #[error("zone id must start with `z:`")]
    MissingPrefix,

    #[error("tailscale tag must start with `tag:fcp-`")]
    InvalidTailscaleTagPrefix,

    #[error("zone id has invalid character '{ch}' at byte {index}")]
    InvalidChar { ch: char, index: usize },
}

impl ZoneId {
    /// Owner zone - highest trust level.
    pub const OWNER: &str = "z:owner";
    /// Private zone - personal data.
    pub const PRIVATE: &str = "z:private";
    /// Work zone - project collaboration.
    pub const WORK: &str = "z:work";
    /// Community zone - public/semi-public content.
    pub const COMMUNITY: &str = "z:community";
    /// Public zone - internet-facing, untrusted.
    pub const PUBLIC: &str = "z:public";

    /// Create an owner zone.
    #[must_use]
    pub fn owner() -> Self {
        Self(Self::OWNER.into())
    }

    /// Create a private zone.
    #[must_use]
    pub fn private() -> Self {
        Self(Self::PRIVATE.into())
    }

    /// Create a work zone.
    #[must_use]
    pub fn work() -> Self {
        Self(Self::WORK.into())
    }

    /// Create a community zone.
    #[must_use]
    pub fn community() -> Self {
        Self(Self::COMMUNITY.into())
    }

    /// Create a public zone.
    #[must_use]
    pub fn public() -> Self {
        Self(Self::PUBLIC.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Raw bytes of canonical `ZoneId` string (NORMATIVE).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.as_str().as_bytes()
    }

    /// Fixed-size hash of `ZoneId` (NORMATIVE).
    #[must_use]
    pub fn hash(&self) -> ZoneIdHash {
        let mut h = blake3::Hasher::new();
        h.update(b"FCP2-ZONE-ID-V1");
        h.update(self.as_bytes());
        ZoneIdHash(*h.finalize().as_bytes())
    }

    /// Map to Tailscale ACL tag.
    #[must_use]
    pub fn to_tailscale_tag(&self) -> String {
        let suffix = self
            .as_str()
            .strip_prefix("z:")
            .unwrap_or(self.as_str())
            .replace(['_', ':'], "-");
        format!("tag:fcp-{suffix}")
    }

    /// Create from Tailscale ACL tag.
    ///
    /// # Errors
    /// Returns an error if the tag prefix is invalid or the resulting zone id is non-canonical.
    pub fn from_tailscale_tag(tag: &str) -> Result<Self, ZoneIdError> {
        let Some(suffix) = tag.strip_prefix("tag:fcp-") else {
            return Err(ZoneIdError::InvalidTailscaleTagPrefix);
        };
        let zone = format!("z:{suffix}");
        zone.parse()
    }
}
impl ZoneId {
    fn validate(zone_id: &str) -> Result<(), ZoneIdError> {
        if zone_id.is_empty() {
            return Err(ZoneIdError::Empty);
        }

        if zone_id.len() > 64 {
            return Err(ZoneIdError::TooLong {
                len: zone_id.len(),
                max: 64,
            });
        }

        if !zone_id.is_ascii() {
            return Err(ZoneIdError::NonAscii);
        }

        if !zone_id.starts_with("z:") {
            return Err(ZoneIdError::MissingPrefix);
        }

        for (index, ch) in zone_id.char_indices() {
            let ok =
                ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, ':' | '_' | '-');
            if !ok {
                return Err(ZoneIdError::InvalidChar { ch, index });
            }
        }

        Ok(())
    }
}

impl TryFrom<String> for ZoneId {
    type Error = ZoneIdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::validate(&value)?;
        Ok(Self(value.into()))
    }
}

impl From<ZoneId> for String {
    fn from(value: ZoneId) -> Self {
        value.0.to_string()
    }
}

impl std::str::FromStr for ZoneId {
    type Err = ZoneIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s.to_owned())
    }
}

impl fmt::Display for ZoneId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl AsRef<str> for ZoneId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// Principal identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PrincipalId(std::sync::Arc<str>);

impl PrincipalId {
    /// Create a new principal ID.
    ///
    /// # Errors
    /// Returns an error if the identifier is not canonical.
    pub fn new(id: impl Into<String>) -> Result<Self, IdValidationError> {
        Self::try_from(id.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for PrincipalId {
    type Error = IdValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        validate_canonical_id(&value)?;
        Ok(Self(value.into()))
    }
}

impl From<PrincipalId> for String {
    fn from(value: PrincipalId) -> Self {
        value.0.to_string()
    }
}

impl std::str::FromStr for PrincipalId {
    type Err = IdValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s.to_owned())
    }
}

impl fmt::Display for PrincipalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl AsRef<str> for PrincipalId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// Tailscale Node ID.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TailscaleNodeId(std::sync::Arc<str>);

impl TailscaleNodeId {
    pub fn new(id: impl Into<String>) -> Self {
        let s: String = id.into();
        Self(s.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for TailscaleNodeId {
    fn from(s: String) -> Self {
        Self(s.into())
    }
}

impl From<TailscaleNodeId> for String {
    fn from(id: TailscaleNodeId) -> Self {
        id.0.to_string()
    }
}

/// Capability Object - mesh-native grant object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityObject {
    /// Capabilities granted by this object
    pub caps: Vec<CapabilityGrant>,

    /// Constraints on these capabilities
    #[serde(default)]
    pub constraints: CapabilityConstraints,

    /// Principal this grant is for (optional, if bound to specific principal)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal: Option<PrincipalId>,

    /// Valid from (timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<u64>,

    /// Valid until (timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<u64>,
}

/// Role Object - named bundle of capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleObject {
    /// Name of the role
    pub name: String,

    /// Capabilities included in this role
    pub caps: Vec<CapabilityGrant>,

    /// Inherited roles (`ObjectIds` of other `RoleObjects`)
    #[serde(default)]
    pub includes: Vec<ObjectId>,
}

/// Role Assignment - binds a role to a principal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleAssignment {
    /// The role being assigned (`ObjectId` of `RoleObject`)
    pub role_id: ObjectId,

    /// The principal receiving the role
    pub principal: PrincipalId,

    /// Optional attenuation
    #[serde(default)]
    pub constraints: CapabilityConstraints,
}

/// Flywheel Capability Token (FCT) - cryptographically signed authorization.
///
/// Wraps a `COSE_Sign1` token containing FCP2 claims.
#[derive(Debug, Clone)]
pub struct CapabilityToken {
    /// The raw `COSE_Sign1` token
    pub raw: CoseToken,
}

impl Serialize for CapabilityToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialize as the raw COSE bytes
        let bytes = self.raw.to_cbor().map_err(serde::ser::Error::custom)?;
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de> Deserialize<'de> for CapabilityToken {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BytesVisitor;
        impl<'de> serde::de::Visitor<'de> for BytesVisitor {
            type Value = Vec<u8>;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("byte array")
            }
            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(v.to_vec())
            }
            // Also handle byte buf (owned)
            fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(v)
            }
            // Support base64 strings for JSON
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                // Try base64 decoding if it's a string (e.g. from JSON)
                use base64::Engine;
                base64::engine::general_purpose::STANDARD
                    .decode(v)
                    .map_err(E::custom)
            }

            // Support sequence of bytes (e.g. JSON array of numbers)
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut bytes = Vec::new();
                while let Some(byte) = seq.next_element()? {
                    bytes.push(byte);
                }
                Ok(bytes)
            }
        }

        let bytes = deserializer.deserialize_any(BytesVisitor)?;
        let raw = CoseToken::from_cbor(&bytes).map_err(serde::de::Error::custom)?;

        // Note: Claims are not verified here! They are just parsed.
        // The verifier MUST be called.

        Ok(Self { raw })
    }
}

impl CapabilityToken {
    /// Create a test token with minimal fields for testing.
    ///
    /// This token has a dummy signature and should only be used in tests.
    ///
    /// # Panics
    ///
    /// Panics if token signing fails during test token construction.
    #[must_use]
    pub fn test_token() -> Self {
        // Construct a dummy CoseToken from raw bytes (invalid signature but structurally okay)
        // Or better, generate a real one with a throwaway key.
        use fcp_crypto::cose::CapabilityTokenBuilder;
        use fcp_crypto::ed25519::Ed25519SigningKey;

        let signing_key = Ed25519SigningKey::generate();
        let now = chrono::Utc::now();
        let expires = now + chrono::Duration::hours(1);

        let cose_token = CapabilityTokenBuilder::new()
            .capability_id("cap.all")
            .zone_id("z:work")
            .principal("test-principal")
            .issuer("node:test")
            .validity(now, expires)
            .sign(&signing_key)
            .expect("Failed to create test token");

        Self { raw: cose_token }
    }
}

/// A single capability grant within a token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityGrant {
    /// The capability being granted
    pub capability: CapabilityId,

    /// Optional operation scope (if None, applies to all operations under this cap)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<OperationId>,
}

/// Constraints on capability usage.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CapabilityConstraints {
    /// Resource URI patterns that are allowed
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource_allow: Vec<String>,

    /// Resource URI patterns that are denied
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource_deny: Vec<String>,

    /// Maximum number of invocations
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_calls: Option<u32>,

    /// Maximum bytes that can be transferred
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<u64>,

    /// Idempotency key for deduplication
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,

    /// Allowed credential IDs for secretless egress (NORMATIVE).
    ///
    /// Connectors can only use credentials listed here in egress requests.
    /// The egress proxy verifies `CredentialId` is in this list before
    /// injecting credential material.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credential_allow: Vec<CredentialId>,
}

impl CapabilityConstraints {
    /// Check if a credential ID is allowed by this capability's constraints.
    ///
    /// Returns `true` only if the credential is explicitly listed in `credential_allow`.
    /// Empty `credential_allow` implies no credentials are allowed (default deny).
    #[must_use]
    pub fn is_credential_allowed(&self, credential_id: &CredentialId) -> bool {
        self.credential_allow.contains(credential_id)
    }

    /// Validate that a credential ID is allowed by these constraints.
    ///
    /// # Errors
    ///
    /// Returns `CredentialValidationError::NotInCredentialAllow` if the credential
    /// is not in `credential_allow` and `credential_allow` is non-empty.
    pub fn validate_credential(
        &self,
        credential_id: &CredentialId,
    ) -> Result<(), CredentialValidationError> {
        if self.is_credential_allowed(credential_id) {
            Ok(())
        } else {
            Err(CredentialValidationError::NotInCredentialAllow {
                credential_id: *credential_id,
            })
        }
    }
}

/// Rate limit scope - determines how rate limits are tracked.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationRateLimitScope {
    /// Rate limit per connector instance (default).
    #[default]
    PerConnector,
    /// Rate limit per zone.
    PerZone,
    /// Rate limit per principal (user/agent).
    PerPrincipal,
}

impl std::fmt::Display for OperationRateLimitScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PerConnector => write!(f, "per_connector"),
            Self::PerZone => write!(f, "per_zone"),
            Self::PerPrincipal => write!(f, "per_principal"),
        }
    }
}

impl std::str::FromStr for OperationRateLimitScope {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "per_connector" => Ok(Self::PerConnector),
            "per_zone" => Ok(Self::PerZone),
            "per_principal" => Ok(Self::PerPrincipal),
            _ => Err(format!(
                "invalid rate limit scope `{s}`: expected one of per_connector, per_zone, per_principal"
            )),
        }
    }
}

/// Rate limit configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimit {
    /// Maximum requests in the period (bucket size). Must be > 0.
    pub max: u32,

    /// Period in milliseconds (refill interval). Must be > 0.
    pub per_ms: u64,

    /// Burst allowance (tokens above max that can accumulate).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub burst: Option<u32>,

    /// Scope: determines how rate limits are tracked.
    /// Defaults to `per_connector` if not specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// Pool name for shared rate limiting across operations.
    /// Operations with the same `pool_name` share a single rate limit bucket.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pool_name: Option<String>,
}

impl RateLimit {
    /// Validate the rate limit configuration.
    ///
    /// # Errors
    /// Returns an error if any constraint is violated.
    pub fn validate(&self) -> Result<(), RateLimitValidationError> {
        if self.max == 0 {
            return Err(RateLimitValidationError::ZeroMax);
        }
        if self.per_ms == 0 {
            return Err(RateLimitValidationError::ZeroPeriod);
        }
        if let Some(ref scope) = self.scope {
            scope.parse::<OperationRateLimitScope>().map_err(|_| {
                RateLimitValidationError::InvalidScope {
                    scope: scope.clone(),
                }
            })?;
        }
        // Validate pool_name format if present (must be valid identifier)
        if let Some(ref pool) = self.pool_name {
            if pool.is_empty() {
                return Err(RateLimitValidationError::EmptyPoolName);
            }
            if !pool
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
            {
                return Err(RateLimitValidationError::InvalidPoolName {
                    pool_name: pool.clone(),
                });
            }
        }
        Ok(())
    }

    /// Get the parsed scope, defaulting to `PerConnector`.
    #[must_use]
    pub fn parsed_scope(&self) -> OperationRateLimitScope {
        self.scope
            .as_ref()
            .and_then(|s| s.parse().ok())
            .unwrap_or_default()
    }
}

/// Error returned when rate limit validation fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateLimitValidationError {
    /// `max` (bucket size) must be > 0.
    ZeroMax,
    /// `per_ms` (period) must be > 0.
    ZeroPeriod,
    /// Invalid scope value.
    InvalidScope { scope: String },
    /// Pool name cannot be empty.
    EmptyPoolName,
    /// Pool name contains invalid characters.
    InvalidPoolName { pool_name: String },
}

impl std::fmt::Display for RateLimitValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroMax => write!(f, "rate_limit.max must be > 0"),
            Self::ZeroPeriod => write!(f, "rate_limit.per_ms must be > 0"),
            Self::InvalidScope { scope } => {
                write!(
                    f,
                    "invalid rate_limit.scope `{scope}`: expected per_connector, per_zone, or per_principal"
                )
            }
            Self::EmptyPoolName => write!(f, "rate_limit.pool_name cannot be empty"),
            Self::InvalidPoolName { pool_name } => {
                write!(
                    f,
                    "invalid rate_limit.pool_name `{pool_name}`: must contain only alphanumeric, underscore, hyphen, or dot"
                )
            }
        }
    }
}

impl std::error::Error for RateLimitValidationError {}

/// Verifies capability tokens against the host's public key.
#[derive(Debug, Clone)]
pub struct CapabilityVerifier {
    /// Host's Ed25519 public key (issuance key)
    pub host_public_key: [u8; 32],

    /// Zone this connector is bound to
    pub zone_id: ZoneId,

    /// Instance ID for this connector
    pub instance_id: InstanceId,
}

impl CapabilityVerifier {
    /// Create a new capability verifier.
    #[must_use]
    pub const fn new(host_public_key: [u8; 32], zone_id: ZoneId, instance_id: InstanceId) -> Self {
        Self {
            host_public_key,
            zone_id,
            instance_id,
        }
    }

    /// Helper to deserialize CBOR value
    fn deserialize_cbor<T: serde::de::DeserializeOwned>(value: &ciborium::Value) -> FcpResult<T> {
        let mut bytes = Vec::new();
        ciborium::into_writer(value, &mut bytes).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })?;
        ciborium::from_reader(&bytes[..]).map_err(|e| FcpError::Internal {
            message: format!("Deserialization error: {e}"),
        })
    }

    /// Verify a capability token.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is invalid, claims are missing/expired,
    /// zone binding fails, or the operation is not granted.
    pub fn verify(
        &self,
        token: &CapabilityToken,
        required_capability: &CapabilityId,
        operation: &OperationId,
        resource_uris: &[String],
    ) -> FcpResult<CwtClaims> {
        let verifying_key =
            Ed25519VerifyingKey::from_bytes(&self.host_public_key).map_err(|_| {
                FcpError::Internal {
                    message: "Invalid host key".into(),
                }
            })?;

        // 1. Verify signature and extract claims
        let claims = token
            .raw
            .verify(&verifying_key)
            .map_err(|_| FcpError::InvalidSignature)?;

        // 2. Validate timing
        let now = Utc::now();
        CoseToken::validate_timing(&claims, now).map_err(|e| match e {
            fcp_crypto::CryptoError::TokenNotYetValid => FcpError::TokenNotYetValid,
            _ => FcpError::TokenExpired,
        })?;

        // 3. Check zone binding
        if let Some(iss) = claims.get_zone_id() {
            if iss != self.zone_id.as_str() {
                return Err(FcpError::ZoneViolation {
                    source_zone: iss.into(),
                    target_zone: self.zone_id.0.to_string(),
                    message: "Token zone mismatch".into(),
                });
            }
        } else {
            return Err(FcpError::MissingField {
                field: "iss_zone".into(),
            });
        }

        // 3.5. Check instance binding if present
        if let Some(inst_val) = claims.get(fcp2_claims::INSTANCE_ID) {
            if let Some(inst_str) = inst_val.as_text() {
                if inst_str != self.instance_id.as_str() {
                    return Err(FcpError::ZoneViolation {
                        source_zone: self.zone_id.0.to_string(),
                        target_zone: self.zone_id.0.to_string(),
                        message: format!(
                            "Token instance mismatch: expected {}, got {}",
                            self.instance_id.as_str(),
                            inst_str
                        ),
                    });
                }
            }
        }

        // 4. Check operation grant
        // Extract 'caps' claim and check if operation is allowed
        // 'caps' is array of CapabilityGrant
        if let Some(caps_val) = claims.get(fcp2_claims::GRANTS) {
            // Deserialize CapabilityGrant array
            let grants: Vec<CapabilityGrant> = Self::deserialize_cbor(caps_val)?;

            let op_allowed = grants.iter().any(|g| {
                // Must match the required capability
                if g.capability != *required_capability {
                    return false;
                }
                // Must match the operation (or be a wildcard)
                g.operation.as_ref().is_none_or(|op| op == operation)
            });

            if !op_allowed {
                return Err(FcpError::OperationNotGranted {
                    operation: operation.0.to_string(),
                });
            }
        } else {
            // Fallback to checking fcp2_claims::OPERATIONS if legacy/simplified?
            // The builder uses fcp2_claims::OPERATIONS for string list.
            // Let's check that too.
            if let Some(ops_val) = claims.get(fcp2_claims::OPERATIONS) {
                // Check if the token is for the required capability
                if let Some(cap_id) = claims.get_capability_id() {
                    if cap_id != required_capability.as_str() {
                        return Err(FcpError::OperationNotGranted {
                            operation: operation.0.to_string(),
                        });
                    }
                } else {
                    return Err(FcpError::MissingField {
                        field: "cap_id".into(),
                    });
                }

                // Array of strings
                let ops: Vec<String> = Self::deserialize_cbor(ops_val)?;
                if !ops.iter().any(|o| o == operation.as_str()) {
                    return Err(FcpError::OperationNotGranted {
                        operation: operation.0.to_string(),
                    });
                }
            } else {
                return Err(FcpError::MissingField {
                    field: "caps/operations".into(),
                });
            }
        }

        // 5. Enforce constraints
        if let Some(constr_val) = claims.get(fcp2_claims::CONSTRAINTS) {
            let constraints: CapabilityConstraints = Self::deserialize_cbor(constr_val)?;
            Self::enforce_resource_constraints(&constraints, resource_uris)?;
        }

        Ok(claims)
    }

    fn enforce_resource_constraints(
        constraints: &CapabilityConstraints,
        resource_uris: &[String],
    ) -> FcpResult<()> {
        // Check allow list
        if !constraints.resource_allow.is_empty() {
            for uri in resource_uris {
                let is_allowed = constraints
                    .resource_allow
                    .iter()
                    .any(|pattern| pattern_matches(pattern, uri));
                if !is_allowed {
                    return Err(FcpError::ResourceNotAllowed {
                        resource: uri.clone(),
                    });
                }
            }
        }

        // Check deny list
        for uri in resource_uris {
            if constraints
                .resource_deny
                .iter()
                .any(|pattern| pattern_matches(pattern, uri))
            {
                return Err(FcpError::ResourceNotAllowed {
                    resource: uri.clone(),
                });
            }
        }

        Ok(())
    }
}

/// Risk level for operations and capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Safety tier classification for tools and operations.
///
/// **Purpose:** Classifies the safety level of a tool or operation for agent decision-making.
/// Determines what approval/authorization is needed before an agent can execute the operation.
///
/// **Usage:**
/// - Tool descriptors: `ToolDescriptor.safety_tier`
/// - Operation metadata: `OperationMeta.safety_tier`
/// - Provenance validation: `can_drive_operation(tier)`
/// - CLI filtering: `--max-safety safe`
///
/// **Note:** This is distinct from [`RiskTier`] in `quorum.rs`, which classifies
/// quorum/consensus requirements for distributed operations. `SafetyTier` is about
/// "can this agent do this?", while `RiskTier` is about "how many signatures are needed?".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyTier {
    /// Safe operations: no approval needed, read-only or benign
    Safe,
    /// Risky operations: requires policy check, may have side effects
    Risky,
    /// Dangerous operations: requires interactive approval
    Dangerous,
    /// Critical system operations: requires quorum/elevation
    Critical,
    /// Forbidden: never allowed under any circumstances
    Forbidden,
}

/// Idempotency classification for operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdempotencyClass {
    /// No idempotency guarantees
    None,
    /// Best-effort deduplication
    BestEffort,
    /// Strict idempotency with key
    Strict,
}

/// Retry configuration for operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    pub max_attempts: u32,

    /// Initial delay between retries
    #[serde(with = "duration_millis")]
    pub initial_delay: Duration,

    /// Maximum delay between retries
    #[serde(with = "duration_millis")]
    pub max_delay: Duration,

    /// Multiplier for exponential backoff
    pub multiplier: f64,
}

mod duration_millis {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        u64::try_from(duration.as_millis())
            .unwrap_or(u64::MAX)
            .serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let millis = u64::deserialize(deserializer)?;
        Ok(Duration::from_millis(millis))
    }
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(30),
            multiplier: 2.0,
        }
    }
}

/// Retry with exponential backoff.
///
/// # Errors
///
/// Returns the final non-retryable error from `operation`, or the last retryable error once
/// `max_attempts` is exhausted.
pub async fn retry_with_backoff<F, Fut, T>(config: &RetryConfig, mut operation: F) -> FcpResult<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = FcpResult<T>>,
{
    let mut delay = config.initial_delay;
    let mut attempt = 0;

    loop {
        attempt += 1;
        match operation().await {
            Ok(result) => return Ok(result),
            Err(e) if e.is_retryable() && attempt < config.max_attempts => {
                if let Some(retry_after) = e.retry_after() {
                    time::sleep(retry_after).await;
                } else {
                    time::sleep(delay).await;
                    delay = std::cmp::min(
                        Duration::from_secs_f64(delay.as_secs_f64() * config.multiplier),
                        config.max_delay,
                    );
                }
            }
            Err(e) => return Err(e),
        }
    }
}

/// Correlation identifier for request tracing.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CorrelationId(pub Uuid);

impl CorrelationId {
    /// Generate a new random correlation ID.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for CorrelationId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for CorrelationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Session identifier - unique ID for a handshake session.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub Uuid);

impl SessionId {
    /// Generate a new random session ID.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Principal - an identity making requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Principal {
    /// Type of principal (e.g., "user", "agent", "service", "webhook")
    pub kind: String,

    /// Unique identifier for this principal
    pub id: String,

    /// Trust level of this principal
    pub trust: TrustLevel,

    /// Display name for humans
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
}

/// Trust level for principals.
///
/// Per FCP Specification Section 6.5 (Ingress Bindings):
/// These are the canonical trust levels for external principals.
/// Order is from lowest to highest trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustLevel {
    /// Explicitly denied access
    Blocked,
    /// Unauthenticated user
    Anonymous,
    /// Authenticated but not approved
    Untrusted,
    /// Explicitly approved external user
    Paired,
    /// Elevated but not root
    Admin,
    /// Root trust (owner)
    Owner,
}

/// Taint level for provenance tracking.
///
/// Per FCP Specification Section 7.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub enum TaintLevel {
    /// Trusted source only
    #[default]
    Untainted,
    /// Untrusted input present in chain
    Tainted,
    /// Direct untrusted instruction
    HighlyTainted,
}

/// A step in the provenance chain.
///
/// Per FCP Specification Section 7.2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceStep {
    /// Timestamp in milliseconds since epoch
    pub timestamp_ms: u64,

    /// Zone where this step occurred
    pub zone: ZoneId,

    /// Actor (agent/user/connector id)
    pub actor: String,

    /// Action performed (e.g., "discord.message", "tool.invoke")
    pub action: String,

    /// Resource URI or capability identifier
    pub resource: String,
}

/// Provenance metadata for tracking data origin.
///
/// Per FCP Specification Section 7.2:
/// - `origin_zone`: Where the triggering input originated
/// - `chain`: Monotonic chain of causal steps
/// - `taint`: Highest taint severity observed in the chain
/// - `elevated`: Whether explicit elevation has been granted
/// - `elevation_token`: Token proving elevation (if elevated)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provenance {
    /// The zone where the request/data originated
    pub origin_zone: ZoneId,

    /// Monotonic chain of causal steps
    #[serde(default)]
    pub chain: Vec<ProvenanceStep>,

    /// Highest taint severity observed in the chain
    #[serde(default)]
    pub taint: TaintLevel,

    /// Whether this request has been elevated
    #[serde(default)]
    pub elevated: bool,

    /// Elevation token if elevated
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elevation_token: Option<String>,
}

impl Provenance {
    /// Create provenance from an origin zone.
    #[must_use]
    pub const fn new(origin_zone: ZoneId) -> Self {
        Self {
            origin_zone,
            chain: Vec::new(),
            taint: TaintLevel::Untainted,
            elevated: false,
            elevation_token: None,
        }
    }

    /// Create tainted provenance from an untrusted source.
    #[must_use]
    pub const fn tainted(origin_zone: ZoneId) -> Self {
        Self {
            origin_zone,
            chain: Vec::new(),
            taint: TaintLevel::Tainted,
            elevated: false,
            elevation_token: None,
        }
    }

    /// Create highly tainted provenance from a direct untrusted instruction.
    #[must_use]
    pub const fn highly_tainted(origin_zone: ZoneId) -> Self {
        Self {
            origin_zone,
            chain: Vec::new(),
            taint: TaintLevel::HighlyTainted,
            elevated: false,
            elevation_token: None,
        }
    }

    /// Add a step to the provenance chain.
    #[must_use]
    pub fn with_step(mut self, step: ProvenanceStep) -> Self {
        self.chain.push(step);
        self
    }

    /// Mark as elevated with a token.
    #[must_use]
    pub fn elevated_with(mut self, token: impl Into<String>) -> Self {
        self.elevated = true;
        self.elevation_token = Some(token.into());
        self
    }

    /// Check if this provenance is tainted.
    #[must_use]
    pub const fn is_tainted(&self) -> bool {
        !matches!(self.taint, TaintLevel::Untainted)
    }

    /// Check if this provenance can access a higher-trust zone.
    ///
    /// Per FCP spec, tainted provenance cannot access higher-trust zones
    /// without explicit elevation.
    #[must_use]
    pub const fn can_access_higher_trust(&self) -> bool {
        !self.is_tainted() || self.elevated
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;

    // ─────────────────────────────────────────────────────────────────────────
    // Canonical ID Validation Tests (FCP Spec §3.4.2)
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn canonical_id_valid_simple() {
        assert!(validate_canonical_id("hello").is_ok());
        assert!(validate_canonical_id("a").is_ok());
        assert!(validate_canonical_id("0").is_ok());
        assert!(validate_canonical_id("test123").is_ok());
    }

    #[test]
    fn canonical_id_reject_uppercase() {
        assert_eq!(
            validate_canonical_id("Hello"),
            Err(IdValidationError::UppercaseNotAllowed)
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CapabilityVerifier Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn verify_capability_token() {
        // 1. Generate keys
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let pub_bytes = verifying_key.to_bytes();

        // 2. Create token data
        let now = Utc::now();
        let expires = now + Duration::hours(1);

        let cose_token = CapabilityTokenBuilder::new()
            .capability_id("cap.test")
            .zone_id("z:work")
            .principal("user:test")
            .operations(&["op.test"])
            .issuer("node:primary")
            .validity(now, expires)
            .sign(&signing_key)
            .expect("Failed to sign token");

        // 3. Wrap in CapabilityToken
        let token = CapabilityToken { raw: cose_token };

        // 4. Verify
        let verifier = CapabilityVerifier::new(pub_bytes, ZoneId::work(), InstanceId::new());

        let op = OperationId::new("op.test").unwrap();
        let cap = CapabilityId::new("cap.test").unwrap();

        let claims = verifier
            .verify(&token, &cap, &op, &[])
            .expect("Verification failed");

        assert_eq!(claims.get_capability_id(), Some("cap.test"));
    }

    #[test]
    fn verify_rejects_capability_mismatch() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let pub_bytes = verifying_key.to_bytes();

        let now = Utc::now();
        // Token grants "cap.benign" with operations "op.test"
        let cose_token = CapabilityTokenBuilder::new()
            .capability_id("cap.benign")
            .zone_id("z:work")
            .principal("user:test")
            .operations(&["op.test"])
            .issuer("node:primary")
            .validity(now, now + Duration::hours(1))
            .sign(&signing_key)
            .unwrap();

        let token = CapabilityToken { raw: cose_token };
        let verifier = CapabilityVerifier::new(pub_bytes, ZoneId::work(), InstanceId::new());

        let op = OperationId::new("op.test").unwrap();
        // We TRY to use "cap.critical"
        let required_cap = CapabilityId::new("cap.critical").unwrap();

        let result = verifier.verify(&token, &required_cap, &op, &[]);
        assert!(matches!(result, Err(FcpError::OperationNotGranted { .. })));
    }

    #[test]
    fn verify_rejects_wrong_zone() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let pub_bytes = verifying_key.to_bytes();

        let now = Utc::now();
        let cose_token = CapabilityTokenBuilder::new()
            .capability_id("cap.test")
            .zone_id("z:wrong") // Wrong zone
            .principal("user:test")
            .operations(&["op.test"])
            .issuer("node:primary")
            .validity(now, now + Duration::hours(1))
            .sign(&signing_key)
            .unwrap();

        let token = CapabilityToken { raw: cose_token };
        let verifier = CapabilityVerifier::new(pub_bytes, ZoneId::work(), InstanceId::new());
        let op = OperationId::new("op.test").unwrap();
        let cap = CapabilityId::new("cap.test").unwrap();

        let result = verifier.verify(&token, &cap, &op, &[]);
        assert!(matches!(result, Err(FcpError::ZoneViolation { .. })));
    }

    #[test]
    fn verify_rejects_expired() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let pub_bytes = verifying_key.to_bytes();

        let now = Utc::now();
        let cose_token = CapabilityTokenBuilder::new()
            .capability_id("cap.test")
            .zone_id("z:work")
            .principal("user:test")
            .operations(&["op.test"])
            .issuer("node:primary")
            .validity(now - Duration::hours(2), now - Duration::hours(1)) // Expired
            .sign(&signing_key)
            .unwrap();

        let token = CapabilityToken { raw: cose_token };
        let verifier = CapabilityVerifier::new(pub_bytes, ZoneId::work(), InstanceId::new());
        let op = OperationId::new("op.test").unwrap();
        let cap = CapabilityId::new("cap.test").unwrap();

        let result = verifier.verify(&token, &cap, &op, &[]);
        assert!(matches!(result, Err(FcpError::TokenExpired)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CapabilityConstraints Credential Allow Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn credential_allow_empty_denies_all() {
        let constraints = CapabilityConstraints::default();
        let cred_id = CredentialId::new();

        assert!(!constraints.is_credential_allowed(&cred_id));
        assert!(constraints.validate_credential(&cred_id).is_err());
    }

    #[test]
    fn credential_allow_permits_listed_credential() {
        let cred_id1 = CredentialId::new();
        let cred_id2 = CredentialId::new();

        let constraints = CapabilityConstraints {
            credential_allow: vec![cred_id1, cred_id2],
            ..Default::default()
        };

        assert!(constraints.is_credential_allowed(&cred_id1));
        assert!(constraints.is_credential_allowed(&cred_id2));
        assert!(constraints.validate_credential(&cred_id1).is_ok());
        assert!(constraints.validate_credential(&cred_id2).is_ok());
    }

    #[test]
    fn credential_allow_denies_unlisted_credential() {
        let allowed_cred = CredentialId::new();
        let denied_cred = CredentialId::new();

        let constraints = CapabilityConstraints {
            credential_allow: vec![allowed_cred],
            ..Default::default()
        };

        assert!(!constraints.is_credential_allowed(&denied_cred));
        let result = constraints.validate_credential(&denied_cred);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(
            matches!(
                &err,
                CredentialValidationError::NotInCredentialAllow { credential_id } if *credential_id == denied_cred
            ),
            "Expected NotInCredentialAllow error, got {err:?}"
        );
    }

    #[test]
    fn credential_allow_with_multiple_credentials() {
        let cred1 = CredentialId::new();
        let cred2 = CredentialId::new();
        let cred3 = CredentialId::new();
        let denied_cred = CredentialId::new();

        let constraints = CapabilityConstraints {
            credential_allow: vec![cred1, cred2, cred3],
            ..Default::default()
        };

        // All listed should be allowed
        assert!(constraints.is_credential_allowed(&cred1));
        assert!(constraints.is_credential_allowed(&cred2));
        assert!(constraints.is_credential_allowed(&cred3));

        // Unlisted should be denied
        assert!(!constraints.is_credential_allowed(&denied_cred));
    }

    #[test]
    fn credential_allow_error_contains_credential_id() {
        let denied_cred = CredentialId::new();
        let allowed_cred = CredentialId::new();

        let constraints = CapabilityConstraints {
            credential_allow: vec![allowed_cred],
            ..Default::default()
        };

        let result = constraints.validate_credential(&denied_cred);
        assert!(result.is_err());

        // Verify the error message contains the credential ID
        let err = result.unwrap_err();
        let err_string = err.to_string();
        assert!(err_string.contains(&denied_cred.to_string()));
        assert!(err_string.contains("credential_allow"));
    }

    #[test]
    fn credential_constraints_serialization_includes_credential_allow() {
        let cred_id = CredentialId::new();
        let constraints = CapabilityConstraints {
            credential_allow: vec![cred_id],
            resource_allow: vec!["/api/v1/*".into()],
            ..Default::default()
        };

        let json = serde_json::to_string(&constraints).unwrap();
        assert!(json.contains("credential_allow"));
        assert!(json.contains(&cred_id.to_string()));

        let decoded: CapabilityConstraints = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.credential_allow.len(), 1);
        assert_eq!(decoded.credential_allow[0], cred_id);
    }

    #[test]
    fn credential_constraints_empty_credential_allow_omitted_in_json() {
        let constraints = CapabilityConstraints {
            resource_allow: vec!["/api/*".into()],
            ..Default::default()
        };

        let json = serde_json::to_string(&constraints).unwrap();
        // Empty vecs should be omitted per #[serde(skip_serializing_if = "Vec::is_empty")]
        assert!(!json.contains("credential_allow"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Type Naming Standardization Tests (SafetyTier vs RiskTier)
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn safety_tier_vs_risk_tier_are_distinct() {
        // These are different types for different purposes:
        // - SafetyTier: tool/operation safety classification
        // - RiskTier (in quorum.rs): quorum/consensus requirements
        //
        // They share similar variant names but have different semantics:
        // - SafetyTier has 5 levels: Safe, Risky, Dangerous, Critical, Forbidden
        // - RiskTier has 4 levels: Safe, Risky, Dangerous, CriticalWrite

        // SafetyTier variant order (for documentation)
        assert!(matches!(SafetyTier::Safe, SafetyTier::Safe));
        assert!(matches!(SafetyTier::Risky, SafetyTier::Risky));
        assert!(matches!(SafetyTier::Dangerous, SafetyTier::Dangerous));
        assert!(matches!(SafetyTier::Critical, SafetyTier::Critical));
        assert!(matches!(SafetyTier::Forbidden, SafetyTier::Forbidden));

        // Verify SafetyTier serialization
        let tiers = [
            (SafetyTier::Safe, "safe"),
            (SafetyTier::Risky, "risky"),
            (SafetyTier::Dangerous, "dangerous"),
            (SafetyTier::Critical, "critical"),
            (SafetyTier::Forbidden, "forbidden"),
        ];

        for (tier, expected) in tiers {
            let json = serde_json::to_string(&tier).unwrap();
            assert!(
                json.contains(expected),
                "SafetyTier::{tier:?} should serialize to contain '{expected}'"
            );
        }
    }

    #[test]
    fn safety_tier_serialization_roundtrip() {
        let tiers = [
            SafetyTier::Safe,
            SafetyTier::Risky,
            SafetyTier::Dangerous,
            SafetyTier::Critical,
            SafetyTier::Forbidden,
        ];

        for tier in tiers {
            let json = serde_json::to_string(&tier).unwrap();
            let parsed: SafetyTier = serde_json::from_str(&json).unwrap();
            assert_eq!(tier, parsed);
        }
    }

    // ── validate_canonical_id ────────────────────────────────────────────

    #[test]
    fn canonical_id_rejects_empty() {
        assert_eq!(validate_canonical_id(""), Err(IdValidationError::Empty));
    }

    #[test]
    fn canonical_id_rejects_too_long() {
        let long = "a".repeat(129);
        assert!(matches!(
            validate_canonical_id(&long),
            Err(IdValidationError::TooLong { len: 129, max: 128 })
        ));
        // Exactly 128 should be ok
        let exact = "a".repeat(128);
        assert!(validate_canonical_id(&exact).is_ok());
    }

    #[test]
    fn canonical_id_rejects_non_ascii() {
        assert_eq!(
            validate_canonical_id("héllo"),
            Err(IdValidationError::NonAscii)
        );
    }

    #[test]
    fn canonical_id_rejects_invalid_start_char() {
        assert!(matches!(
            validate_canonical_id(".test"),
            Err(IdValidationError::InvalidStartChar { ch: '.' })
        ));
        assert!(matches!(
            validate_canonical_id("-test"),
            Err(IdValidationError::InvalidStartChar { ch: '-' })
        ));
    }

    #[test]
    fn canonical_id_rejects_invalid_char() {
        assert!(matches!(
            validate_canonical_id("test@value"),
            Err(IdValidationError::InvalidChar { ch: '@', .. })
        ));
        assert!(matches!(
            validate_canonical_id("test value"),
            Err(IdValidationError::InvalidChar { ch: ' ', .. })
        ));
    }

    #[test]
    fn canonical_id_allows_all_valid_chars() {
        assert!(validate_canonical_id("abc.def_ghi:jkl-mno").is_ok());
        assert!(validate_canonical_id("0123456789").is_ok());
        assert!(validate_canonical_id("a:b:c").is_ok());
    }

    // ── Identifier types ───────────────────────────────────────────────────

    #[test]
    fn capability_id_serde_roundtrip() {
        let id = CapabilityId::new("cap.read").unwrap();
        let json = serde_json::to_string(&id).unwrap();
        let back: CapabilityId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn capability_id_display() {
        let id = CapabilityId::new("cap.read").unwrap();
        assert_eq!(id.to_string(), "cap.read");
    }

    #[test]
    fn capability_id_from_str() {
        let id: CapabilityId = "cap.write".parse().unwrap();
        assert_eq!(id.as_str(), "cap.write");
        assert!("BAD".parse::<CapabilityId>().is_err());
    }

    #[test]
    fn connector_id_three_part() {
        let id = ConnectorId::new("gmail", "fcp2", "1.0").unwrap();
        assert_eq!(id.as_str(), "gmail:fcp2:1.0");
    }

    #[test]
    fn connector_id_from_static() {
        let id = ConnectorId::from_static("test:conn:v1");
        assert_eq!(id.as_str(), "test:conn:v1");
    }

    #[test]
    fn connector_id_serde_roundtrip() {
        let id = ConnectorId::from_static("discord:fcp2:1.0");
        let json = serde_json::to_string(&id).unwrap();
        let back: ConnectorId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn instance_id_is_unique() {
        let a = InstanceId::new();
        let b = InstanceId::new();
        assert_ne!(a.as_str(), b.as_str());
    }

    #[test]
    fn instance_id_default_same_as_new() {
        let d = InstanceId::default();
        assert!(d.as_str().starts_with("inst_"));
    }

    #[test]
    fn instance_id_display() {
        let id = InstanceId::new();
        assert!(id.as_str().starts_with("inst_"));
        assert_eq!(id.as_str(), id.to_string());
    }

    #[test]
    fn operation_id_from_static() {
        let id = OperationId::from_static("op.send");
        assert_eq!(id.as_str(), "op.send");
    }

    #[test]
    fn operation_id_serde_roundtrip() {
        let id = OperationId::new("op.test").unwrap();
        let json = serde_json::to_string(&id).unwrap();
        let back: OperationId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn principal_id_serde_roundtrip() {
        let id = PrincipalId::new("user:alice").unwrap();
        let json = serde_json::to_string(&id).unwrap();
        let back: PrincipalId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    // ── ZoneId ─────────────────────────────────────────────────────────────

    #[test]
    fn zone_id_standard_zones() {
        assert_eq!(ZoneId::owner().as_str(), "z:owner");
        assert_eq!(ZoneId::private().as_str(), "z:private");
        assert_eq!(ZoneId::work().as_str(), "z:work");
        assert_eq!(ZoneId::community().as_str(), "z:community");
        assert_eq!(ZoneId::public().as_str(), "z:public");
    }

    #[test]
    fn zone_id_parse_valid() {
        let z: ZoneId = "z:work".parse().unwrap();
        assert_eq!(z.as_str(), "z:work");
    }

    #[test]
    fn zone_id_rejects_missing_prefix() {
        assert!(matches!(
            "work".parse::<ZoneId>(),
            Err(ZoneIdError::MissingPrefix)
        ));
    }

    #[test]
    fn zone_id_rejects_empty() {
        assert!(matches!("".parse::<ZoneId>(), Err(ZoneIdError::Empty)));
    }

    #[test]
    fn zone_id_rejects_too_long() {
        let long = format!("z:{}", "a".repeat(63));
        assert!(matches!(
            long.parse::<ZoneId>(),
            Err(ZoneIdError::TooLong { .. })
        ));
    }

    #[test]
    fn zone_id_hash_deterministic() {
        let z1 = ZoneId::work();
        let z2 = ZoneId::work();
        assert_eq!(z1.hash().as_bytes(), z2.hash().as_bytes());
    }

    #[test]
    fn zone_id_hash_differs_across_zones() {
        assert_ne!(
            ZoneId::work().hash().as_bytes(),
            ZoneId::owner().hash().as_bytes()
        );
    }

    #[test]
    fn zone_id_to_tailscale_tag() {
        assert_eq!(ZoneId::work().to_tailscale_tag(), "tag:fcp-work");
        assert_eq!(ZoneId::owner().to_tailscale_tag(), "tag:fcp-owner");
    }

    #[test]
    fn zone_id_from_tailscale_tag() {
        let z = ZoneId::from_tailscale_tag("tag:fcp-work").unwrap();
        assert_eq!(z.as_str(), "z:work");
    }

    #[test]
    fn zone_id_from_tailscale_tag_rejects_invalid() {
        assert!(matches!(
            ZoneId::from_tailscale_tag("tag:wrong-work"),
            Err(ZoneIdError::InvalidTailscaleTagPrefix)
        ));
    }

    #[test]
    fn zone_id_serde_roundtrip() {
        let z = ZoneId::work();
        let json = serde_json::to_string(&z).unwrap();
        let back: ZoneId = serde_json::from_str(&json).unwrap();
        assert_eq!(z, back);
    }

    // ── RateLimit ──────────────────────────────────────────────────────────

    #[test]
    fn rate_limit_validate_ok() {
        let rl = RateLimit {
            max: 10,
            per_ms: 60_000,
            burst: Some(5),
            scope: Some("per_zone".into()),
            pool_name: Some("shared.pool".into()),
        };
        assert!(rl.validate().is_ok());
    }

    #[test]
    fn rate_limit_validate_zero_max() {
        let rl = RateLimit {
            max: 0,
            per_ms: 1000,
            burst: None,
            scope: None,
            pool_name: None,
        };
        assert_eq!(rl.validate(), Err(RateLimitValidationError::ZeroMax));
    }

    #[test]
    fn rate_limit_validate_zero_period() {
        let rl = RateLimit {
            max: 10,
            per_ms: 0,
            burst: None,
            scope: None,
            pool_name: None,
        };
        assert_eq!(rl.validate(), Err(RateLimitValidationError::ZeroPeriod));
    }

    #[test]
    fn rate_limit_validate_invalid_scope() {
        let rl = RateLimit {
            max: 10,
            per_ms: 1000,
            burst: None,
            scope: Some("bad".into()),
            pool_name: None,
        };
        assert!(matches!(
            rl.validate(),
            Err(RateLimitValidationError::InvalidScope { .. })
        ));
    }

    #[test]
    fn rate_limit_validate_empty_pool_name() {
        let rl = RateLimit {
            max: 10,
            per_ms: 1000,
            burst: None,
            scope: None,
            pool_name: Some(String::new()),
        };
        assert_eq!(rl.validate(), Err(RateLimitValidationError::EmptyPoolName));
    }

    #[test]
    fn rate_limit_validate_invalid_pool_name() {
        let rl = RateLimit {
            max: 10,
            per_ms: 1000,
            burst: None,
            scope: None,
            pool_name: Some("a b".into()),
        };
        assert!(matches!(
            rl.validate(),
            Err(RateLimitValidationError::InvalidPoolName { .. })
        ));
    }

    #[test]
    fn rate_limit_parsed_scope_default() {
        let rl = RateLimit {
            max: 10,
            per_ms: 1000,
            burst: None,
            scope: None,
            pool_name: None,
        };
        assert_eq!(rl.parsed_scope(), OperationRateLimitScope::PerConnector);
    }

    #[test]
    fn rate_limit_parsed_scope_explicit() {
        let rl = RateLimit {
            max: 10,
            per_ms: 1000,
            burst: None,
            scope: Some("per_principal".into()),
            pool_name: None,
        };
        assert_eq!(rl.parsed_scope(), OperationRateLimitScope::PerPrincipal);
    }

    // ── OperationRateLimitScope ────────────────────────────────────────────

    #[test]
    fn operation_rate_limit_scope_from_str() {
        assert_eq!(
            "per_connector".parse::<OperationRateLimitScope>().unwrap(),
            OperationRateLimitScope::PerConnector
        );
        assert_eq!(
            "per_zone".parse::<OperationRateLimitScope>().unwrap(),
            OperationRateLimitScope::PerZone
        );
        assert_eq!(
            "per_principal".parse::<OperationRateLimitScope>().unwrap(),
            OperationRateLimitScope::PerPrincipal
        );
        assert!("invalid".parse::<OperationRateLimitScope>().is_err());
    }

    #[test]
    fn operation_rate_limit_scope_display() {
        assert_eq!(
            OperationRateLimitScope::PerConnector.to_string(),
            "per_connector"
        );
        assert_eq!(OperationRateLimitScope::PerZone.to_string(), "per_zone");
        assert_eq!(
            OperationRateLimitScope::PerPrincipal.to_string(),
            "per_principal"
        );
    }

    #[test]
    fn operation_rate_limit_scope_default() {
        assert_eq!(
            OperationRateLimitScope::default(),
            OperationRateLimitScope::PerConnector
        );
    }

    // ── RetryConfig ────────────────────────────────────────────────────────

    #[test]
    fn retry_config_default_values() {
        let cfg = RetryConfig::default();
        assert_eq!(cfg.max_attempts, 3);
        assert_eq!(cfg.initial_delay, std::time::Duration::from_millis(100));
        assert_eq!(cfg.max_delay, std::time::Duration::from_secs(30));
        assert!((cfg.multiplier - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    fn retry_config_serde_roundtrip() {
        let cfg = RetryConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let back: RetryConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.max_attempts, cfg.max_attempts);
    }

    // ── TrustLevel ─────────────────────────────────────────────────────────

    #[test]
    fn trust_level_ordering() {
        assert!(TrustLevel::Blocked < TrustLevel::Anonymous);
        assert!(TrustLevel::Anonymous < TrustLevel::Untrusted);
        assert!(TrustLevel::Untrusted < TrustLevel::Paired);
        assert!(TrustLevel::Paired < TrustLevel::Admin);
        assert!(TrustLevel::Admin < TrustLevel::Owner);
    }

    #[test]
    fn trust_level_serde_roundtrip() {
        for level in [
            TrustLevel::Blocked,
            TrustLevel::Anonymous,
            TrustLevel::Untrusted,
            TrustLevel::Paired,
            TrustLevel::Admin,
            TrustLevel::Owner,
        ] {
            let json = serde_json::to_string(&level).unwrap();
            let back: TrustLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(level, back);
        }
    }

    // ── TaintLevel ─────────────────────────────────────────────────────────

    #[test]
    fn taint_level_default_is_untainted() {
        assert_eq!(TaintLevel::default(), TaintLevel::Untainted);
    }

    #[test]
    fn taint_level_ordering() {
        assert!(TaintLevel::Untainted < TaintLevel::Tainted);
        assert!(TaintLevel::Tainted < TaintLevel::HighlyTainted);
    }

    // ── Provenance ─────────────────────────────────────────────────────────

    #[test]
    fn provenance_new_is_untainted() {
        let p = Provenance::new(ZoneId::work());
        assert!(!p.is_tainted());
        assert!(p.can_access_higher_trust());
        assert_eq!(p.origin_zone.as_str(), "z:work");
    }

    #[test]
    fn provenance_tainted() {
        let p = Provenance::tainted(ZoneId::public());
        assert!(p.is_tainted());
        assert!(!p.can_access_higher_trust());
    }

    #[test]
    fn provenance_highly_tainted() {
        let p = Provenance::highly_tainted(ZoneId::public());
        assert!(p.is_tainted());
        assert_eq!(p.taint, TaintLevel::HighlyTainted);
    }

    #[test]
    fn provenance_elevated_can_access_higher() {
        let p = Provenance::tainted(ZoneId::public()).elevated_with("high-elev-token");
        assert!(p.is_tainted());
        assert!(p.can_access_higher_trust());
        assert_eq!(p.elevation_token.as_deref(), Some("high-elev-token"));
    }

    #[test]
    fn provenance_with_step() {
        let step = ProvenanceStep {
            timestamp_ms: 1000,
            zone: ZoneId::work(),
            actor: "agent:bot".into(),
            action: "invoke".into(),
            resource: "cap.read".into(),
        };
        let p = Provenance::new(ZoneId::work()).with_step(step);
        assert_eq!(p.chain.len(), 1);
    }

    // ── IdempotencyClass ───────────────────────────────────────────────────

    #[test]
    fn idempotency_class_serde_roundtrip() {
        for class in [
            IdempotencyClass::None,
            IdempotencyClass::BestEffort,
            IdempotencyClass::Strict,
        ] {
            let json = serde_json::to_string(&class).unwrap();
            let back: IdempotencyClass = serde_json::from_str(&json).unwrap();
            assert_eq!(class, back);
        }
    }

    // ── CorrelationId / SessionId ──────────────────────────────────────────

    #[test]
    fn correlation_id_unique() {
        let a = CorrelationId::new();
        let b = CorrelationId::new();
        assert_ne!(a, b);
    }

    #[test]
    fn session_id_unique() {
        let a = SessionId::new();
        let b = SessionId::new();
        assert_ne!(a, b);
    }

    // ── CapabilityGrant ────────────────────────────────────────────────────

    #[test]
    fn capability_grant_serde_roundtrip() {
        let grant = CapabilityGrant {
            capability: CapabilityId::new("cap.read").unwrap(),
            operation: Some(OperationId::new("op.list").unwrap()),
        };
        let json = serde_json::to_string(&grant).unwrap();
        let back: CapabilityGrant = serde_json::from_str(&json).unwrap();
        assert_eq!(grant, back);
    }

    #[test]
    fn capability_grant_omits_none_operation() {
        let grant = CapabilityGrant {
            capability: CapabilityId::new("cap.all").unwrap(),
            operation: None,
        };
        let json = serde_json::to_string(&grant).unwrap();
        assert!(!json.contains("operation"));
    }

    // ── RiskLevel ──────────────────────────────────────────────────────────

    #[test]
    fn risk_level_serde_roundtrip() {
        for level in [
            RiskLevel::Low,
            RiskLevel::Medium,
            RiskLevel::High,
            RiskLevel::Critical,
        ] {
            let json = serde_json::to_string(&level).unwrap();
            let back: RiskLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(level, back);
        }
    }

    #[test]
    fn risk_level_vs_safety_tier_are_distinct() {
        // RiskLevel: UX/prioritization (Low, Medium, High, Critical)
        // SafetyTier: normative enforcement (Safe, Risky, Dangerous, Critical, Forbidden)
        //
        // Both may be present in ToolDescriptor, each for different purposes.

        // RiskLevel serialization
        let levels = [
            (RiskLevel::Low, "low"),
            (RiskLevel::Medium, "medium"),
            (RiskLevel::High, "high"),
            (RiskLevel::Critical, "critical"),
        ];

        for (level, expected) in levels {
            let json = serde_json::to_string(&level).unwrap();
            assert!(
                json.contains(expected),
                "RiskLevel::{level:?} should serialize to contain '{expected}'"
            );
        }

        // SafetyTier serialization (different enum, different values)
        let tiers = [
            (SafetyTier::Safe, "safe"),
            (SafetyTier::Forbidden, "forbidden"),
        ];

        for (tier, expected) in tiers {
            let json = serde_json::to_string(&tier).unwrap();
            assert!(
                json.contains(expected),
                "SafetyTier::{tier:?} should serialize to contain '{expected}'"
            );
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: CapabilityId edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn capability_id_rejects_empty() {
        assert!(matches!(
            CapabilityId::new(""),
            Err(IdValidationError::Empty)
        ));
    }

    #[test]
    fn capability_id_at_max_length_boundary() {
        // Exactly 128 bytes should succeed
        let max_id = "a".repeat(128);
        assert!(CapabilityId::new(max_id).is_ok());

        // 129 bytes should fail
        let over_id = "a".repeat(129);
        assert!(matches!(
            CapabilityId::new(over_id),
            Err(IdValidationError::TooLong { len: 129, max: 128 })
        ));
    }

    #[test]
    fn capability_id_with_multiple_colons() {
        // Multiple colons are valid per the regex `^[a-z0-9][a-z0-9._:-]*$`
        let id = CapabilityId::new("cap:scope:sub:detail").unwrap();
        assert_eq!(id.as_str(), "cap:scope:sub:detail");
    }

    #[test]
    fn capability_id_with_all_separator_types() {
        let id = CapabilityId::new("a.b_c:d-e").unwrap();
        assert_eq!(id.as_str(), "a.b_c:d-e");
    }

    #[test]
    fn capability_id_single_digit_start() {
        let id = CapabilityId::new("9cap").unwrap();
        assert_eq!(id.as_str(), "9cap");
    }

    #[test]
    fn capability_id_rejects_space_in_middle() {
        assert!(matches!(
            CapabilityId::new("cap read"),
            Err(IdValidationError::InvalidChar { ch: ' ', index: 3 })
        ));
    }

    #[test]
    fn capability_id_rejects_unicode_emoji() {
        assert!(matches!(
            CapabilityId::new("cap\u{1F600}"),
            Err(IdValidationError::NonAscii)
        ));
    }

    #[test]
    fn capability_id_rejects_starting_with_underscore() {
        assert!(matches!(
            CapabilityId::new("_cap"),
            Err(IdValidationError::InvalidStartChar { ch: '_' })
        ));
    }

    #[test]
    fn capability_id_rejects_starting_with_colon() {
        assert!(matches!(
            CapabilityId::new(":cap"),
            Err(IdValidationError::InvalidStartChar { ch: ':' })
        ));
    }

    #[test]
    fn capability_id_clone_preserves_value() {
        let original = CapabilityId::new("cap.read").unwrap();
        let cloned = original.clone();
        assert_eq!(original.as_str(), cloned.as_str());
    }

    #[test]
    fn capability_id_hash_equality() {
        use std::collections::HashSet;
        let id1 = CapabilityId::new("cap.test").unwrap();
        let id2 = CapabilityId::new("cap.test").unwrap();
        let mut set = HashSet::new();
        set.insert(id1);
        assert!(set.contains(&id2));
    }

    #[test]
    fn capability_id_as_ref_str() {
        let id = CapabilityId::new("cap.ref").unwrap();
        let s: &str = id.as_ref();
        assert_eq!(s, "cap.ref");
    }

    #[test]
    fn capability_id_into_string() {
        let id = CapabilityId::new("cap.owned").unwrap();
        let s: String = id.into();
        assert_eq!(s, "cap.owned");
    }

    #[test]
    #[should_panic(expected = "static capability ID must be canonical")]
    fn capability_id_from_static_panics_on_invalid() {
        let _ = CapabilityId::from_static("INVALID");
    }

    #[test]
    fn capability_id_debug_format() {
        let id = CapabilityId::new("cap.debug").unwrap();
        let dbg = format!("{id:?}");
        assert!(dbg.contains("cap.debug"));
    }

    #[test]
    fn capability_id_serde_rejects_invalid_json() {
        let result: Result<CapabilityId, _> = serde_json::from_str("\"UPPER\"");
        assert!(result.is_err());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: ConnectorId edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn connector_id_clone_preserves_value() {
        let original = ConnectorId::from_static("test:conn:v1");
        let cloned = original.clone();
        assert_eq!(original.as_str(), cloned.as_str());
    }

    #[test]
    fn connector_id_as_ref_str() {
        let id = ConnectorId::from_static("test:conn:v1");
        let s: &str = id.as_ref();
        assert_eq!(s, "test:conn:v1");
    }

    #[test]
    fn connector_id_into_string() {
        let id = ConnectorId::from_static("test:conn:v1");
        let s: String = id.into();
        assert_eq!(s, "test:conn:v1");
    }

    #[test]
    fn connector_id_display() {
        let id = ConnectorId::from_static("test:conn:v1");
        assert_eq!(id.to_string(), "test:conn:v1");
    }

    #[test]
    fn connector_id_rejects_uppercase_part() {
        assert!(ConnectorId::new("Gmail", "fcp2", "1.0").is_err());
    }

    #[test]
    #[should_panic(expected = "static connector ID must be canonical")]
    fn connector_id_from_static_panics_on_invalid() {
        let _ = ConnectorId::from_static("BAD ID");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: OperationId edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn operation_id_rejects_empty() {
        assert!(matches!(
            OperationId::new(""),
            Err(IdValidationError::Empty)
        ));
    }

    #[test]
    fn operation_id_clone_preserves_value() {
        let original = OperationId::from_static("op.send");
        let cloned = original.clone();
        assert_eq!(original.as_str(), cloned.as_str());
    }

    #[test]
    fn operation_id_display() {
        let id = OperationId::from_static("op.list");
        assert_eq!(id.to_string(), "op.list");
    }

    #[test]
    fn operation_id_as_ref_str() {
        let id = OperationId::from_static("op.get");
        let s: &str = id.as_ref();
        assert_eq!(s, "op.get");
    }

    #[test]
    #[should_panic(expected = "static operation ID must be canonical")]
    fn operation_id_from_static_panics_on_invalid() {
        let _ = OperationId::from_static("OP.INVALID");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: InstanceId edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn instance_id_starts_with_prefix() {
        let id = InstanceId::new();
        assert!(id.as_str().starts_with("inst_"));
    }

    #[test]
    fn instance_id_serde_roundtrip() {
        let id = InstanceId::new();
        let json = serde_json::to_string(&id).unwrap();
        let back: InstanceId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn instance_id_display_format() {
        let id = InstanceId::new();
        let displayed = id.to_string();
        assert!(displayed.starts_with("inst_"));
        assert_eq!(displayed, id.as_str());
    }

    #[test]
    fn instance_id_clone_preserves_value() {
        let original = InstanceId::new();
        let cloned = original.clone();
        assert_eq!(original.as_str(), cloned.as_str());
    }

    #[test]
    fn instance_id_as_ref_str() {
        let id = InstanceId::new();
        let s: &str = id.as_ref();
        assert!(s.starts_with("inst_"));
    }

    #[test]
    fn instance_id_into_string() {
        let id = InstanceId::new();
        let expected = id.as_str().to_owned();
        let s: String = id.into();
        assert_eq!(s, expected);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: PrincipalId edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn principal_id_display() {
        let id = PrincipalId::new("user:alice").unwrap();
        assert_eq!(id.to_string(), "user:alice");
    }

    #[test]
    fn principal_id_as_ref_str() {
        let id = PrincipalId::new("agent:bot").unwrap();
        let s: &str = id.as_ref();
        assert_eq!(s, "agent:bot");
    }

    #[test]
    fn principal_id_into_string() {
        let id = PrincipalId::new("user:bob").unwrap();
        let s: String = id.into();
        assert_eq!(s, "user:bob");
    }

    #[test]
    fn principal_id_rejects_uppercase() {
        assert!(matches!(
            PrincipalId::new("User:Alice"),
            Err(IdValidationError::UppercaseNotAllowed)
        ));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: ZoneId edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn zone_id_rejects_non_ascii() {
        assert!(matches!(
            "z:\u{00e9}l\u{00e8}ve".parse::<ZoneId>(),
            Err(ZoneIdError::NonAscii)
        ));
    }

    #[test]
    fn zone_id_rejects_invalid_char() {
        assert!(matches!(
            "z:work@home".parse::<ZoneId>(),
            Err(ZoneIdError::InvalidChar { ch: '@', .. })
        ));
    }

    #[test]
    fn zone_id_rejects_uppercase() {
        assert!(matches!(
            "z:Work".parse::<ZoneId>(),
            Err(ZoneIdError::InvalidChar { ch: 'W', .. })
        ));
    }

    #[test]
    fn zone_id_at_max_length_boundary() {
        // Exactly 64 bytes should succeed
        let max_zone = format!("z:{}", "a".repeat(62));
        assert_eq!(max_zone.len(), 64);
        assert!(max_zone.parse::<ZoneId>().is_ok());

        // 65 bytes should fail
        let over_zone = format!("z:{}", "a".repeat(63));
        assert_eq!(over_zone.len(), 65);
        assert!(matches!(
            over_zone.parse::<ZoneId>(),
            Err(ZoneIdError::TooLong { len: 65, max: 64 })
        ));
    }

    #[test]
    fn zone_id_clone_preserves_value() {
        let original = ZoneId::work();
        let cloned = original.clone();
        assert_eq!(original.as_str(), cloned.as_str());
    }

    #[test]
    fn zone_id_display() {
        let z = ZoneId::owner();
        assert_eq!(z.to_string(), "z:owner");
    }

    #[test]
    fn zone_id_as_ref_str() {
        let z = ZoneId::private();
        let s: &str = z.as_ref();
        assert_eq!(s, "z:private");
    }

    #[test]
    fn zone_id_into_string() {
        let z = ZoneId::community();
        let s: String = z.into();
        assert_eq!(s, "z:community");
    }

    #[test]
    fn zone_id_as_bytes() {
        let z = ZoneId::work();
        assert_eq!(z.as_bytes(), b"z:work");
    }

    #[test]
    fn zone_id_hash_from_bytes_roundtrip() {
        let z = ZoneId::work();
        let hash = z.hash();
        let reconstructed = ZoneIdHash::from_bytes(*hash.as_bytes());
        assert_eq!(hash, reconstructed);
    }

    #[test]
    fn zone_id_hash_debug_is_hex() {
        let z = ZoneId::work();
        let hash = z.hash();
        let dbg = format!("{hash:?}");
        assert!(dbg.starts_with("ZoneIdHash("));
        // The inner value should be hex
        assert!(dbg.contains(')'));
    }

    #[test]
    fn zone_id_hash_as_ref_bytes() {
        let z = ZoneId::work();
        let hash = z.hash();
        let bytes: &[u8] = hash.as_ref();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn zone_id_with_hyphens_and_underscores() {
        let z: ZoneId = "z:my-custom_zone".parse().unwrap();
        assert_eq!(z.as_str(), "z:my-custom_zone");
    }

    #[test]
    fn zone_id_tailscale_tag_roundtrip_standard_zones() {
        for zone in [
            ZoneId::owner(),
            ZoneId::private(),
            ZoneId::work(),
            ZoneId::community(),
            ZoneId::public(),
        ] {
            let tag = zone.to_tailscale_tag();
            let recovered = ZoneId::from_tailscale_tag(&tag).unwrap();
            assert_eq!(zone.as_str(), recovered.as_str());
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: ZoneIdError Display coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn zone_id_error_display_empty() {
        let err = ZoneIdError::Empty;
        assert_eq!(err.to_string(), "zone id must not be empty");
    }

    #[test]
    fn zone_id_error_display_too_long() {
        let err = ZoneIdError::TooLong { len: 100, max: 64 };
        assert_eq!(err.to_string(), "zone id too long (100 bytes > 64 bytes)");
    }

    #[test]
    fn zone_id_error_display_non_ascii() {
        let err = ZoneIdError::NonAscii;
        assert_eq!(err.to_string(), "zone id must be ASCII");
    }

    #[test]
    fn zone_id_error_display_missing_prefix() {
        let err = ZoneIdError::MissingPrefix;
        assert_eq!(err.to_string(), "zone id must start with `z:`");
    }

    #[test]
    fn zone_id_error_display_invalid_tailscale_tag() {
        let err = ZoneIdError::InvalidTailscaleTagPrefix;
        assert_eq!(err.to_string(), "tailscale tag must start with `tag:fcp-`");
    }

    #[test]
    fn zone_id_error_display_invalid_char() {
        let err = ZoneIdError::InvalidChar { ch: '!', index: 5 };
        assert_eq!(
            err.to_string(),
            "zone id has invalid character '!' at byte 5"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: IdValidationError Display coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn id_validation_error_display_empty() {
        let err = IdValidationError::Empty;
        assert_eq!(err.to_string(), "identifier must not be empty");
    }

    #[test]
    fn id_validation_error_display_too_long() {
        let err = IdValidationError::TooLong { len: 200, max: 128 };
        assert_eq!(
            err.to_string(),
            "identifier too long (200 bytes > 128 bytes)"
        );
    }

    #[test]
    fn id_validation_error_display_non_ascii() {
        let err = IdValidationError::NonAscii;
        assert_eq!(err.to_string(), "identifier must be ASCII");
    }

    #[test]
    fn id_validation_error_display_uppercase() {
        let err = IdValidationError::UppercaseNotAllowed;
        assert_eq!(err.to_string(), "identifier contains uppercase ASCII");
    }

    #[test]
    fn id_validation_error_display_invalid_start() {
        let err = IdValidationError::InvalidStartChar { ch: '-' };
        assert_eq!(
            err.to_string(),
            "identifier has invalid start character '-'"
        );
    }

    #[test]
    fn id_validation_error_display_invalid_char() {
        let err = IdValidationError::InvalidChar { ch: '!', index: 4 };
        assert_eq!(
            err.to_string(),
            "identifier has invalid character '!' at byte 4"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: CapabilityGrant edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn capability_grant_with_operation_includes_field() {
        let grant = CapabilityGrant {
            capability: CapabilityId::new("cap.write").unwrap(),
            operation: Some(OperationId::new("op.create").unwrap()),
        };
        let json = serde_json::to_string(&grant).unwrap();
        assert!(json.contains("operation"));
        assert!(json.contains("op.create"));
    }

    #[test]
    fn capability_grant_clone_preserves_fields() {
        let original = CapabilityGrant {
            capability: CapabilityId::new("cap.admin").unwrap(),
            operation: Some(OperationId::new("op.delete").unwrap()),
        };
        let cloned = original.clone();
        assert_eq!(original.capability, cloned.capability);
        assert_eq!(original.operation, cloned.operation);
    }

    #[test]
    fn capability_grant_debug_format() {
        let grant = CapabilityGrant {
            capability: CapabilityId::new("cap.test").unwrap(),
            operation: None,
        };
        let dbg = format!("{grant:?}");
        assert!(dbg.contains("cap.test"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: CapabilityConstraints edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn capability_constraints_default_all_empty() {
        let c = CapabilityConstraints::default();
        assert!(c.resource_allow.is_empty());
        assert!(c.resource_deny.is_empty());
        assert!(c.max_calls.is_none());
        assert!(c.max_bytes.is_none());
        assert!(c.idempotency_key.is_none());
        assert!(c.credential_allow.is_empty());
    }

    #[test]
    fn capability_constraints_full_serde_roundtrip() {
        let cred = CredentialId::new();
        let c = CapabilityConstraints {
            resource_allow: vec!["/api/v1/*".into(), "/api/v2/*".into()],
            resource_deny: vec!["/admin/*".into()],
            max_calls: Some(100),
            max_bytes: Some(1_000_000),
            idempotency_key: Some("idem-key-123".into()),
            credential_allow: vec![cred],
        };

        let json = serde_json::to_string(&c).unwrap();
        let back: CapabilityConstraints = serde_json::from_str(&json).unwrap();

        assert_eq!(back.resource_allow.len(), 2);
        assert_eq!(back.resource_deny.len(), 1);
        assert_eq!(back.max_calls, Some(100));
        assert_eq!(back.max_bytes, Some(1_000_000));
        assert_eq!(back.idempotency_key.as_deref(), Some("idem-key-123"));
        assert_eq!(back.credential_allow.len(), 1);
    }

    #[test]
    fn capability_constraints_default_json_minimal() {
        let c = CapabilityConstraints::default();
        let json = serde_json::to_string(&c).unwrap();
        // All fields with skip_serializing_if should be omitted
        assert!(!json.contains("resource_allow"));
        assert!(!json.contains("resource_deny"));
        assert!(!json.contains("max_calls"));
        assert!(!json.contains("max_bytes"));
        assert!(!json.contains("idempotency_key"));
        assert!(!json.contains("credential_allow"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: CapabilityObject serde
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn capability_object_serde_roundtrip() {
        let obj = CapabilityObject {
            caps: vec![CapabilityGrant {
                capability: CapabilityId::new("cap.read").unwrap(),
                operation: None,
            }],
            constraints: CapabilityConstraints::default(),
            principal: Some(PrincipalId::new("user:alice").unwrap()),
            valid_from: Some(1000),
            valid_until: Some(2000),
        };
        let json = serde_json::to_string(&obj).unwrap();
        let back: CapabilityObject = serde_json::from_str(&json).unwrap();
        assert_eq!(back.caps.len(), 1);
        assert_eq!(back.valid_from, Some(1000));
        assert_eq!(back.valid_until, Some(2000));
        assert!(back.principal.is_some());
    }

    #[test]
    fn capability_object_omits_none_fields() {
        let obj = CapabilityObject {
            caps: vec![],
            constraints: CapabilityConstraints::default(),
            principal: None,
            valid_from: None,
            valid_until: None,
        };
        let json = serde_json::to_string(&obj).unwrap();
        assert!(!json.contains("principal"));
        assert!(!json.contains("valid_from"));
        assert!(!json.contains("valid_until"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: RoleObject / RoleAssignment
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn role_object_serde_roundtrip() {
        let role = RoleObject {
            name: "editor".into(),
            caps: vec![CapabilityGrant {
                capability: CapabilityId::new("cap.edit").unwrap(),
                operation: Some(OperationId::new("op.update").unwrap()),
            }],
            includes: vec![],
        };
        let json = serde_json::to_string(&role).unwrap();
        let back: RoleObject = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "editor");
        assert_eq!(back.caps.len(), 1);
    }

    #[test]
    fn role_assignment_serde_roundtrip() {
        let assignment = RoleAssignment {
            role_id: ObjectId::test_id("role-test"),
            principal: PrincipalId::new("user:bob").unwrap(),
            constraints: CapabilityConstraints::default(),
        };
        let json = serde_json::to_string(&assignment).unwrap();
        let back: RoleAssignment = serde_json::from_str(&json).unwrap();
        assert_eq!(back.principal.as_str(), "user:bob");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: TailscaleNodeId
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn tailscale_node_id_new_and_access() {
        let node = TailscaleNodeId::new("node-abc123");
        assert_eq!(node.as_str(), "node-abc123");
    }

    #[test]
    fn tailscale_node_id_from_string() {
        let node: TailscaleNodeId = String::from("ts-node-42").into();
        assert_eq!(node.as_str(), "ts-node-42");
    }

    #[test]
    fn tailscale_node_id_into_string() {
        let node = TailscaleNodeId::new("node-xyz");
        let s: String = node.into();
        assert_eq!(s, "node-xyz");
    }

    #[test]
    fn tailscale_node_id_serde_roundtrip() {
        let node = TailscaleNodeId::new("node-serde-test");
        let json = serde_json::to_string(&node).unwrap();
        let back: TailscaleNodeId = serde_json::from_str(&json).unwrap();
        assert_eq!(back.as_str(), "node-serde-test");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: RateLimit edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn rate_limit_serde_roundtrip() {
        let rl = RateLimit {
            max: 50,
            per_ms: 30_000,
            burst: Some(10),
            scope: Some("per_zone".into()),
            pool_name: Some("shared.pool".into()),
        };
        let json = serde_json::to_string(&rl).unwrap();
        let back: RateLimit = serde_json::from_str(&json).unwrap();
        assert_eq!(back.max, 50);
        assert_eq!(back.per_ms, 30_000);
        assert_eq!(back.burst, Some(10));
        assert_eq!(back.scope.as_deref(), Some("per_zone"));
        assert_eq!(back.pool_name.as_deref(), Some("shared.pool"));
    }

    #[test]
    fn rate_limit_pool_name_with_valid_chars() {
        let rl = RateLimit {
            max: 1,
            per_ms: 1,
            burst: None,
            scope: None,
            pool_name: Some("my-pool_v2.api".into()),
        };
        assert!(rl.validate().is_ok());
    }

    #[test]
    fn rate_limit_pool_name_with_special_chars_rejected() {
        let rl = RateLimit {
            max: 1,
            per_ms: 1,
            burst: None,
            scope: None,
            pool_name: Some("pool name!".into()),
        };
        assert!(matches!(
            rl.validate(),
            Err(RateLimitValidationError::InvalidPoolName { .. })
        ));
    }

    #[test]
    fn rate_limit_parsed_scope_invalid_falls_back() {
        let rl = RateLimit {
            max: 1,
            per_ms: 1,
            burst: None,
            scope: Some("invalid_scope".into()),
            pool_name: None,
        };
        // Invalid scope should fall back to default
        assert_eq!(rl.parsed_scope(), OperationRateLimitScope::PerConnector);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: RateLimitValidationError Display coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn rate_limit_validation_error_display_zero_max() {
        let err = RateLimitValidationError::ZeroMax;
        assert_eq!(err.to_string(), "rate_limit.max must be > 0");
    }

    #[test]
    fn rate_limit_validation_error_display_zero_period() {
        let err = RateLimitValidationError::ZeroPeriod;
        assert_eq!(err.to_string(), "rate_limit.per_ms must be > 0");
    }

    #[test]
    fn rate_limit_validation_error_display_invalid_scope() {
        let err = RateLimitValidationError::InvalidScope {
            scope: "bogus".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("bogus"));
        assert!(msg.contains("rate_limit.scope"));
    }

    #[test]
    fn rate_limit_validation_error_display_empty_pool() {
        let err = RateLimitValidationError::EmptyPoolName;
        assert_eq!(err.to_string(), "rate_limit.pool_name cannot be empty");
    }

    #[test]
    fn rate_limit_validation_error_display_invalid_pool() {
        let err = RateLimitValidationError::InvalidPoolName {
            pool_name: "a b c".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("a b c"));
        assert!(msg.contains("rate_limit.pool_name"));
    }

    #[test]
    fn rate_limit_validation_error_is_std_error() {
        let err = RateLimitValidationError::ZeroMax;
        // Verify it implements std::error::Error
        let _: &dyn std::error::Error = &err;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: RetryConfig edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn retry_config_custom_values_serde() {
        let cfg = RetryConfig {
            max_attempts: 5,
            initial_delay: std::time::Duration::from_millis(250),
            max_delay: std::time::Duration::from_secs(60),
            multiplier: 1.23,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let back: RetryConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.max_attempts, 5);
        assert_eq!(back.initial_delay, std::time::Duration::from_millis(250));
        assert_eq!(back.max_delay, std::time::Duration::from_secs(60));
        assert!((back.multiplier - 1.23).abs() < f64::EPSILON);
    }

    #[test]
    fn retry_config_debug_format() {
        let cfg = RetryConfig::default();
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("max_attempts"));
        assert!(dbg.contains("initial_delay"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: CorrelationId / SessionId edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn correlation_id_default_same_as_new() {
        let d = CorrelationId::default();
        // Should be a valid UUID
        assert!(!d.0.is_nil());
    }

    #[test]
    fn correlation_id_display_is_uuid_format() {
        let id = CorrelationId::new();
        let displayed = id.to_string();
        // UUID v4 format: 8-4-4-4-12 hex chars
        assert_eq!(displayed.len(), 36);
        assert_eq!(displayed.chars().filter(|&c| c == '-').count(), 4);
    }

    #[test]
    fn correlation_id_serde_roundtrip() {
        let id = CorrelationId::new();
        let json = serde_json::to_string(&id).unwrap();
        let back: CorrelationId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn correlation_id_clone_preserves_value() {
        let original = CorrelationId::new();
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn session_id_default_same_as_new() {
        let d = SessionId::default();
        assert!(!d.0.is_nil());
    }

    #[test]
    fn session_id_display_is_uuid_format() {
        let id = SessionId::new();
        let displayed = id.to_string();
        assert_eq!(displayed.len(), 36);
        assert_eq!(displayed.chars().filter(|&c| c == '-').count(), 4);
    }

    #[test]
    fn session_id_serde_roundtrip() {
        let id = SessionId::new();
        let json = serde_json::to_string(&id).unwrap();
        let back: SessionId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn session_id_clone_preserves_value() {
        let original = SessionId::new();
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: Principal / TrustLevel edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn principal_serde_roundtrip() {
        let p = Principal {
            kind: "agent".into(),
            id: "bot-42".into(),
            trust: TrustLevel::Paired,
            display: Some("Bot 42".into()),
        };
        let json = serde_json::to_string(&p).unwrap();
        let back: Principal = serde_json::from_str(&json).unwrap();
        assert_eq!(back.kind, "agent");
        assert_eq!(back.id, "bot-42");
        assert_eq!(back.trust, TrustLevel::Paired);
        assert_eq!(back.display.as_deref(), Some("Bot 42"));
    }

    #[test]
    fn principal_omits_none_display() {
        let p = Principal {
            kind: "user".into(),
            id: "u1".into(),
            trust: TrustLevel::Anonymous,
            display: None,
        };
        let json = serde_json::to_string(&p).unwrap();
        assert!(!json.contains("display"));
    }

    #[test]
    fn trust_level_clone_and_copy() {
        let level = TrustLevel::Admin;
        let copied = level;
        assert_eq!(level, copied);
        // Verify Copy semantics: original still usable after assignment
        assert_eq!(level, TrustLevel::Admin);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: TaintLevel / Provenance edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn taint_level_serde_roundtrip() {
        for level in [
            TaintLevel::Untainted,
            TaintLevel::Tainted,
            TaintLevel::HighlyTainted,
        ] {
            let json = serde_json::to_string(&level).unwrap();
            let back: TaintLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(level, back);
        }
    }

    #[test]
    fn provenance_serde_roundtrip() {
        let p = Provenance::new(ZoneId::work())
            .with_step(ProvenanceStep {
                timestamp_ms: 42,
                zone: ZoneId::work(),
                actor: "agent:test".into(),
                action: "invoke".into(),
                resource: "cap.read".into(),
            })
            .elevated_with("elev-token-abc");

        let json = serde_json::to_string(&p).unwrap();
        let back: Provenance = serde_json::from_str(&json).unwrap();
        assert_eq!(back.origin_zone.as_str(), "z:work");
        assert_eq!(back.chain.len(), 1);
        assert!(back.elevated);
        assert_eq!(back.elevation_token.as_deref(), Some("elev-token-abc"));
    }

    #[test]
    fn provenance_multiple_steps() {
        let p = Provenance::new(ZoneId::work())
            .with_step(ProvenanceStep {
                timestamp_ms: 100,
                zone: ZoneId::work(),
                actor: "a1".into(),
                action: "read".into(),
                resource: "r1".into(),
            })
            .with_step(ProvenanceStep {
                timestamp_ms: 200,
                zone: ZoneId::private(),
                actor: "a2".into(),
                action: "write".into(),
                resource: "r2".into(),
            });
        assert_eq!(p.chain.len(), 2);
        assert_eq!(p.chain[0].timestamp_ms, 100);
        assert_eq!(p.chain[1].timestamp_ms, 200);
    }

    #[test]
    fn provenance_untainted_can_access_higher_trust() {
        let p = Provenance::new(ZoneId::work());
        assert!(!p.is_tainted());
        assert!(p.can_access_higher_trust());
    }

    #[test]
    fn provenance_highly_tainted_cannot_access_without_elevation() {
        let p = Provenance::highly_tainted(ZoneId::public());
        assert!(p.is_tainted());
        assert!(!p.can_access_higher_trust());
    }

    #[test]
    fn provenance_highly_tainted_with_elevation_can_access() {
        let p = Provenance::highly_tainted(ZoneId::public()).elevated_with("high-elev-token");
        assert!(p.is_tainted());
        assert!(p.can_access_higher_trust());
        assert_eq!(p.elevation_token.as_deref(), Some("high-elev-token"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: CapabilityToken test_token
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn capability_token_test_token_is_constructible() {
        let token = CapabilityToken::test_token();
        // Should have raw COSE token
        let dbg = format!("{token:?}");
        assert!(dbg.contains("CapabilityToken"));
    }

    #[test]
    fn capability_token_clone() {
        let token = CapabilityToken::test_token();
        let cloned = token.clone();
        // Both should exist independently
        let dbg1 = format!("{token:?}");
        let dbg2 = format!("{cloned:?}");
        assert!(!dbg1.is_empty());
        assert!(!dbg2.is_empty());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: CapabilityVerifier construction
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn capability_verifier_new_stores_fields() {
        let key = [0u8; 32];
        let zone = ZoneId::work();
        let instance = InstanceId::new();
        let verifier = CapabilityVerifier::new(key, zone.clone(), instance.clone());

        assert_eq!(verifier.host_public_key, [0u8; 32]);
        assert_eq!(verifier.zone_id.as_str(), zone.as_str());
        assert_eq!(verifier.instance_id.as_str(), instance.as_str());
    }

    #[test]
    fn capability_verifier_clone() {
        let key = [1u8; 32];
        let zone = ZoneId::owner();
        let instance = InstanceId::new();
        let original = CapabilityVerifier::new(key, zone, instance);
        let cloned = original.clone();
        assert_eq!(original.host_public_key, cloned.host_public_key);
        assert_eq!(original.zone_id.as_str(), cloned.zone_id.as_str());
    }

    #[test]
    fn capability_verifier_rejects_wrong_key() {
        // Generate token with one key, verify with a different key
        let signing_key = Ed25519SigningKey::generate();
        let wrong_key = Ed25519SigningKey::generate();
        let wrong_pub = wrong_key.verifying_key().to_bytes();

        let now = Utc::now();
        let cose_token = CapabilityTokenBuilder::new()
            .capability_id("cap.test")
            .zone_id("z:work")
            .principal("user:test")
            .operations(&["op.test"])
            .issuer("node:primary")
            .validity(now, now + Duration::hours(1))
            .sign(&signing_key)
            .unwrap();

        let token = CapabilityToken { raw: cose_token };
        let verifier = CapabilityVerifier::new(wrong_pub, ZoneId::work(), InstanceId::new());
        let op = OperationId::new("op.test").unwrap();
        let cap = CapabilityId::new("cap.test").unwrap();

        let result = verifier.verify(&token, &cap, &op, &[]);
        assert!(result.is_err());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: OperationRateLimitScope serde roundtrip
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn operation_rate_limit_scope_serde_roundtrip() {
        for scope in [
            OperationRateLimitScope::PerConnector,
            OperationRateLimitScope::PerZone,
            OperationRateLimitScope::PerPrincipal,
        ] {
            let json = serde_json::to_string(&scope).unwrap();
            let back: OperationRateLimitScope = serde_json::from_str(&json).unwrap();
            assert_eq!(scope, back);
        }
    }

    #[test]
    fn operation_rate_limit_scope_from_str_error_message() {
        let err = "garbage".parse::<OperationRateLimitScope>().unwrap_err();
        assert!(err.contains("garbage"));
        assert!(err.contains("per_connector"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: IdempotencyClass / SafetyTier copy semantics
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn idempotency_class_is_copy() {
        let a = IdempotencyClass::Strict;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn safety_tier_is_copy() {
        let a = SafetyTier::Dangerous;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn risk_level_is_copy() {
        let a = RiskLevel::High;
        let b = a;
        assert_eq!(a, b);
    }
}
