//! Credential types for FCP2 secretless egress (NORMATIVE).
//!
//! This module implements `CredentialObject` and `CredentialId` for "secretless"
//! credential injection as described in `FCP_Specification_V2.md`.
//!
//! **Core principle:** Connectors SHOULD NOT receive raw credential bytes. They
//! reference a `CredentialId` in egress requests, and the `MeshNode` egress proxy
//! injects credential material at the network boundary.
//!
//! **Security guarantees:**
//! - Credentials are zone-bound and capability-gated.
//! - Credential injection is audited via `AuditEvent`.
//! - Host binding provides defense-in-depth against credential misuse.

use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{ObjectHeader, SecretId, ZoneId};

/// Canonical credential identifier (NORMATIVE).
///
/// A `CredentialId` uniquely identifies a credential within a zone. It is used
/// to reference credentials in egress requests without exposing secret material.
///
/// **IMPORTANT**: Credential IDs MUST NOT be encoded inside capability IDs.
/// Operations that need credentials must require a capability whose constraints
/// include the needed `CredentialId` in `credential_allow`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CredentialId(Uuid);

impl CredentialId {
    /// Create a new random `CredentialId`.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create a `CredentialId` from a UUID.
    #[must_use]
    pub const fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Get the inner UUID.
    #[must_use]
    pub const fn as_uuid(&self) -> &Uuid {
        &self.0
    }

    /// Parse a `CredentialId` from a string.
    ///
    /// # Errors
    /// Returns an error if the string is not a valid UUID.
    pub fn parse(s: &str) -> Result<Self, uuid::Error> {
        Ok(Self(Uuid::parse_str(s)?))
    }

    /// Create a test `CredentialId` from bytes (for testing only).
    #[cfg(test)]
    #[must_use]
    pub const fn test_id(bytes: [u8; 16]) -> Self {
        Self(Uuid::from_bytes(bytes))
    }
}

impl Default for CredentialId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for CredentialId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("CredentialId")
            .field(&self.0.to_string())
            .finish()
    }
}

impl fmt::Display for CredentialId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// How to apply a credential to outbound traffic (NORMATIVE).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CredentialApplication {
    /// HTTP Authorization header (e.g., `Bearer <token>`).
    HttpAuthorizationBearer,

    /// HTTP Authorization header with Basic auth.
    HttpAuthorizationBasic,

    /// Custom HTTP header.
    HttpHeader {
        /// Header name (e.g., "X-API-Key").
        name: String,
        /// Optional prefix before the secret value.
        #[serde(skip_serializing_if = "Option::is_none")]
        prefix: Option<String>,
    },

    /// Query parameter.
    QueryParameter {
        /// Parameter name.
        name: String,
    },

    /// TLS client certificate.
    TlsClientCertificate,

    /// SSH key authentication.
    SshKey,

    /// Database connection string credential.
    DatabaseConnection,

    /// WebSocket subprotocol with auth token.
    WebSocketAuth,

    /// Generic credential (application-specific handling).
    Generic {
        /// Application-specific configuration.
        config: String,
    },
}

/// Mesh-stored credential object (NORMATIVE).
///
/// A `CredentialObject` is a zone-bound, auditable handle describing *how to apply*
/// a secret to outbound traffic. It maps `CredentialId` to `SecretId` and defines
/// the application method.
///
/// **Key properties:**
/// - Zone-bound: Only usable within the owning zone.
/// - Auditable: Every use is logged via `AuditEvent`.
/// - Host-bound (optional): Can restrict which hosts the credential may be sent to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialObject {
    /// Standard object header.
    pub header: ObjectHeader,

    /// Unique identifier for this credential.
    pub credential_id: CredentialId,

    /// Human-readable label (MUST NOT contain secret material).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,

    /// Reference to the underlying secret.
    pub secret_id: SecretId,

    /// How to apply this credential to outbound traffic.
    pub application: CredentialApplication,

    /// Allowed hosts for defense-in-depth (optional).
    ///
    /// If present, the egress proxy MUST verify the destination host matches
    /// one of these patterns before injecting the credential.
    ///
    /// Patterns support:
    /// - Exact match: `"api.example.com"`
    /// - Wildcard prefix: `"*.example.com"` (matches subdomains)
    /// - Port specification: `"api.example.com:443"`
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub host_allow: Vec<String>,

    /// When this credential expires (Unix timestamp).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,

    /// Optional description of the credential's purpose.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Tags for categorization and filtering.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

impl CredentialObject {
    /// Get the zone ID from the header.
    #[must_use]
    pub const fn zone_id(&self) -> &ZoneId {
        &self.header.zone_id
    }

    /// Check if this credential has expired.
    #[must_use]
    pub fn is_expired(&self, now_unix: u64) -> bool {
        self.expires_at.is_some_and(|exp| now_unix >= exp)
    }

    /// Check if a host is allowed by this credential's `host_allow` list.
    ///
    /// If `host_allow` is empty, all hosts are allowed.
    /// Otherwise, the host must match at least one pattern.
    #[must_use]
    pub fn is_host_allowed(&self, host: &str) -> bool {
        if self.host_allow.is_empty() {
            return true;
        }

        let host_lower = host.to_lowercase();
        self.host_allow.iter().any(|pattern| {
            let pattern_lower = pattern.to_lowercase();
            pattern_lower.strip_prefix("*.").map_or_else(
                // Exact match when no wildcard
                || host_lower == pattern_lower,
                |_| {
                    // Wildcard match: *.example.com matches foo.example.com (not base domain)
                    let suffix = &pattern_lower[1..]; // ".example.com"
                    host_lower.ends_with(suffix) && host_lower.len() > suffix.len()
                },
            )
        })
    }

    /// Check if this credential is currently usable for a given host.
    #[must_use]
    pub fn is_usable(&self, now_unix: u64, host: &str) -> bool {
        !self.is_expired(now_unix) && self.is_host_allowed(host)
    }

    /// Check if the given host string is an IP literal (IPv4 or IPv6).
    ///
    /// Handles port suffixes (e.g., `192.168.1.1:8080`, `[::1]:8080`).
    #[must_use]
    pub fn is_ip_literal(host: &str) -> bool {
        // Strip port if present
        let host_part = if host.starts_with('[') {
            // IPv6 with brackets: [::1]:8080 or [::1]
            host.find(']').map_or(host, |i| &host[1..i])
        } else if let Some(colon_pos) = host.rfind(':') {
            // Could be IPv4:port or IPv6 without brackets
            let before_colon = &host[..colon_pos];
            // If there's another colon before this one, it's IPv6
            if before_colon.contains(':') {
                host // Return full string, it's IPv6
            } else {
                before_colon // IPv4 with port
            }
        } else {
            host
        };

        // Try parsing as IP address
        host_part.parse::<std::net::IpAddr>().is_ok()
    }

    /// Check if the `host_allow` list contains any IP literals.
    ///
    /// This is useful for policies that require canonical hostnames only.
    #[must_use]
    pub fn has_ip_literal_in_host_allow(&self) -> bool {
        self.host_allow.iter().any(|h| {
            // Skip wildcard prefix for IP check
            let host = h.strip_prefix("*.").unwrap_or(h);
            Self::is_ip_literal(host)
        })
    }

    /// Validate that the credential configuration is policy-compliant.
    ///
    /// When `reject_ip_literals` is true, returns an error if any entry in
    /// `host_allow` is an IP literal rather than a hostname.
    ///
    /// # Errors
    ///
    /// Returns `CredentialValidationError::HostNotAllowed` if an IP literal
    /// is found when they are not allowed.
    pub fn validate_host_policy(
        &self,
        reject_ip_literals: bool,
    ) -> Result<(), CredentialValidationError> {
        if reject_ip_literals && self.has_ip_literal_in_host_allow() {
            // Find the first offending IP literal for the error message
            let ip_literal = self
                .host_allow
                .iter()
                .find(|h| {
                    let host = h.strip_prefix("*.").unwrap_or(h);
                    Self::is_ip_literal(host)
                })
                .cloned()
                .unwrap_or_default();

            return Err(CredentialValidationError::HostNotAllowed {
                credential_id: self.credential_id,
                host: ip_literal,
            });
        }
        Ok(())
    }
}

/// Error when credential validation fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialValidationError {
    /// Credential has expired.
    Expired { credential_id: CredentialId },
    /// Host is not in the allowed list.
    HostNotAllowed {
        credential_id: CredentialId,
        host: String,
    },
    /// Credential ID not in capability's `credential_allow`.
    NotInCredentialAllow { credential_id: CredentialId },
    /// Referenced secret not found.
    SecretNotFound { secret_id: SecretId },
    /// Referenced secret has been revoked.
    SecretRevoked { secret_id: SecretId },
}

impl fmt::Display for CredentialValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Expired { credential_id } => {
                write!(f, "credential {credential_id} has expired")
            }
            Self::HostNotAllowed {
                credential_id,
                host,
            } => {
                write!(
                    f,
                    "host '{host}' not in allowed list for credential {credential_id}"
                )
            }
            Self::NotInCredentialAllow { credential_id } => {
                write!(
                    f,
                    "credential {credential_id} not in capability's credential_allow"
                )
            }
            Self::SecretNotFound { secret_id } => {
                write!(f, "secret {secret_id} not found")
            }
            Self::SecretRevoked { secret_id } => {
                write!(f, "secret {secret_id} has been revoked")
            }
        }
    }
}

impl std::error::Error for CredentialValidationError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Provenance;
    use fcp_cbor::SchemaId;
    use semver::Version;

    fn test_header() -> ObjectHeader {
        ObjectHeader {
            schema: SchemaId::new("fcp.core", "CredentialObject", Version::new(1, 0, 0)),
            zone_id: ZoneId::work(),
            created_at: 1_700_000_000,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        }
    }

    fn test_credential() -> CredentialObject {
        CredentialObject {
            header: test_header(),
            credential_id: CredentialId::new(),
            label: Some("api-key-prod".into()),
            secret_id: SecretId::new(),
            application: CredentialApplication::HttpAuthorizationBearer,
            host_allow: vec![],
            expires_at: None,
            description: Some("Production API key".into()),
            tags: vec!["prod".into(), "api".into()],
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CredentialId Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn credential_id_new_is_unique() {
        let id1 = CredentialId::new();
        let id2 = CredentialId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn credential_id_parse_roundtrip() {
        let id = CredentialId::new();
        let s = id.to_string();
        let parsed = CredentialId::parse(&s).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn credential_id_display_is_uuid() {
        let uuid = Uuid::from_bytes([0xCD; 16]);
        let id = CredentialId::from_uuid(uuid);
        assert_eq!(id.to_string(), uuid.to_string());
    }

    #[test]
    fn credential_id_serialization_roundtrip() {
        let id = CredentialId::new();
        let json = serde_json::to_string(&id).unwrap();
        let deserialized: CredentialId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, deserialized);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CredentialApplication Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn credential_application_serializes_tagged() {
        let bearer = CredentialApplication::HttpAuthorizationBearer;
        let json = serde_json::to_string(&bearer).unwrap();
        assert!(json.contains("\"type\":\"http_authorization_bearer\""));

        let header = CredentialApplication::HttpHeader {
            name: "X-API-Key".into(),
            prefix: Some("Key ".into()),
        };
        let json = serde_json::to_string(&header).unwrap();
        assert!(json.contains("\"type\":\"http_header\""));
        assert!(json.contains("\"name\":\"X-API-Key\""));
        assert!(json.contains("\"prefix\":\"Key \""));
    }

    #[test]
    fn credential_application_roundtrip() {
        let apps = vec![
            CredentialApplication::HttpAuthorizationBearer,
            CredentialApplication::HttpAuthorizationBasic,
            CredentialApplication::HttpHeader {
                name: "Authorization".into(),
                prefix: None,
            },
            CredentialApplication::QueryParameter {
                name: "api_key".into(),
            },
            CredentialApplication::TlsClientCertificate,
            CredentialApplication::SshKey,
            CredentialApplication::DatabaseConnection,
            CredentialApplication::WebSocketAuth,
            CredentialApplication::Generic {
                config: r#"{"custom": true}"#.into(),
            },
        ];

        for app in apps {
            let json = serde_json::to_string(&app).unwrap();
            let decoded: CredentialApplication = serde_json::from_str(&json).unwrap();
            assert_eq!(app, decoded);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CredentialObject Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn credential_object_is_expired() {
        let mut cred = test_credential();
        cred.expires_at = Some(1_700_000_100);

        assert!(!cred.is_expired(1_700_000_000));
        assert!(!cred.is_expired(1_700_000_099));
        assert!(cred.is_expired(1_700_000_100));
        assert!(cred.is_expired(1_700_000_200));
    }

    #[test]
    fn credential_object_no_expiry_never_expires() {
        let cred = test_credential();
        assert!(!cred.is_expired(u64::MAX));
    }

    #[test]
    fn credential_object_host_allow_empty_allows_all() {
        let cred = test_credential();
        assert!(cred.is_host_allowed("api.example.com"));
        assert!(cred.is_host_allowed("anything.anywhere.net"));
        assert!(cred.is_host_allowed("localhost"));
    }

    #[test]
    fn credential_object_host_allow_exact_match() {
        let mut cred = test_credential();
        cred.host_allow = vec!["api.example.com".into(), "api.other.net".into()];

        assert!(cred.is_host_allowed("api.example.com"));
        assert!(cred.is_host_allowed("API.EXAMPLE.COM")); // case insensitive
        assert!(cred.is_host_allowed("api.other.net"));
        assert!(!cred.is_host_allowed("evil.com"));
        assert!(!cred.is_host_allowed("foo.api.example.com")); // no wildcard
    }

    #[test]
    fn credential_object_host_allow_wildcard() {
        let mut cred = test_credential();
        cred.host_allow = vec!["*.example.com".into()];

        assert!(cred.is_host_allowed("api.example.com"));
        assert!(cred.is_host_allowed("foo.example.com"));
        assert!(!cred.is_host_allowed("example.com")); // wildcard does not match base domain
        assert!(!cred.is_host_allowed("example.net"));
        assert!(!cred.is_host_allowed("notexample.com"));
    }

    #[test]
    fn credential_object_host_allow_with_port() {
        let mut cred = test_credential();
        cred.host_allow = vec!["api.example.com:443".into()];

        assert!(cred.is_host_allowed("api.example.com:443"));
        assert!(!cred.is_host_allowed("api.example.com:80"));
        assert!(!cred.is_host_allowed("api.example.com")); // port required
    }

    #[test]
    fn credential_object_is_usable() {
        let mut cred = test_credential();
        cred.expires_at = Some(1_700_000_100);
        cred.host_allow = vec!["api.example.com".into()];

        assert!(cred.is_usable(1_700_000_000, "api.example.com"));
        assert!(!cred.is_usable(1_700_000_000, "evil.com")); // host not allowed
        assert!(!cred.is_usable(1_700_000_200, "api.example.com")); // expired
    }

    #[test]
    fn credential_object_serialization_roundtrip() {
        let cred = CredentialObject {
            header: test_header(),
            credential_id: CredentialId::new(),
            label: Some("github-token".into()),
            secret_id: SecretId::new(),
            application: CredentialApplication::HttpHeader {
                name: "Authorization".into(),
                prefix: Some("token ".into()),
            },
            host_allow: vec!["api.github.com".into(), "*.githubusercontent.com".into()],
            expires_at: Some(1_800_000_000),
            description: Some("GitHub personal access token".into()),
            tags: vec!["github".into(), "vcs".into()],
        };

        let json = serde_json::to_string(&cred).unwrap();
        let decoded: CredentialObject = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.credential_id, cred.credential_id);
        assert_eq!(decoded.label.as_deref(), Some("github-token"));
        assert_eq!(decoded.host_allow.len(), 2);
        assert_eq!(decoded.tags.len(), 2);
    }

    #[test]
    fn credential_object_optional_fields_omitted() {
        let cred = CredentialObject {
            header: test_header(),
            credential_id: CredentialId::new(),
            label: None,
            secret_id: SecretId::new(),
            application: CredentialApplication::HttpAuthorizationBearer,
            host_allow: vec![],
            expires_at: None,
            description: None,
            tags: vec![],
        };

        let json = serde_json::to_string(&cred).unwrap();
        assert!(!json.contains("label"));
        assert!(!json.contains("host_allow"));
        assert!(!json.contains("expires_at"));
        assert!(!json.contains("description"));
        assert!(!json.contains("tags"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CredentialValidationError Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn credential_validation_error_display() {
        let cred_id = CredentialId::test_id([0x11; 16]);
        let secret_id = SecretId::test_id([0x22; 16]);

        let err = CredentialValidationError::Expired {
            credential_id: cred_id,
        };
        assert!(err.to_string().contains("expired"));

        let err = CredentialValidationError::HostNotAllowed {
            credential_id: cred_id,
            host: "evil.com".into(),
        };
        assert!(err.to_string().contains("evil.com"));
        assert!(err.to_string().contains("not in allowed list"));

        let err = CredentialValidationError::NotInCredentialAllow {
            credential_id: cred_id,
        };
        assert!(err.to_string().contains("credential_allow"));

        let err = CredentialValidationError::SecretNotFound { secret_id };
        assert!(err.to_string().contains("not found"));

        let err = CredentialValidationError::SecretRevoked { secret_id };
        assert!(err.to_string().contains("revoked"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // IP Literal Detection Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn is_ip_literal_ipv4() {
        assert!(CredentialObject::is_ip_literal("192.168.1.1"));
        assert!(CredentialObject::is_ip_literal("10.0.0.1"));
        assert!(CredentialObject::is_ip_literal("127.0.0.1"));
        assert!(CredentialObject::is_ip_literal("0.0.0.0"));
        assert!(CredentialObject::is_ip_literal("255.255.255.255"));
    }

    #[test]
    fn is_ip_literal_ipv4_with_port() {
        assert!(CredentialObject::is_ip_literal("192.168.1.1:8080"));
        assert!(CredentialObject::is_ip_literal("10.0.0.1:443"));
        assert!(CredentialObject::is_ip_literal("127.0.0.1:80"));
    }

    #[test]
    fn is_ip_literal_ipv6() {
        assert!(CredentialObject::is_ip_literal("::1"));
        assert!(CredentialObject::is_ip_literal("::"));
        assert!(CredentialObject::is_ip_literal("fe80::1"));
        assert!(CredentialObject::is_ip_literal("2001:db8::1"));
        assert!(CredentialObject::is_ip_literal("::ffff:192.168.1.1"));
    }

    #[test]
    fn is_ip_literal_ipv6_with_brackets() {
        assert!(CredentialObject::is_ip_literal("[::1]"));
        assert!(CredentialObject::is_ip_literal("[::1]:8080"));
        assert!(CredentialObject::is_ip_literal("[2001:db8::1]:443"));
        // IPv6 zone IDs like [fe80::1%eth0] don't parse as valid IPs
        assert!(!CredentialObject::is_ip_literal("[fe80::1%eth0]"));
    }

    #[test]
    fn is_ip_literal_not_ip() {
        assert!(!CredentialObject::is_ip_literal("api.example.com"));
        assert!(!CredentialObject::is_ip_literal("localhost"));
        assert!(!CredentialObject::is_ip_literal("api.example.com:443"));
        assert!(!CredentialObject::is_ip_literal("*.example.com"));
        assert!(!CredentialObject::is_ip_literal("sub.domain.example.com"));
    }

    #[test]
    fn is_ip_literal_edge_cases() {
        // Invalid but not hostnames
        assert!(!CredentialObject::is_ip_literal("999.999.999.999")); // Invalid IPv4 - doesn't parse
        assert!(!CredentialObject::is_ip_literal(""));
        assert!(!CredentialObject::is_ip_literal(":"));
        assert!(!CredentialObject::is_ip_literal("[]"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Host Policy Validation Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn has_ip_literal_in_host_allow_detects_ipv4() {
        let mut cred = test_credential();
        cred.host_allow = vec!["192.168.1.1".into()];
        assert!(cred.has_ip_literal_in_host_allow());

        cred.host_allow = vec!["api.example.com".into(), "10.0.0.1:8080".into()];
        assert!(cred.has_ip_literal_in_host_allow());
    }

    #[test]
    fn has_ip_literal_in_host_allow_detects_ipv6() {
        let mut cred = test_credential();
        cred.host_allow = vec!["[::1]:8080".into()];
        assert!(cred.has_ip_literal_in_host_allow());

        cred.host_allow = vec!["::1".into()];
        assert!(cred.has_ip_literal_in_host_allow());
    }

    #[test]
    fn has_ip_literal_in_host_allow_no_ip() {
        let mut cred = test_credential();
        cred.host_allow = vec!["api.example.com".into(), "*.other.net".into()];
        assert!(!cred.has_ip_literal_in_host_allow());
    }

    #[test]
    fn has_ip_literal_in_host_allow_empty() {
        let cred = test_credential();
        assert!(!cred.has_ip_literal_in_host_allow());
    }

    #[test]
    fn validate_host_policy_allows_hostnames() {
        let mut cred = test_credential();
        cred.host_allow = vec!["api.example.com".into(), "*.other.net".into()];

        assert!(cred.validate_host_policy(true).is_ok());
        assert!(cred.validate_host_policy(false).is_ok());
    }

    #[test]
    fn validate_host_policy_rejects_ip_when_required() {
        let mut cred = test_credential();
        cred.host_allow = vec!["192.168.1.1".into()];

        // Should reject when reject_ip_literals is true
        let result = cred.validate_host_policy(true);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(
                &err,
                CredentialValidationError::HostNotAllowed { host, .. } if host == "192.168.1.1"
            ),
            "Expected HostNotAllowed error, got {err:?}"
        );

        // Should allow when reject_ip_literals is false
        assert!(cred.validate_host_policy(false).is_ok());
    }

    #[test]
    fn validate_host_policy_rejects_ipv6_when_required() {
        let mut cred = test_credential();
        cred.host_allow = vec!["api.example.com".into(), "[::1]:8080".into()];

        let result = cred.validate_host_policy(true);
        assert!(result.is_err());
    }

    #[test]
    fn validate_host_policy_empty_list_passes() {
        let cred = test_credential();
        assert!(cred.validate_host_policy(true).is_ok());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CredentialId Canonicity Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn credential_id_is_canonical_uuid() {
        let id = CredentialId::new();
        let s = id.to_string();

        // UUID v4 format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
        assert_eq!(s.len(), 36);
        assert_eq!(s.chars().filter(|c| *c == '-').count(), 4);

        // Verify it's lowercase (canonical)
        assert_eq!(s, s.to_lowercase());
    }

    #[test]
    fn credential_id_stable_display() {
        let bytes = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
            0xFF, 0x00,
        ];
        let id = CredentialId::test_id(bytes);

        // Display should be deterministic
        let s1 = id.to_string();
        let s2 = id.to_string();
        assert_eq!(s1, s2);

        // Display should be the canonical lowercase UUID
        assert_eq!(s1, "11223344-5566-7788-99aa-bbccddeeff00");
    }

    #[test]
    fn credential_id_parse_rejects_invalid() {
        assert!(CredentialId::parse("not-a-uuid").is_err());
        assert!(CredentialId::parse("").is_err());
        assert!(CredentialId::parse("11223344-5566-7788-99aa-bbccddeeff0").is_err()); // too short
        assert!(CredentialId::parse("11223344-5566-7788-99aa-bbccddeeff000").is_err()); // too long
    }

    #[test]
    fn credential_id_parse_accepts_uppercase() {
        // UUID parsing should be case-insensitive
        let upper = CredentialId::parse("11223344-5566-7788-99AA-BBCCDDEEFF00");
        let lower = CredentialId::parse("11223344-5566-7788-99aa-bbccddeeff00");

        assert!(upper.is_ok());
        assert!(lower.is_ok());
        assert_eq!(upper.unwrap(), lower.unwrap());
    }
}
