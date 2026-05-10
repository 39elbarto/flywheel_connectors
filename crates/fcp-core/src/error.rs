//! FCP Error types and error response structures.
//!
//! Error codes follow the FCP specification:
//! - FCP-1xxx: Protocol errors
//! - FCP-2xxx: Auth/Identity errors
//! - FCP-3xxx: Capability errors
//! - FCP-4xxx: Zone/Topology/Provenance errors
//! - FCP-5xxx: Connector lifecycle/health errors
//! - FCP-6xxx: Resource errors
//! - FCP-7xxx: External service errors
//! - FCP-9xxx: Internal errors

use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{ThrottleViolation, UsageMetricKind};

/// FCP error type covering all error categories.
#[derive(Error, Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "category")]
pub enum FcpError {
    // ─────────────────────────────────────────────────────────────────────────
    // Protocol errors (FCP-1xxx)
    // ─────────────────────────────────────────────────────────────────────────
    #[error("Invalid request: {message}")]
    InvalidRequest { code: u16, message: String },

    #[error("Malformed frame: {message}")]
    MalformedFrame { code: u16, message: String },

    #[error("Missing required field: {field}")]
    MissingField { field: String },

    #[error("Checksum mismatch")]
    ChecksumMismatch,

    #[error("Protocol version mismatch: expected {expected}, got {actual}")]
    VersionMismatch { expected: String, actual: String },

    // ─────────────────────────────────────────────────────────────────────────
    // Auth errors (FCP-2xxx)
    // ─────────────────────────────────────────────────────────────────────────
    #[error("Unauthorized: {message}")]
    Unauthorized { code: u16, message: String },

    #[error("Token expired")]
    TokenExpired,

    #[error("Token not yet valid")]
    TokenNotYetValid,

    #[error("Invalid signature")]
    InvalidSignature,

    // ─────────────────────────────────────────────────────────────────────────
    // Capability errors (FCP-3xxx)
    // ─────────────────────────────────────────────────────────────────────────
    #[error("Capability denied: {capability}")]
    CapabilityDenied { capability: String, reason: String },

    #[error("Rate limited: retry after {retry_after_ms}ms")]
    RateLimited {
        retry_after_ms: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        violation: Option<Box<ThrottleViolation>>,
    },

    #[error("Operation not granted: {operation}")]
    OperationNotGranted { operation: String },

    #[error("Resource not allowed: {resource}")]
    ResourceNotAllowed { resource: String },

    #[error("Capability constraint denied ({kind}) on claim '{claim_type}': {detail}")]
    CapabilityConstraintDenied {
        /// Categorical reason for the denial. Stable across releases — audit
        /// consumers and replay tooling depend on the discriminant.
        kind: CapabilityConstraintErrorKind,
        /// The constraint claim that produced the denial (e.g. `"host_allowlist"`,
        /// `"resource_uri"`, `"max_calls"`). Free-form so policy authors can
        /// label per-deployment claim shapes without bumping the enum.
        claim_type: String,
        /// Operator-readable specifics (observed value, expected pattern, ...).
        /// Never contains raw payload bytes — only the narrow descriptor that
        /// reproduces the denial in audit logs.
        detail: String,
    },

    // ─────────────────────────────────────────────────────────────────────────
    // Zone errors (FCP-4xxx)
    // ─────────────────────────────────────────────────────────────────────────
    #[error("Zone violation: {message}")]
    ZoneViolation {
        source_zone: String,
        target_zone: String,
        message: String,
    },

    #[error("Taint violation: origin {origin_zone} cannot invoke {capability} in {target_zone}")]
    TaintViolation {
        origin_zone: String,
        target_zone: String,
        capability: String,
    },

    #[error("Elevation required for {capability}")]
    ElevationRequired {
        capability: String,
        ttl_seconds: Option<u32>,
    },

    // ─────────────────────────────────────────────────────────────────────────
    // Connector errors (FCP-5xxx)
    // ─────────────────────────────────────────────────────────────────────────
    #[error("Connector unavailable: {message}")]
    ConnectorUnavailable { code: u16, message: String },

    #[error("Connector not configured")]
    NotConfigured,

    #[error("Connector not handshaken")]
    NotHandshaken,

    #[error("Health check failed: {reason}")]
    HealthCheckFailed { reason: String },

    #[error("Streaming not supported")]
    StreamingNotSupported,

    #[error(
        "Configuration leaked secret material: field_name_hash={field_name_hash}, detector={detector}"
    )]
    ConfigurationLeakedSecret {
        /// SHA-256 digest of the rejected configuration field name.
        field_name_hash: String,
        /// Redaction-safe detector label, such as `named_secret_field` or
        /// `secret_like_value`.
        detector: String,
    },

    // ─────────────────────────────────────────────────────────────────────────
    // Resource errors (FCP-6xxx)
    // ─────────────────────────────────────────────────────────────────────────
    #[error("Resource not found: {resource}")]
    ResourceNotFound { resource: String },

    #[error("Resource exhausted: {resource}")]
    ResourceExhausted { resource: String },

    #[error("Budget exceeded for {metric:?}: used {used} of {limit} per {window_seconds}s")]
    BudgetExceeded {
        metric: UsageMetricKind,
        used: u64,
        limit: u64,
        window_seconds: u64,
    },

    #[error("Conflict: {message}")]
    Conflict { message: String },

    // ─────────────────────────────────────────────────────────────────────────
    // External service errors (FCP-7xxx)
    // ─────────────────────────────────────────────────────────────────────────
    #[error("External service error: {service} - {message}")]
    External {
        service: String,
        message: String,
        status_code: Option<u16>,
        retryable: bool,
        #[serde(with = "optional_duration_millis")]
        retry_after: Option<Duration>,
    },

    #[error("Upstream timeout: {service}")]
    UpstreamTimeout { service: String },

    #[error("Dependency unavailable: {service}")]
    DependencyUnavailable { service: String },

    // ─────────────────────────────────────────────────────────────────────────
    // Internal errors (FCP-9xxx)
    // ─────────────────────────────────────────────────────────────────────────
    #[error("Internal error: {message}")]
    Internal { message: String },
}

mod optional_duration_millis {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    #[allow(clippy::ref_option)]
    pub fn serialize<S>(duration: &Option<Duration>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match duration {
            Some(d) => serializer.serialize_some(&u64::try_from(d.as_millis()).unwrap_or(u64::MAX)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let millis: Option<u64> = Option::deserialize(deserializer)?;
        Ok(millis.map(Duration::from_millis))
    }
}

/// Error category for classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCategory {
    /// Protocol-level errors (malformed requests, version mismatches)
    Protocol,
    /// Authentication and identity errors
    Auth,
    /// Capability and permission errors
    Capability,
    /// Zone topology and provenance errors
    Zone,
    /// Connector lifecycle and health errors
    Connector,
    /// Resource availability errors
    Resource,
    /// External service errors
    External,
    /// Internal implementation errors
    Internal,
}

impl ErrorCategory {
    /// Returns the error code range for this category.
    #[must_use]
    pub const fn code_range(self) -> (u16, u16) {
        match self {
            Self::Protocol => (1000, 1999),
            Self::Auth => (2000, 2999),
            Self::Capability => (3000, 3999),
            Self::Zone => (4000, 4999),
            Self::Connector => (5000, 5999),
            Self::Resource => (6000, 6999),
            Self::External => (7000, 7999),
            Self::Internal => (9000, 9999),
        }
    }

    /// Returns a human-readable name for the category.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Protocol => "Protocol",
            Self::Auth => "Auth/Identity",
            Self::Capability => "Capability",
            Self::Zone => "Zone/Topology",
            Self::Connector => "Connector",
            Self::Resource => "Resource",
            Self::External => "External Service",
            Self::Internal => "Internal",
        }
    }
}

/// Categorical reason for an [`FcpError::CapabilityConstraintDenied`] (m8j0q.A.3).
///
/// Audit consumers, replay tooling, and conformance vectors depend on this
/// discriminant being **stable across releases**. Adding a new variant is a
/// SemVer-breaking change in the FCP error taxonomy; renaming or reordering
/// variants is forbidden — the serde tag (`snake_case` of the variant name)
/// is the wire format.
///
/// All variants are non-retryable: a capability constraint denial is a
/// security decision, never a transient failure. See
/// [`FcpError::is_retryable`] — `CapabilityConstraintDenied { .. }` returns
/// `false` for every `kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityConstraintErrorKind {
    /// Observed value did not exactly match the constraint's allowlist or
    /// expected value (e.g. host not in `host_allowlist`, principal not the
    /// bound principal, object id not in `object_id_allowlist`).
    ExactMismatch,
    /// Observed value fell outside an allowed numeric or temporal range
    /// (e.g. `request_time` before `not_before`, `observed_calls` > `max_calls`,
    /// `observed_bytes` > `max_bytes`).
    OutOfRange,
    /// The constraint claim referenced a type that this enforcer does not
    /// know how to evaluate. Indicates either a forward-rolled token
    /// (issued by a newer mint) or a deployment-config drift.
    UnsupportedClaimType,
    /// A claim that the policy marks MANDATORY for this operation was
    /// absent from the capability token's `CapabilityConstraints`. Default
    /// deny (C3.4) — the absence itself is the denial.
    MissingMandatoryConstraint,
    /// The constraint claim was syntactically present but could not be
    /// parsed (malformed CBOR fragment, incompatible schema version,
    /// failed validation in [`fcp_auth_schema`]). Distinct from
    /// `UnsupportedClaimType` — the type IS known, the bytes are bad.
    ConstraintParseError,
}

impl CapabilityConstraintErrorKind {
    /// Stable machine label used in logs, audit events, and the wire-format
    /// `serde` tag. MUST match `serde(rename_all = "snake_case")`.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ExactMismatch => "exact_mismatch",
            Self::OutOfRange => "out_of_range",
            Self::UnsupportedClaimType => "unsupported_claim_type",
            Self::MissingMandatoryConstraint => "missing_mandatory_constraint",
            Self::ConstraintParseError => "constraint_parse_error",
        }
    }

    /// Operator-readable explanation of the kind.
    ///
    /// Used by `to_response().ai_hint` to give the operator a one-line
    /// description without dumping the full CBOR claim back at them.
    #[must_use]
    pub const fn explanation(&self) -> &'static str {
        match self {
            Self::ExactMismatch => {
                "Observed value did not match the constraint's exact allowlist or expected value"
            }
            Self::OutOfRange => "Observed value fell outside an allowed numeric or temporal range",
            Self::UnsupportedClaimType => {
                "The capability token references a constraint claim type this enforcer does not know how to evaluate"
            }
            Self::MissingMandatoryConstraint => {
                "A constraint claim that policy marks MANDATORY for this operation was absent from the token (default-deny per C3.4)"
            }
            Self::ConstraintParseError => {
                "The constraint claim could not be parsed (malformed CBOR fragment, incompatible schema version, or failed validation)"
            }
        }
    }

    /// Enumerate every variant in declaration order. Used by the variant-
    /// matrix conformance test and by audit replay tools that build a
    /// per-kind histogram.
    #[must_use]
    pub const fn all() -> [Self; 5] {
        [
            Self::ExactMismatch,
            Self::OutOfRange,
            Self::UnsupportedClaimType,
            Self::MissingMandatoryConstraint,
            Self::ConstraintParseError,
        ]
    }
}

impl std::fmt::Display for CapabilityConstraintErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

fn configuration_field_name_hash(field_name: &str) -> String {
    let digest = Sha256::digest(field_name.as_bytes());
    hex::encode(digest)
}

impl FcpError {
    /// Construct a redaction-safe configuration secret-leak error.
    ///
    /// `field_name` is immediately hashed and is not retained. `detector` must
    /// be a stable redaction-safe label, not a raw secret value or provider
    /// error string.
    #[must_use]
    pub fn configuration_leaked_secret(field_name: &str, detector: impl Into<String>) -> Self {
        Self::ConfigurationLeakedSecret {
            field_name_hash: configuration_field_name_hash(field_name),
            detector: detector.into(),
        }
    }

    /// Returns the error category for classification.
    #[must_use]
    pub const fn category(&self) -> ErrorCategory {
        match self {
            Self::InvalidRequest { .. }
            | Self::MalformedFrame { .. }
            | Self::ChecksumMismatch
            | Self::VersionMismatch { .. }
            | Self::MissingField { .. } => ErrorCategory::Protocol,

            Self::Unauthorized { .. }
            | Self::TokenExpired
            | Self::TokenNotYetValid
            | Self::InvalidSignature => ErrorCategory::Auth,

            Self::CapabilityDenied { .. }
            | Self::RateLimited { .. }
            | Self::OperationNotGranted { .. }
            | Self::ResourceNotAllowed { .. }
            | Self::CapabilityConstraintDenied { .. } => ErrorCategory::Capability,

            Self::ZoneViolation { .. }
            | Self::TaintViolation { .. }
            | Self::ElevationRequired { .. } => ErrorCategory::Zone,

            Self::ConnectorUnavailable { .. }
            | Self::NotConfigured
            | Self::NotHandshaken
            | Self::HealthCheckFailed { .. }
            | Self::StreamingNotSupported
            | Self::ConfigurationLeakedSecret { .. } => ErrorCategory::Connector,

            Self::ResourceNotFound { .. }
            | Self::ResourceExhausted { .. }
            | Self::BudgetExceeded { .. }
            | Self::Conflict { .. } => ErrorCategory::Resource,

            Self::External { .. }
            | Self::UpstreamTimeout { .. }
            | Self::DependencyUnavailable { .. } => ErrorCategory::External,

            Self::Internal { .. } => ErrorCategory::Internal,
        }
    }

    /// Returns the stable error code string (e.g., "FCP-3001").
    #[must_use]
    pub fn error_code(&self) -> String {
        self.to_response().code
    }

    /// Returns the numeric error code (e.g., 3001 for "FCP-3001").
    #[must_use]
    pub const fn numeric_code(&self) -> u16 {
        match self {
            Self::InvalidRequest { code, .. }
            | Self::MalformedFrame { code, .. }
            | Self::Unauthorized { code, .. }
            | Self::ConnectorUnavailable { code, .. } => *code,

            Self::ChecksumMismatch => 1004,
            Self::VersionMismatch { .. } => 1005,

            Self::TokenExpired => 2002,
            Self::TokenNotYetValid => 2005,
            Self::InvalidSignature => 2003,

            Self::CapabilityDenied { .. } => 3001,
            Self::RateLimited { .. } => 3002,
            Self::OperationNotGranted { .. } => 3003,
            Self::ResourceNotAllowed { .. } => 3004,
            Self::CapabilityConstraintDenied { .. } => 3005,

            Self::ZoneViolation { .. } => 4001,
            Self::TaintViolation { .. } => 4002,
            Self::ElevationRequired { .. } => 4003,

            Self::NotConfigured => 5002,
            Self::NotHandshaken => 5003,
            Self::HealthCheckFailed { .. } => 5004,
            Self::StreamingNotSupported => 5005,
            Self::ConfigurationLeakedSecret { .. } => 5006,

            Self::ResourceNotFound { .. } => 6001,
            Self::ResourceExhausted { .. } => 6002,
            Self::Conflict { .. } => 6003,
            Self::BudgetExceeded { .. } => 6004,

            Self::External { status_code, .. } => match status_code {
                Some(429) => 7001,
                Some(504) => 7002,
                _ => 7003,
            },
            Self::UpstreamTimeout { .. } => 7002,
            Self::DependencyUnavailable { .. } => 7003,

            Self::Internal { .. } => 9001,
            Self::MissingField { .. } => 1006,
        }
    }

    /// Returns true if the error is retryable.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::External { retryable, .. } => *retryable,
            Self::RateLimited { .. }
            | Self::ResourceExhausted { .. }
            | Self::BudgetExceeded { .. }
            | Self::UpstreamTimeout { .. }
            | Self::DependencyUnavailable { .. }
            | Self::ConnectorUnavailable { .. } => true,
            _ => false,
        }
    }

    /// Returns the suggested retry delay, if any.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::External { retry_after, .. } => *retry_after,
            Self::RateLimited { retry_after_ms, .. } => {
                Some(Duration::from_millis(*retry_after_ms))
            }
            _ => None,
        }
    }

    /// Convert to wire response format.
    #[must_use]
    #[allow(clippy::too_many_lines)] // Large match over all error variants is inherently verbose
    pub fn to_response(&self) -> FcpErrorResponse {
        let (code, ai_hint) = match self {
            // ─────────────────────────────────────────────────────────────────
            // Protocol errors (FCP-1xxx)
            // ─────────────────────────────────────────────────────────────────
            Self::InvalidRequest { code, .. } => (
                format!("FCP-{code:04}"),
                Some("Check the request format matches the operation schema. Validate all required fields are present and correctly typed.".into()),
            ),
            Self::MalformedFrame { code, .. } => (
                format!("FCP-{code:04}"),
                Some("The wire frame is corrupted or uses an incompatible encoding. Verify CBOR serialization and frame structure.".into()),
            ),
            Self::ChecksumMismatch => (
                "FCP-1004".into(),
                Some("Data integrity check failed. Retry the request; if persistent, check for network issues or intermediary corruption.".into()),
            ),
            Self::VersionMismatch { .. } => (
                "FCP-1005".into(),
                Some("Protocol version incompatible. Update the connector or host to a compatible version.".into()),
            ),

            // ─────────────────────────────────────────────────────────────────
            // Auth/Identity errors (FCP-2xxx)
            // ─────────────────────────────────────────────────────────────────
            Self::Unauthorized { code, .. } => (
                format!("FCP-{code:04}"),
                Some("Authentication failed. Verify credentials are valid and the principal has access to this zone.".into()),
            ),
            Self::TokenExpired => (
                "FCP-2002".into(),
                Some("Request a new capability token from the issuing node. Tokens have limited validity periods.".into()),
            ),
            Self::TokenNotYetValid => (
                "FCP-2005".into(),
                Some("The capability token's not-before (nbf) claim is in the future. Wait until the token becomes valid, or request a token with an earlier nbf.".into()),
            ),
            Self::InvalidSignature => (
                "FCP-2003".into(),
                Some("Cryptographic signature verification failed. The token may be corrupted, or the signing key may have been rotated. Request a fresh token.".into()),
            ),

            // ─────────────────────────────────────────────────────────────────
            // Capability errors (FCP-3xxx)
            // ─────────────────────────────────────────────────────────────────
            Self::CapabilityDenied { capability, .. } => (
                "FCP-3001".into(),
                Some(format!(
                    "The capability '{capability}' is not granted in this zone. Request the capability from the zone's policy administrator or use a zone where it is available."
                )),
            ),
            Self::RateLimited { retry_after_ms, .. } => (
                "FCP-3002".into(),
                Some(format!(
                    "Rate limit exceeded. Wait {retry_after_ms}ms before retrying. Consider batching requests or spreading them over time."
                )),
            ),
            Self::OperationNotGranted { operation, .. } => (
                "FCP-3003".into(),
                Some(format!(
                    "Operation '{operation}' is not permitted by current capabilities. Request additional capability grants or use an alternative operation."
                )),
            ),
            Self::ResourceNotAllowed { resource, .. } => (
                "FCP-3004".into(),
                Some(format!(
                    "Access to resource '{resource}' is not permitted. Verify the resource is within the connector's allowed scope."
                )),
            ),
            Self::CapabilityConstraintDenied {
                kind,
                claim_type,
                detail,
            } => (
                "FCP-3005".into(),
                Some(format!(
                    "Capability constraint '{claim_type}' denied the request ({kind}): {}. {detail} Request a narrower operation, a matching resource scope, or a new capability token. Security denials are non-retryable.",
                    kind.explanation()
                )),
            ),

            // ─────────────────────────────────────────────────────────────────
            // Zone/Topology/Provenance errors (FCP-4xxx)
            // ─────────────────────────────────────────────────────────────────
            Self::ZoneViolation { source_zone, target_zone, .. } => (
                "FCP-4001".into(),
                Some(format!(
                    "Cross-zone access from '{source_zone}' to '{target_zone}' is denied. Request an ApprovalToken for zone transition or restructure the workflow to stay within zone boundaries."
                )),
            ),
            Self::TaintViolation { origin_zone, target_zone, capability, .. } => (
                "FCP-4002".into(),
                Some(format!(
                    "Data from '{origin_zone}' cannot invoke '{capability}' in '{target_zone}'. Request elevation via ApprovalToken, sanitize the input with a registered sanitizer, or move the operation to a compatible zone."
                )),
            ),
            Self::ElevationRequired { capability, ttl_seconds, .. } => (
                "FCP-4003".into(),
                Some(format!(
                    "Operation '{capability}' requires owner approval. Request an ApprovalToken{}.",
                    ttl_seconds.map_or(String::new(), |t| format!(" (valid for {t}s)"))
                )),
            ),

            // ─────────────────────────────────────────────────────────────────
            // Connector lifecycle/health errors (FCP-5xxx)
            // ─────────────────────────────────────────────────────────────────
            Self::ConnectorUnavailable { code, .. } => (
                format!("FCP-{code:04}"),
                Some("The connector is temporarily unavailable. Retry after a delay. If persistent, check connector health via 'fcp doctor'.".into()),
            ),
            Self::NotConfigured => (
                "FCP-5002".into(),
                Some("Connector has not been configured. Call configure() with valid connector settings before invoking operations.".into()),
            ),
            Self::NotHandshaken => (
                "FCP-5003".into(),
                Some("Connector handshake not completed. Call handshake() after configure() to establish a session before invoking operations.".into()),
            ),
            Self::HealthCheckFailed { reason, .. } => (
                "FCP-5004".into(),
                Some(format!(
                    "Health check failed: {reason}. Verify external service connectivity and credentials. Run 'fcp doctor' for diagnostics."
                )),
            ),
            Self::StreamingNotSupported => (
                "FCP-5005".into(),
                Some("This connector does not support streaming subscriptions. Use request-response operations instead, or choose a connector that supports the streaming archetype.".into()),
            ),
            Self::ConfigurationLeakedSecret { .. } => (
                "FCP-5006".into(),
                Some("Connector configuration contained raw secret material. Replace raw secret fields with credential_id references owned by the host credential backend, then retry configure().".into()),
            ),

            // ─────────────────────────────────────────────────────────────────
            // Resource errors (FCP-6xxx)
            // ─────────────────────────────────────────────────────────────────
            Self::ResourceNotFound { resource, .. } => (
                "FCP-6001".into(),
                Some(format!(
                    "Resource '{resource}' was not found. Verify the resource identifier is correct and the resource exists."
                )),
            ),
            Self::ResourceExhausted { resource, .. } => (
                "FCP-6002".into(),
                Some(format!(
                    "Resource '{resource}' is exhausted. Wait for resources to become available or reduce concurrent usage. This is usually transient."
                )),
            ),
            Self::BudgetExceeded {
                metric,
                used,
                limit,
                window_seconds,
                ..
            } => (
                "FCP-6004".into(),
                Some(format!(
                    "Usage budget exceeded for {metric:?}. Used {used} of {limit} in the last {window_seconds}s. Reduce usage or wait for the budget window to reset."
                )),
            ),
            Self::Conflict { message, .. } => (
                "FCP-6003".into(),
                Some(format!(
                    "Conflict detected: {message}. Resolve the conflict by refreshing state and retrying with updated data."
                )),
            ),

            // ─────────────────────────────────────────────────────────────────
            // External service errors (FCP-7xxx)
            // ─────────────────────────────────────────────────────────────────
            Self::External { service, status_code, retryable, .. } => {
                let code = match status_code {
                    Some(429) => "FCP-7001", // Rate limited
                    Some(504) => "FCP-7002", // Timeout
                    _ => "FCP-7003",         // Dependency unavailable
                };
                let status_str = status_code.map_or_else(|| "unknown".to_string(), |c| c.to_string());
                let hint = if *retryable {
                    format!(
                        "External service '{service}' returned an error (HTTP {status_str}). This is retryable; wait and retry with exponential backoff."
                    )
                } else {
                    format!(
                        "External service '{service}' returned a non-retryable error (HTTP {status_str}). Check the request parameters and service documentation."
                    )
                };
                (code.into(), Some(hint))
            }
            Self::UpstreamTimeout { service, .. } => (
                "FCP-7002".into(),
                Some(format!(
                    "Request to '{service}' timed out. The service may be slow or overloaded. Retry with a longer timeout or reduce request complexity."
                )),
            ),
            Self::DependencyUnavailable { service, .. } => (
                "FCP-7003".into(),
                Some(format!(
                    "Dependency '{service}' is unavailable. Verify network connectivity and service status. Retry after the service recovers."
                )),
            ),

            // ─────────────────────────────────────────────────────────────────
            // Internal errors (FCP-9xxx)
            // ─────────────────────────────────────────────────────────────────
            Self::Internal { .. } => (
                "FCP-9001".into(),
                Some("An internal error occurred. This is a bug. Please report with the error details and correlation ID if available.".into()),
            ),
            Self::MissingField { field } => (
                "FCP-1006".into(),
                Some(format!("The field '{field}' is missing from the request or structure. Verify the schema."))
            ),
        };

        FcpErrorResponse {
            code,
            message: self.to_string(),
            retryable: self.is_retryable(),
            retry_after_ms: self
                .retry_after()
                .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)),
            details: self.details(),
            ai_recovery_hint: ai_hint,
        }
    }

    /// Extract structured details for the error.
    #[must_use]
    pub fn details(&self) -> Option<serde_json::Value> {
        match self {
            Self::CapabilityDenied { capability, reason } => Some(serde_json::json!({
                "capability": capability,
                "reason": reason,
            })),
            Self::RateLimited { violation, .. } => violation.as_ref().map(|v| {
                serde_json::json!({
                    "throttle_violation": v,
                })
            }),
            Self::BudgetExceeded {
                metric,
                used,
                limit,
                window_seconds,
            } => Some(serde_json::json!({
                "metric": metric,
                "used": used,
                "limit": limit,
                "window_seconds": window_seconds,
            })),
            Self::CapabilityConstraintDenied {
                kind,
                claim_type,
                detail,
            } => Some(serde_json::json!({
                "kind": kind,
                "claim_type": claim_type,
                "detail": detail,
            })),
            Self::ZoneViolation {
                source_zone,
                target_zone,
                ..
            } => Some(serde_json::json!({
                "source_zone": source_zone,
                "target_zone": target_zone,
            })),
            Self::TaintViolation {
                origin_zone,
                target_zone,
                capability,
            } => Some(serde_json::json!({
                "origin_zone": origin_zone,
                "target_zone": target_zone,
                "capability": capability,
            })),
            Self::ElevationRequired {
                capability,
                ttl_seconds,
            } => Some(serde_json::json!({
                "capability": capability,
                "ttl_seconds": ttl_seconds,
            })),
            Self::ConfigurationLeakedSecret {
                field_name_hash,
                detector,
            } => Some(serde_json::json!({
                "field_name_hash": field_name_hash,
                "detector": detector,
            })),
            Self::External {
                service,
                status_code,
                ..
            } => Some(serde_json::json!({
                "service": service,
                "status_code": status_code,
            })),
            _ => None,
        }
    }
}

/// Result type alias for FCP operations.
pub type FcpResult<T> = Result<T, FcpError>;

/// Wire format for error responses (matches FCP specification Section 16.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FcpErrorResponse {
    /// Error code (e.g., "FCP-4002" or "`FCP_FORBIDDEN`")
    pub code: String,

    /// Human-readable message
    pub message: String,

    /// Whether retry might succeed
    pub retryable: bool,

    /// Suggested retry delay in milliseconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,

    /// Structured details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,

    /// Agent-friendly recovery hint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai_recovery_hint: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─────────────────────────────────────────────────────────────────────────
    // Error Category Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn category_protocol_errors() {
        assert_eq!(
            FcpError::InvalidRequest {
                code: 1001,
                message: "test".into()
            }
            .category(),
            ErrorCategory::Protocol
        );
        assert_eq!(
            FcpError::MalformedFrame {
                code: 1002,
                message: "test".into()
            }
            .category(),
            ErrorCategory::Protocol
        );
        assert_eq!(
            FcpError::ChecksumMismatch.category(),
            ErrorCategory::Protocol
        );
        assert_eq!(
            FcpError::VersionMismatch {
                expected: "1.0".into(),
                actual: "2.0".into()
            }
            .category(),
            ErrorCategory::Protocol
        );
    }

    #[test]
    fn category_auth_errors() {
        assert_eq!(
            FcpError::Unauthorized {
                code: 2001,
                message: "test".into()
            }
            .category(),
            ErrorCategory::Auth
        );
        assert_eq!(FcpError::TokenExpired.category(), ErrorCategory::Auth);
        assert_eq!(FcpError::InvalidSignature.category(), ErrorCategory::Auth);
    }

    #[test]
    fn category_capability_errors() {
        assert_eq!(
            FcpError::CapabilityDenied {
                capability: "test".into(),
                reason: "denied".into()
            }
            .category(),
            ErrorCategory::Capability
        );
        assert_eq!(
            FcpError::RateLimited {
                retry_after_ms: 1000,
                violation: None
            }
            .category(),
            ErrorCategory::Capability
        );
    }

    #[test]
    fn category_zone_errors() {
        assert_eq!(
            FcpError::ZoneViolation {
                source_zone: "a".into(),
                target_zone: "b".into(),
                message: "test".into()
            }
            .category(),
            ErrorCategory::Zone
        );
        assert_eq!(
            FcpError::TaintViolation {
                origin_zone: "a".into(),
                target_zone: "b".into(),
                capability: "c".into()
            }
            .category(),
            ErrorCategory::Zone
        );
    }

    #[test]
    fn category_connector_errors() {
        assert_eq!(FcpError::NotConfigured.category(), ErrorCategory::Connector);
        assert_eq!(FcpError::NotHandshaken.category(), ErrorCategory::Connector);
        assert_eq!(
            FcpError::StreamingNotSupported.category(),
            ErrorCategory::Connector
        );
        assert_eq!(
            FcpError::configuration_leaked_secret("token", "named_secret_field").category(),
            ErrorCategory::Connector
        );
    }

    #[test]
    fn category_resource_errors() {
        assert_eq!(
            FcpError::ResourceNotFound {
                resource: "test".into()
            }
            .category(),
            ErrorCategory::Resource
        );
        assert_eq!(
            FcpError::BudgetExceeded {
                metric: UsageMetricKind::Tokens,
                used: 10,
                limit: 5,
                window_seconds: 60,
            }
            .category(),
            ErrorCategory::Resource
        );
        assert_eq!(
            FcpError::Conflict {
                message: "test".into()
            }
            .category(),
            ErrorCategory::Resource
        );
    }

    #[test]
    fn category_external_errors() {
        assert_eq!(
            FcpError::UpstreamTimeout {
                service: "test".into()
            }
            .category(),
            ErrorCategory::External
        );
        assert_eq!(
            FcpError::DependencyUnavailable {
                service: "test".into()
            }
            .category(),
            ErrorCategory::External
        );
    }

    #[test]
    fn category_internal_errors() {
        assert_eq!(
            FcpError::Internal {
                message: "test".into()
            }
            .category(),
            ErrorCategory::Internal
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Error Code Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn numeric_code_ranges() {
        // Protocol: 1000-1999
        assert_eq!(FcpError::ChecksumMismatch.numeric_code(), 1004);
        assert!(FcpError::ChecksumMismatch.numeric_code() >= 1000);
        assert!(FcpError::ChecksumMismatch.numeric_code() < 2000);

        // Auth: 2000-2999
        assert_eq!(FcpError::TokenExpired.numeric_code(), 2002);
        assert!(FcpError::TokenExpired.numeric_code() >= 2000);
        assert!(FcpError::TokenExpired.numeric_code() < 3000);

        // Capability: 3000-3999
        assert_eq!(
            FcpError::CapabilityDenied {
                capability: "x".into(),
                reason: "y".into()
            }
            .numeric_code(),
            3001
        );

        // Zone: 4000-4999
        assert_eq!(
            FcpError::ZoneViolation {
                source_zone: "a".into(),
                target_zone: "b".into(),
                message: "c".into()
            }
            .numeric_code(),
            4001
        );

        // Connector: 5000-5999
        assert_eq!(FcpError::NotConfigured.numeric_code(), 5002);
        assert_eq!(
            FcpError::configuration_leaked_secret("token", "named_secret_field").numeric_code(),
            5006
        );

        // Resource: 6000-6999
        assert_eq!(
            FcpError::ResourceNotFound {
                resource: "x".into()
            }
            .numeric_code(),
            6001
        );
        assert_eq!(
            FcpError::BudgetExceeded {
                metric: UsageMetricKind::Bytes,
                used: 10,
                limit: 5,
                window_seconds: 60,
            }
            .numeric_code(),
            6004
        );

        // External: 7000-7999
        assert_eq!(
            FcpError::UpstreamTimeout {
                service: "x".into()
            }
            .numeric_code(),
            7002
        );

        // Internal: 9000-9999
        assert_eq!(
            FcpError::Internal {
                message: "x".into()
            }
            .numeric_code(),
            9001
        );
    }

    #[test]
    fn error_code_format() {
        assert_eq!(FcpError::ChecksumMismatch.error_code(), "FCP-1004");
        assert_eq!(FcpError::TokenExpired.error_code(), "FCP-2002");
        assert_eq!(
            FcpError::CapabilityDenied {
                capability: "x".into(),
                reason: "y".into()
            }
            .error_code(),
            "FCP-3001"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // AI Recovery Hint Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn all_errors_have_ai_hints() {
        // Representative errors from each category
        let errors: Vec<FcpError> = vec![
            FcpError::InvalidRequest {
                code: 1001,
                message: "test".into(),
            },
            FcpError::MalformedFrame {
                code: 1002,
                message: "test".into(),
            },
            FcpError::ChecksumMismatch,
            FcpError::VersionMismatch {
                expected: "1.0".into(),
                actual: "2.0".into(),
            },
            FcpError::Unauthorized {
                code: 2001,
                message: "test".into(),
            },
            FcpError::TokenExpired,
            FcpError::InvalidSignature,
            FcpError::CapabilityDenied {
                capability: "cap.test".into(),
                reason: "denied".into(),
            },
            FcpError::RateLimited {
                retry_after_ms: 5000,
                violation: None,
            },
            FcpError::OperationNotGranted {
                operation: "op.test".into(),
            },
            FcpError::ResourceNotAllowed {
                resource: "res.test".into(),
            },
            FcpError::ZoneViolation {
                source_zone: "z:public".into(),
                target_zone: "z:private".into(),
                message: "denied".into(),
            },
            FcpError::TaintViolation {
                origin_zone: "z:public".into(),
                target_zone: "z:private".into(),
                capability: "cap.test".into(),
            },
            FcpError::ElevationRequired {
                capability: "cap.admin".into(),
                ttl_seconds: Some(3600),
            },
            FcpError::ConnectorUnavailable {
                code: 5001,
                message: "busy".into(),
            },
            FcpError::NotConfigured,
            FcpError::NotHandshaken,
            FcpError::HealthCheckFailed {
                reason: "timeout".into(),
            },
            FcpError::StreamingNotSupported,
            FcpError::configuration_leaked_secret("token", "named_secret_field"),
            FcpError::ResourceNotFound {
                resource: "file.txt".into(),
            },
            FcpError::ResourceExhausted {
                resource: "memory".into(),
            },
            FcpError::Conflict {
                message: "version mismatch".into(),
            },
            FcpError::External {
                service: "api.example.com".into(),
                message: "error".into(),
                status_code: Some(500),
                retryable: true,
                retry_after: None,
            },
            FcpError::UpstreamTimeout {
                service: "api.example.com".into(),
            },
            FcpError::DependencyUnavailable {
                service: "database".into(),
            },
            FcpError::Internal {
                message: "unexpected".into(),
            },
        ];

        for err in errors {
            let resp = err.to_response();
            assert!(
                resp.ai_recovery_hint.is_some(),
                "Error {} missing AI recovery hint",
                resp.code
            );
            assert!(
                !resp.ai_recovery_hint.as_ref().unwrap().is_empty(),
                "Error {} has empty AI recovery hint",
                resp.code
            );
        }
    }

    #[test]
    fn ai_hints_are_actionable() {
        // Verify hints contain actionable guidance
        let err = FcpError::TokenExpired;
        let hint = err.to_response().ai_recovery_hint.unwrap();
        assert!(hint.contains("token") || hint.contains("Token"));

        let err = FcpError::RateLimited {
            retry_after_ms: 5000,
            violation: None,
        };
        let hint = err.to_response().ai_recovery_hint.unwrap();
        assert!(hint.contains("5000")); // Should mention the specific delay

        let err = FcpError::CapabilityDenied {
            capability: "cap.admin".into(),
            reason: "not authorized".into(),
        };
        let hint = err.to_response().ai_recovery_hint.unwrap();
        assert!(hint.contains("cap.admin")); // Should mention the specific capability
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden Vector Tests (Representative Error Serialization)
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn golden_vector_token_expired() {
        let err = FcpError::TokenExpired;
        let resp = err.to_response();

        assert_eq!(resp.code, "FCP-2002");
        assert_eq!(resp.message, "Token expired");
        assert!(!resp.retryable);
        assert!(resp.retry_after_ms.is_none());
        assert!(resp.details.is_none());
        assert!(resp.ai_recovery_hint.is_some());
    }

    #[test]
    fn golden_vector_rate_limited() {
        let err = FcpError::RateLimited {
            retry_after_ms: 30000,
            violation: None,
        };
        let resp = err.to_response();

        assert_eq!(resp.code, "FCP-3002");
        assert!(resp.message.contains("30000"));
        assert!(resp.retryable);
        assert_eq!(resp.retry_after_ms, Some(30000));
        assert!(resp.ai_recovery_hint.is_some());
    }

    #[test]
    fn golden_vector_zone_violation() {
        let err = FcpError::ZoneViolation {
            source_zone: "z:public".into(),
            target_zone: "z:owner".into(),
            message: "Integrity elevation required".into(),
        };
        let resp = err.to_response();

        assert_eq!(resp.code, "FCP-4001");
        assert!(!resp.retryable);
        assert!(resp.details.is_some());

        let details = resp.details.unwrap();
        assert_eq!(details["source_zone"], "z:public");
        assert_eq!(details["target_zone"], "z:owner");

        let hint = resp.ai_recovery_hint.unwrap();
        assert!(hint.contains("z:public"));
        assert!(hint.contains("z:owner"));
    }

    #[test]
    fn golden_vector_external_rate_limited() {
        let err = FcpError::External {
            service: "api.github.com".into(),
            message: "Rate limit exceeded".into(),
            status_code: Some(429),
            retryable: true,
            retry_after: Some(Duration::from_secs(60)),
        };
        let resp = err.to_response();

        assert_eq!(resp.code, "FCP-7001");
        assert!(resp.retryable);
        assert_eq!(resp.retry_after_ms, Some(60000));

        let hint = resp.ai_recovery_hint.unwrap();
        assert!(hint.contains("api.github.com"));
        assert!(hint.contains("429"));
    }

    #[test]
    fn golden_vector_internal_error() {
        let err = FcpError::Internal {
            message: "Unexpected panic in handler".into(),
        };
        let resp = err.to_response();

        assert_eq!(resp.code, "FCP-9001");
        assert!(!resp.retryable);
        assert!(resp.message.contains("Unexpected panic"));

        let hint = resp.ai_recovery_hint.unwrap();
        assert!(hint.contains("bug") || hint.contains("report"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Category Code Range Validation
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn category_code_ranges_are_correct() {
        assert_eq!(ErrorCategory::Protocol.code_range(), (1000, 1999));
        assert_eq!(ErrorCategory::Auth.code_range(), (2000, 2999));
        assert_eq!(ErrorCategory::Capability.code_range(), (3000, 3999));
        assert_eq!(ErrorCategory::Zone.code_range(), (4000, 4999));
        assert_eq!(ErrorCategory::Connector.code_range(), (5000, 5999));
        assert_eq!(ErrorCategory::Resource.code_range(), (6000, 6999));
        assert_eq!(ErrorCategory::External.code_range(), (7000, 7999));
        assert_eq!(ErrorCategory::Internal.code_range(), (9000, 9999));
    }

    #[test]
    fn category_names() {
        assert_eq!(ErrorCategory::Protocol.name(), "Protocol");
        assert_eq!(ErrorCategory::Auth.name(), "Auth/Identity");
        assert_eq!(ErrorCategory::Capability.name(), "Capability");
        assert_eq!(ErrorCategory::Zone.name(), "Zone/Topology");
        assert_eq!(ErrorCategory::Connector.name(), "Connector");
        assert_eq!(ErrorCategory::Resource.name(), "Resource");
        assert_eq!(ErrorCategory::External.name(), "External Service");
        assert_eq!(ErrorCategory::Internal.name(), "Internal");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Retryable Error Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn retryable_rate_limited() {
        let err = FcpError::RateLimited {
            retry_after_ms: 5000,
            violation: None,
        };
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn retryable_resource_exhausted() {
        let err = FcpError::ResourceExhausted {
            resource: "memory".into(),
        };
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), None);
    }

    #[test]
    fn retryable_upstream_timeout() {
        let err = FcpError::UpstreamTimeout {
            service: "external-api".into(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn retryable_dependency_unavailable() {
        let err = FcpError::DependencyUnavailable {
            service: "database".into(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn retryable_connector_unavailable() {
        let err = FcpError::ConnectorUnavailable {
            code: 5001,
            message: "Connector busy".into(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn retryable_external_with_flag() {
        let err = FcpError::External {
            service: "api".into(),
            message: "Error".into(),
            status_code: Some(503),
            retryable: true,
            retry_after: Some(Duration::from_secs(30)),
        };
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn not_retryable_external() {
        let err = FcpError::External {
            service: "api".into(),
            message: "Bad request".into(),
            status_code: Some(400),
            retryable: false,
            retry_after: None,
        };
        assert!(!err.is_retryable());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Non-Retryable Error Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn not_retryable_invalid_request() {
        let err = FcpError::InvalidRequest {
            code: 1001,
            message: "Missing field".into(),
        };
        assert!(!err.is_retryable());
        assert_eq!(err.retry_after(), None);
    }

    #[test]
    fn not_retryable_token_expired() {
        let err = FcpError::TokenExpired;
        assert!(!err.is_retryable());
    }

    #[test]
    fn not_retryable_invalid_signature() {
        let err = FcpError::InvalidSignature;
        assert!(!err.is_retryable());
    }

    #[test]
    fn not_retryable_capability_denied() {
        let err = FcpError::CapabilityDenied {
            capability: "cap.write".into(),
            reason: "Not authorized".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn not_retryable_zone_violation() {
        let err = FcpError::ZoneViolation {
            source_zone: "z:public".into(),
            target_zone: "z:private".into(),
            message: "Access denied".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn not_retryable_internal() {
        let err = FcpError::Internal {
            message: "Unexpected error".into(),
        };
        assert!(!err.is_retryable());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Error Response Conversion Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn to_response_checksum_mismatch() {
        let err = FcpError::ChecksumMismatch;
        let resp = err.to_response();
        assert_eq!(resp.code, "FCP-1004");
        assert!(!resp.retryable);
    }

    #[test]
    fn to_response_version_mismatch() {
        let err = FcpError::VersionMismatch {
            expected: "2.0.0".into(),
            actual: "1.0.0".into(),
        };
        let resp = err.to_response();
        assert_eq!(resp.code, "FCP-1005");
        assert!(resp.message.contains("expected 2.0.0"));
        assert!(resp.message.contains("got 1.0.0"));
    }

    #[test]
    fn to_response_token_expired_with_hint() {
        let err = FcpError::TokenExpired;
        let resp = err.to_response();
        assert_eq!(resp.code, "FCP-2002");
        assert!(resp.ai_recovery_hint.is_some());
        assert!(
            resp.ai_recovery_hint
                .unwrap()
                .contains("new capability token")
        );
    }

    #[test]
    fn to_response_invalid_signature() {
        let err = FcpError::InvalidSignature;
        let resp = err.to_response();
        assert_eq!(resp.code, "FCP-2003");
    }

    #[test]
    fn to_response_capability_denied_with_details() {
        let err = FcpError::CapabilityDenied {
            capability: "cap.admin".into(),
            reason: "Insufficient privileges".into(),
        };
        let resp = err.to_response();
        assert_eq!(resp.code, "FCP-3001");
        assert!(resp.details.is_some());
        let details = resp.details.unwrap();
        assert_eq!(details["capability"], "cap.admin");
        assert_eq!(details["reason"], "Insufficient privileges");
    }

    #[test]
    fn to_response_rate_limited_with_retry() {
        let err = FcpError::RateLimited {
            retry_after_ms: 10000,
            violation: None,
        };
        let resp = err.to_response();
        assert_eq!(resp.code, "FCP-3002");
        assert!(resp.retryable);
        assert_eq!(resp.retry_after_ms, Some(10000));
        assert!(resp.ai_recovery_hint.is_some());
    }

    #[test]
    fn to_response_zone_violation_with_details() {
        let err = FcpError::ZoneViolation {
            source_zone: "z:public".into(),
            target_zone: "z:owner".into(),
            message: "Cross-zone access denied".into(),
        };
        let resp = err.to_response();
        assert_eq!(resp.code, "FCP-4001");
        assert!(resp.details.is_some());
        let details = resp.details.unwrap();
        assert_eq!(details["source_zone"], "z:public");
        assert_eq!(details["target_zone"], "z:owner");
    }

    #[test]
    fn to_response_taint_violation_with_hint() {
        let err = FcpError::TaintViolation {
            origin_zone: "z:public".into(),
            target_zone: "z:private".into(),
            capability: "cap.sensitive".into(),
        };
        let resp = err.to_response();
        assert_eq!(resp.code, "FCP-4002");
        assert!(resp.ai_recovery_hint.is_some());
        assert!(resp.ai_recovery_hint.unwrap().contains("elevation"));
    }

    #[test]
    fn to_response_elevation_required_with_hint() {
        let err = FcpError::ElevationRequired {
            capability: "cap.admin".into(),
            ttl_seconds: Some(3600),
        };
        let resp = err.to_response();
        assert_eq!(resp.code, "FCP-4003");
        assert!(resp.details.is_some());
        let details = resp.details.unwrap();
        assert_eq!(details["capability"], "cap.admin");
        assert_eq!(details["ttl_seconds"], 3600);
        assert!(resp.ai_recovery_hint.is_some());
    }

    #[test]
    fn to_response_not_configured() {
        let err = FcpError::NotConfigured;
        let resp = err.to_response();
        assert_eq!(resp.code, "FCP-5002");
    }

    #[test]
    fn to_response_not_handshaken() {
        let err = FcpError::NotHandshaken;
        let resp = err.to_response();
        assert_eq!(resp.code, "FCP-5003");
    }

    #[test]
    fn to_response_resource_not_found() {
        let err = FcpError::ResourceNotFound {
            resource: "file:///missing".into(),
        };
        let resp = err.to_response();
        assert_eq!(resp.code, "FCP-6001");
        assert!(resp.message.contains("file:///missing"));
    }

    #[test]
    fn to_response_external_rate_limited() {
        let err = FcpError::External {
            service: "github".into(),
            message: "Rate limited".into(),
            status_code: Some(429),
            retryable: true,
            retry_after: Some(Duration::from_secs(60)),
        };
        let resp = err.to_response();
        assert_eq!(resp.code, "FCP-7001");
        assert!(resp.retryable);
        assert_eq!(resp.retry_after_ms, Some(60000));
    }

    #[test]
    fn to_response_external_timeout() {
        let err = FcpError::External {
            service: "api".into(),
            message: "Gateway timeout".into(),
            status_code: Some(504),
            retryable: true,
            retry_after: None,
        };
        let resp = err.to_response();
        assert_eq!(resp.code, "FCP-7002");
    }

    #[test]
    fn to_response_internal() {
        let err = FcpError::Internal {
            message: "Panic recovered".into(),
        };
        let resp = err.to_response();
        assert_eq!(resp.code, "FCP-9001");
        assert!(resp.message.contains("Panic recovered"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Error Response Serialization Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn error_response_serialization_roundtrip() {
        let resp = FcpErrorResponse {
            code: "FCP-1234".into(),
            message: "Test error".into(),
            retryable: true,
            retry_after_ms: Some(5000),
            details: Some(serde_json::json!({"key": "value"})),
            ai_recovery_hint: Some("Try again".into()),
        };

        let json = serde_json::to_string(&resp).unwrap();
        let deserialized: FcpErrorResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.code, "FCP-1234");
        assert_eq!(deserialized.message, "Test error");
        assert!(deserialized.retryable);
        assert_eq!(deserialized.retry_after_ms, Some(5000));
        assert!(deserialized.ai_recovery_hint.is_some());
    }

    #[test]
    fn error_response_omits_none_fields() {
        let resp = FcpErrorResponse {
            code: "FCP-1000".into(),
            message: "Error".into(),
            retryable: false,
            retry_after_ms: None,
            details: None,
            ai_recovery_hint: None,
        };

        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("retry_after_ms"));
        assert!(!json.contains("details"));
        assert!(!json.contains("ai_recovery_hint"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Error Message Display Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn error_display_invalid_request() {
        let err = FcpError::InvalidRequest {
            code: 1001,
            message: "Missing required field".into(),
        };
        assert_eq!(err.to_string(), "Invalid request: Missing required field");
    }

    #[test]
    fn error_display_malformed_frame() {
        let err = FcpError::MalformedFrame {
            code: 1002,
            message: "Invalid CBOR".into(),
        };
        assert_eq!(err.to_string(), "Malformed frame: Invalid CBOR");
    }

    #[test]
    fn error_display_zone_violation() {
        let err = FcpError::ZoneViolation {
            source_zone: "z:a".into(),
            target_zone: "z:b".into(),
            message: "Denied".into(),
        };
        assert_eq!(err.to_string(), "Zone violation: Denied");
    }

    #[test]
    fn error_display_taint_violation() {
        let err = FcpError::TaintViolation {
            origin_zone: "z:public".into(),
            target_zone: "z:private".into(),
            capability: "cap.secret".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("z:public"));
        assert!(msg.contains("z:private"));
        assert!(msg.contains("cap.secret"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // FcpError Serialization Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn fcp_error_serialization_roundtrip() {
        let errors = vec![
            FcpError::ChecksumMismatch,
            FcpError::TokenExpired,
            FcpError::InvalidSignature,
            FcpError::NotConfigured,
            FcpError::NotHandshaken,
            FcpError::StreamingNotSupported,
            FcpError::configuration_leaked_secret("token", "named_secret_field"),
            FcpError::RateLimited {
                retry_after_ms: 1000,
                violation: None,
            },
            FcpError::ResourceNotFound {
                resource: "test".into(),
            },
            FcpError::Internal {
                message: "error".into(),
            },
        ];

        for err in errors {
            let json = serde_json::to_string(&err).unwrap();
            let deserialized: FcpError = serde_json::from_str(&json).unwrap();
            // Compare display strings since some errors don't implement PartialEq
            assert_eq!(err.to_string(), deserialized.to_string());
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ErrorCategory trait coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn error_category_copy() {
        let cat = ErrorCategory::Protocol;
        let copied = cat;
        assert_eq!(cat, copied);
    }

    #[test]
    fn error_category_hash_consistency() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let cat = ErrorCategory::Zone;
        let mut h1 = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        cat.hash(&mut h1);
        cat.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn error_category_serde_roundtrip() {
        let categories = [
            ErrorCategory::Protocol,
            ErrorCategory::Auth,
            ErrorCategory::Capability,
            ErrorCategory::Zone,
            ErrorCategory::Connector,
            ErrorCategory::Resource,
            ErrorCategory::External,
            ErrorCategory::Internal,
        ];
        for cat in categories {
            let json = serde_json::to_string(&cat).unwrap();
            let back: ErrorCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(cat, back);
        }
    }

    #[test]
    fn error_category_inequality() {
        assert_ne!(ErrorCategory::Protocol, ErrorCategory::Auth);
        assert_ne!(ErrorCategory::Zone, ErrorCategory::Internal);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // FcpError trait coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn fcp_error_clone() {
        let err = FcpError::ZoneViolation {
            source_zone: "z:a".into(),
            target_zone: "z:b".into(),
            message: "denied".into(),
        };
        let cloned = err.clone();
        assert_eq!(err.to_string(), cloned.to_string());
    }

    #[test]
    fn fcp_error_std_error_trait() {
        let err: Box<dyn std::error::Error> = Box::new(FcpError::TokenExpired);
        assert!(!err.to_string().is_empty());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // FcpError category coverage for all variants
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn category_missing_field_is_protocol() {
        let err = FcpError::MissingField {
            field: "name".into(),
        };
        assert_eq!(err.category(), ErrorCategory::Protocol);
    }

    #[test]
    fn category_budget_exceeded_is_resource() {
        let err = FcpError::BudgetExceeded {
            metric: crate::UsageMetricKind::ApiCredits,
            used: 100,
            limit: 50,
            window_seconds: 3600,
        };
        assert_eq!(err.category(), ErrorCategory::Resource);
    }

    #[test]
    fn category_operation_not_granted_is_capability() {
        let err = FcpError::OperationNotGranted {
            operation: "op.test".into(),
        };
        assert_eq!(err.category(), ErrorCategory::Capability);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // FcpError numeric_code coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn numeric_code_missing_field() {
        let err = FcpError::MissingField { field: "x".into() };
        assert_eq!(err.numeric_code(), 1006);
    }

    #[test]
    fn numeric_code_budget_exceeded() {
        let err = FcpError::BudgetExceeded {
            metric: crate::UsageMetricKind::ApiCredits,
            used: 100,
            limit: 50,
            window_seconds: 3600,
        };
        assert_eq!(err.numeric_code(), 6004);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // FcpError display coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn error_display_missing_field() {
        let err = FcpError::MissingField {
            field: "zone_id".into(),
        };
        assert_eq!(err.to_string(), "Missing required field: zone_id");
    }

    #[test]
    fn error_display_budget_exceeded() {
        let err = FcpError::BudgetExceeded {
            metric: crate::UsageMetricKind::ApiCredits,
            used: 100,
            limit: 50,
            window_seconds: 3600,
        };
        let msg = err.to_string();
        assert!(msg.contains("100"));
        assert!(msg.contains("50"));
        assert!(msg.contains("3600"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // FcpError retryable coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn retryable_budget_exceeded() {
        let err = FcpError::BudgetExceeded {
            metric: crate::UsageMetricKind::ApiCredits,
            used: 100,
            limit: 50,
            window_seconds: 3600,
        };
        assert!(err.is_retryable());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // FcpErrorResponse trait coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn error_response_clone() {
        let resp = FcpErrorResponse {
            code: "FCP-1000".into(),
            message: "test".into(),
            retryable: false,
            retry_after_ms: None,
            details: None,
            ai_recovery_hint: None,
        };
        let cloned = Clone::clone(&resp);
        assert_eq!(cloned.code, "FCP-1000");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // FcpError serde edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn fcp_error_serde_external_with_retry_after() {
        let err = FcpError::External {
            service: "api".into(),
            message: "rate limited".into(),
            status_code: Some(429),
            retryable: true,
            retry_after: Some(Duration::from_secs(30)),
        };
        let json = serde_json::to_string(&err).unwrap();
        let back: FcpError = serde_json::from_str(&json).unwrap();
        assert_eq!(err.to_string(), back.to_string());
    }

    #[test]
    fn fcp_error_serde_budget_exceeded() {
        let err = FcpError::BudgetExceeded {
            metric: crate::UsageMetricKind::ApiCredits,
            used: 100,
            limit: 50,
            window_seconds: 3600,
        };
        let json = serde_json::to_string(&err).unwrap();
        let back: FcpError = serde_json::from_str(&json).unwrap();
        assert_eq!(err.to_string(), back.to_string());
    }

    #[test]
    fn to_response_missing_field() {
        let err = FcpError::MissingField {
            field: "zone_id".into(),
        };
        let resp = err.to_response();
        assert_eq!(resp.code, "FCP-1006");
        assert!(resp.ai_recovery_hint.is_some());
        assert!(resp.ai_recovery_hint.unwrap().contains("zone_id"));
    }

    #[test]
    fn to_response_budget_exceeded() {
        let err = FcpError::BudgetExceeded {
            metric: crate::UsageMetricKind::ApiCredits,
            used: 100,
            limit: 50,
            window_seconds: 3600,
        };
        let resp = err.to_response();
        assert_eq!(resp.code, "FCP-6004");
        assert!(resp.retryable);
        assert!(resp.details.is_some());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Display message tests for every variant
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn display_checksum_mismatch() {
        assert_eq!(FcpError::ChecksumMismatch.to_string(), "Checksum mismatch");
    }

    #[test]
    fn display_token_expired() {
        assert_eq!(FcpError::TokenExpired.to_string(), "Token expired");
    }

    #[test]
    fn display_invalid_signature() {
        assert_eq!(FcpError::InvalidSignature.to_string(), "Invalid signature");
    }

    #[test]
    fn display_not_configured() {
        assert_eq!(
            FcpError::NotConfigured.to_string(),
            "Connector not configured"
        );
    }

    #[test]
    fn display_not_handshaken() {
        assert_eq!(
            FcpError::NotHandshaken.to_string(),
            "Connector not handshaken"
        );
    }

    #[test]
    fn display_streaming_not_supported() {
        assert_eq!(
            FcpError::StreamingNotSupported.to_string(),
            "Streaming not supported"
        );
    }

    #[test]
    fn display_configuration_leaked_secret_redacts_field_name() {
        let err = FcpError::configuration_leaked_secret("token", "named_secret_field");
        let rendered = err.to_string();

        assert!(rendered.contains("field_name_hash="));
        assert!(rendered.contains("detector=named_secret_field"));
        assert!(!rendered.contains("token"));
        assert!(!format!("{err:?}").contains("token"));
    }

    #[test]
    fn display_capability_denied() {
        let err = FcpError::CapabilityDenied {
            capability: "cap.write".into(),
            reason: "not authorized".into(),
        };
        assert_eq!(err.to_string(), "Capability denied: cap.write");
    }

    #[test]
    fn display_rate_limited() {
        let err = FcpError::RateLimited {
            retry_after_ms: 2500,
            violation: None,
        };
        assert_eq!(err.to_string(), "Rate limited: retry after 2500ms");
    }

    #[test]
    fn display_operation_not_granted() {
        let err = FcpError::OperationNotGranted {
            operation: "op.delete".into(),
        };
        assert_eq!(err.to_string(), "Operation not granted: op.delete");
    }

    #[test]
    fn display_resource_not_allowed() {
        let err = FcpError::ResourceNotAllowed {
            resource: "secret.key".into(),
        };
        assert_eq!(err.to_string(), "Resource not allowed: secret.key");
    }

    #[test]
    fn display_connector_unavailable() {
        let err = FcpError::ConnectorUnavailable {
            code: 5001,
            message: "overloaded".into(),
        };
        assert_eq!(err.to_string(), "Connector unavailable: overloaded");
    }

    #[test]
    fn display_health_check_failed() {
        let err = FcpError::HealthCheckFailed {
            reason: "connection refused".into(),
        };
        assert_eq!(err.to_string(), "Health check failed: connection refused");
    }

    #[test]
    fn display_resource_not_found() {
        let err = FcpError::ResourceNotFound {
            resource: "user:42".into(),
        };
        assert_eq!(err.to_string(), "Resource not found: user:42");
    }

    #[test]
    fn display_resource_exhausted() {
        let err = FcpError::ResourceExhausted {
            resource: "disk".into(),
        };
        assert_eq!(err.to_string(), "Resource exhausted: disk");
    }

    #[test]
    fn display_conflict() {
        let err = FcpError::Conflict {
            message: "version mismatch".into(),
        };
        assert_eq!(err.to_string(), "Conflict: version mismatch");
    }

    #[test]
    fn display_external() {
        let err = FcpError::External {
            service: "stripe".into(),
            message: "payment failed".into(),
            status_code: Some(402),
            retryable: false,
            retry_after: None,
        };
        assert_eq!(
            err.to_string(),
            "External service error: stripe - payment failed"
        );
    }

    #[test]
    fn display_upstream_timeout() {
        let err = FcpError::UpstreamTimeout {
            service: "db-primary".into(),
        };
        assert_eq!(err.to_string(), "Upstream timeout: db-primary");
    }

    #[test]
    fn display_dependency_unavailable() {
        let err = FcpError::DependencyUnavailable {
            service: "redis-cache".into(),
        };
        assert_eq!(err.to_string(), "Dependency unavailable: redis-cache");
    }

    #[test]
    fn display_internal() {
        let err = FcpError::Internal {
            message: "null pointer".into(),
        };
        assert_eq!(err.to_string(), "Internal error: null pointer");
    }

    #[test]
    fn display_elevation_required() {
        let err = FcpError::ElevationRequired {
            capability: "cap.destroy".into(),
            ttl_seconds: Some(120),
        };
        assert_eq!(err.to_string(), "Elevation required for cap.destroy");
    }

    #[test]
    fn display_unauthorized() {
        let err = FcpError::Unauthorized {
            code: 2001,
            message: "invalid token".into(),
        };
        assert_eq!(err.to_string(), "Unauthorized: invalid token");
    }

    #[test]
    fn display_version_mismatch() {
        let err = FcpError::VersionMismatch {
            expected: "3.0".into(),
            actual: "1.5".into(),
        };
        assert_eq!(
            err.to_string(),
            "Protocol version mismatch: expected 3.0, got 1.5"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Clone tests (use original after clone to avoid redundant_clone lint)
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn clone_invalid_request() {
        let err = FcpError::InvalidRequest {
            code: 1001,
            message: "bad".into(),
        };
        let cloned = err.clone();
        assert_eq!(err.to_string(), cloned.to_string());
        assert_eq!(err.numeric_code(), cloned.numeric_code());
    }

    #[test]
    fn clone_external_with_retry() {
        let err = FcpError::External {
            service: "svc".into(),
            message: "err".into(),
            status_code: Some(503),
            retryable: true,
            retry_after: Some(Duration::from_secs(10)),
        };
        let cloned = err.clone();
        assert_eq!(err.to_string(), cloned.to_string());
        assert_eq!(err.is_retryable(), cloned.is_retryable());
        assert_eq!(err.retry_after(), cloned.retry_after());
    }

    #[test]
    fn clone_rate_limited_with_violation() {
        let violation = crate::ThrottleViolation {
            violation_id: crate::ObjectId::from_bytes([1; 32]),
            timestamp_ms: 1000,
            zone_id: crate::ZoneId::owner(),
            connector_id: None,
            operation_id: None,
            limit_type: crate::ratelimit::LimitType::Rpm,
            limit_value: 100,
            current_value: 150,
            retry_after_ms: 5000,
        };
        let err = FcpError::RateLimited {
            retry_after_ms: 5000,
            violation: Some(Box::new(violation)),
        };
        let cloned = err.clone();
        assert_eq!(err.to_string(), cloned.to_string());
        assert_eq!(err.retry_after(), cloned.retry_after());
    }

    #[test]
    fn clone_budget_exceeded() {
        let err = FcpError::BudgetExceeded {
            metric: UsageMetricKind::Bytes,
            used: 999,
            limit: 500,
            window_seconds: 120,
        };
        let cloned = err.clone();
        assert_eq!(err.to_string(), cloned.to_string());
        assert_eq!(err.numeric_code(), cloned.numeric_code());
    }

    #[test]
    fn clone_taint_violation() {
        let err = FcpError::TaintViolation {
            origin_zone: "z:work".into(),
            target_zone: "z:owner".into(),
            capability: "cap.exec".into(),
        };
        let cloned = err.clone();
        assert_eq!(err.to_string(), cloned.to_string());
        assert_eq!(err.category(), cloned.category());
    }

    #[test]
    fn clone_unit_variants() {
        let err = FcpError::ChecksumMismatch;
        let cloned = err.clone();
        assert_eq!(err.to_string(), cloned.to_string());

        let err = FcpError::TokenExpired;
        let cloned = err.clone();
        assert_eq!(err.to_string(), cloned.to_string());

        let err = FcpError::InvalidSignature;
        let cloned = err.clone();
        assert_eq!(err.to_string(), cloned.to_string());

        let err = FcpError::NotConfigured;
        let cloned = err.clone();
        assert_eq!(err.to_string(), cloned.to_string());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Debug trait tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn debug_fcp_error_not_empty() {
        let err = FcpError::Internal {
            message: "oops".into(),
        };
        let dbg = format!("{err:?}");
        assert!(!dbg.is_empty());
        assert!(dbg.contains("Internal"));
    }

    #[test]
    fn debug_error_category() {
        let cat = ErrorCategory::External;
        let dbg = format!("{cat:?}");
        assert_eq!(dbg, "External");
    }

    #[test]
    fn debug_error_response() {
        let resp = FcpErrorResponse {
            code: "FCP-9001".into(),
            message: "boom".into(),
            retryable: false,
            retry_after_ms: None,
            details: None,
            ai_recovery_hint: None,
        };
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("FCP-9001"));
        assert!(dbg.contains("boom"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Serde roundtrip tests for all FcpError variants
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn serde_roundtrip_all_protocol_variants() {
        let errors = vec![
            FcpError::InvalidRequest {
                code: 1001,
                message: "bad input".into(),
            },
            FcpError::MalformedFrame {
                code: 1002,
                message: "corrupt cbor".into(),
            },
            FcpError::MissingField {
                field: "connector_id".into(),
            },
            FcpError::ChecksumMismatch,
            FcpError::VersionMismatch {
                expected: "2.0".into(),
                actual: "1.0".into(),
            },
        ];
        for err in errors {
            let json = serde_json::to_string(&err).unwrap();
            let back: FcpError = serde_json::from_str(&json).unwrap();
            assert_eq!(err.to_string(), back.to_string());
            assert_eq!(err.numeric_code(), back.numeric_code());
        }
    }

    #[test]
    fn serde_roundtrip_all_auth_variants() {
        let errors = vec![
            FcpError::Unauthorized {
                code: 2001,
                message: "forbidden".into(),
            },
            FcpError::TokenExpired,
            FcpError::InvalidSignature,
        ];
        for err in errors {
            let json = serde_json::to_string(&err).unwrap();
            let back: FcpError = serde_json::from_str(&json).unwrap();
            assert_eq!(err.to_string(), back.to_string());
        }
    }

    #[test]
    fn serde_roundtrip_all_capability_variants() {
        let errors = vec![
            FcpError::CapabilityDenied {
                capability: "cap.write".into(),
                reason: "nope".into(),
            },
            FcpError::RateLimited {
                retry_after_ms: 500,
                violation: None,
            },
            FcpError::OperationNotGranted {
                operation: "op.delete".into(),
            },
            FcpError::ResourceNotAllowed {
                resource: "secret".into(),
            },
        ];
        for err in errors {
            let json = serde_json::to_string(&err).unwrap();
            let back: FcpError = serde_json::from_str(&json).unwrap();
            assert_eq!(err.to_string(), back.to_string());
        }
    }

    #[test]
    fn serde_roundtrip_all_zone_variants() {
        let errors = vec![
            FcpError::ZoneViolation {
                source_zone: "z:public".into(),
                target_zone: "z:owner".into(),
                message: "nope".into(),
            },
            FcpError::TaintViolation {
                origin_zone: "z:work".into(),
                target_zone: "z:private".into(),
                capability: "cap.read".into(),
            },
            FcpError::ElevationRequired {
                capability: "cap.admin".into(),
                ttl_seconds: Some(300),
            },
            FcpError::ElevationRequired {
                capability: "cap.admin".into(),
                ttl_seconds: None,
            },
        ];
        for err in errors {
            let json = serde_json::to_string(&err).unwrap();
            let back: FcpError = serde_json::from_str(&json).unwrap();
            assert_eq!(err.to_string(), back.to_string());
        }
    }

    #[test]
    fn serde_roundtrip_all_connector_variants() {
        let errors = vec![
            FcpError::ConnectorUnavailable {
                code: 5001,
                message: "down".into(),
            },
            FcpError::NotConfigured,
            FcpError::NotHandshaken,
            FcpError::HealthCheckFailed {
                reason: "timeout".into(),
            },
            FcpError::StreamingNotSupported,
            FcpError::configuration_leaked_secret("token", "named_secret_field"),
        ];
        for err in errors {
            let json = serde_json::to_string(&err).unwrap();
            let back: FcpError = serde_json::from_str(&json).unwrap();
            assert_eq!(err.to_string(), back.to_string());
        }
    }

    #[test]
    fn serde_roundtrip_all_resource_variants() {
        let errors = vec![
            FcpError::ResourceNotFound {
                resource: "obj:123".into(),
            },
            FcpError::ResourceExhausted {
                resource: "cpu".into(),
            },
            FcpError::Conflict {
                message: "stale etag".into(),
            },
            FcpError::BudgetExceeded {
                metric: UsageMetricKind::Requests,
                used: 1001,
                limit: 1000,
                window_seconds: 60,
            },
        ];
        for err in errors {
            let json = serde_json::to_string(&err).unwrap();
            let back: FcpError = serde_json::from_str(&json).unwrap();
            assert_eq!(err.to_string(), back.to_string());
        }
    }

    #[test]
    fn serde_roundtrip_all_external_variants() {
        let errors = vec![
            FcpError::External {
                service: "api".into(),
                message: "fail".into(),
                status_code: Some(500),
                retryable: true,
                retry_after: Some(Duration::from_millis(1500)),
            },
            FcpError::External {
                service: "api".into(),
                message: "fail".into(),
                status_code: None,
                retryable: false,
                retry_after: None,
            },
            FcpError::UpstreamTimeout {
                service: "upstream".into(),
            },
            FcpError::DependencyUnavailable {
                service: "dep".into(),
            },
        ];
        for err in errors {
            let json = serde_json::to_string(&err).unwrap();
            let back: FcpError = serde_json::from_str(&json).unwrap();
            assert_eq!(err.to_string(), back.to_string());
        }
    }

    #[test]
    fn serde_roundtrip_internal() {
        let err = FcpError::Internal {
            message: "stack overflow".into(),
        };
        let json = serde_json::to_string(&err).unwrap();
        let back: FcpError = serde_json::from_str(&json).unwrap();
        assert_eq!(err.to_string(), back.to_string());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Numeric code consistency: code is within category range
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn numeric_code_within_category_range_all_variants() {
        let errors: Vec<FcpError> = vec![
            FcpError::InvalidRequest {
                code: 1001,
                message: "x".into(),
            },
            FcpError::MalformedFrame {
                code: 1002,
                message: "x".into(),
            },
            FcpError::MissingField { field: "f".into() },
            FcpError::ChecksumMismatch,
            FcpError::VersionMismatch {
                expected: "1".into(),
                actual: "2".into(),
            },
            FcpError::Unauthorized {
                code: 2001,
                message: "x".into(),
            },
            FcpError::TokenExpired,
            FcpError::InvalidSignature,
            FcpError::CapabilityDenied {
                capability: "c".into(),
                reason: "r".into(),
            },
            FcpError::RateLimited {
                retry_after_ms: 100,
                violation: None,
            },
            FcpError::OperationNotGranted {
                operation: "o".into(),
            },
            FcpError::ResourceNotAllowed {
                resource: "r".into(),
            },
            FcpError::ZoneViolation {
                source_zone: "z:a".into(),
                target_zone: "z:b".into(),
                message: "m".into(),
            },
            FcpError::TaintViolation {
                origin_zone: "z:a".into(),
                target_zone: "z:b".into(),
                capability: "c".into(),
            },
            FcpError::ElevationRequired {
                capability: "c".into(),
                ttl_seconds: None,
            },
            FcpError::ConnectorUnavailable {
                code: 5001,
                message: "x".into(),
            },
            FcpError::NotConfigured,
            FcpError::NotHandshaken,
            FcpError::HealthCheckFailed { reason: "r".into() },
            FcpError::StreamingNotSupported,
            FcpError::ResourceNotFound {
                resource: "r".into(),
            },
            FcpError::ResourceExhausted {
                resource: "r".into(),
            },
            FcpError::BudgetExceeded {
                metric: UsageMetricKind::Tokens,
                used: 1,
                limit: 0,
                window_seconds: 1,
            },
            FcpError::Conflict {
                message: "m".into(),
            },
            FcpError::UpstreamTimeout {
                service: "s".into(),
            },
            FcpError::DependencyUnavailable {
                service: "s".into(),
            },
            FcpError::Internal {
                message: "m".into(),
            },
        ];
        for err in errors {
            let code = err.numeric_code();
            let (lo, hi) = err.category().code_range();
            assert!(
                code >= lo && code <= hi,
                "Error {:?} numeric_code {} outside category range {}-{}",
                err.category(),
                code,
                lo,
                hi,
            );
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // External error code mapping for different HTTP status codes
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn external_error_code_429() {
        let err = FcpError::External {
            service: "s".into(),
            message: "m".into(),
            status_code: Some(429),
            retryable: true,
            retry_after: None,
        };
        assert_eq!(err.numeric_code(), 7001);
        assert_eq!(err.error_code(), "FCP-7001");
    }

    #[test]
    fn external_error_code_504() {
        let err = FcpError::External {
            service: "s".into(),
            message: "m".into(),
            status_code: Some(504),
            retryable: true,
            retry_after: None,
        };
        assert_eq!(err.numeric_code(), 7002);
        assert_eq!(err.error_code(), "FCP-7002");
    }

    #[test]
    fn external_error_code_other_status() {
        let err = FcpError::External {
            service: "s".into(),
            message: "m".into(),
            status_code: Some(500),
            retryable: true,
            retry_after: None,
        };
        assert_eq!(err.numeric_code(), 7003);
        assert_eq!(err.error_code(), "FCP-7003");
    }

    #[test]
    fn external_error_code_none_status() {
        let err = FcpError::External {
            service: "s".into(),
            message: "m".into(),
            status_code: None,
            retryable: false,
            retry_after: None,
        };
        assert_eq!(err.numeric_code(), 7003);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Details tests for variants with/without details
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    #[allow(clippy::too_many_lines)]
    fn details_none_for_simple_variants() {
        assert!(FcpError::ChecksumMismatch.details().is_none());
        assert!(FcpError::TokenExpired.details().is_none());
        assert!(FcpError::InvalidSignature.details().is_none());
        assert!(FcpError::NotConfigured.details().is_none());
        assert!(FcpError::NotHandshaken.details().is_none());
        assert!(FcpError::StreamingNotSupported.details().is_none());
        assert!(
            FcpError::Internal {
                message: "x".into()
            }
            .details()
            .is_none()
        );
        assert!(
            FcpError::UpstreamTimeout {
                service: "s".into()
            }
            .details()
            .is_none()
        );
        assert!(
            FcpError::DependencyUnavailable {
                service: "s".into()
            }
            .details()
            .is_none()
        );
        assert!(
            FcpError::ResourceNotFound {
                resource: "r".into()
            }
            .details()
            .is_none()
        );
        assert!(
            FcpError::ResourceExhausted {
                resource: "r".into()
            }
            .details()
            .is_none()
        );
        assert!(
            FcpError::Conflict {
                message: "m".into()
            }
            .details()
            .is_none()
        );
        assert!(
            FcpError::InvalidRequest {
                code: 1001,
                message: "x".into()
            }
            .details()
            .is_none()
        );
        assert!(
            FcpError::MalformedFrame {
                code: 1002,
                message: "x".into()
            }
            .details()
            .is_none()
        );
        assert!(
            FcpError::Unauthorized {
                code: 2001,
                message: "x".into()
            }
            .details()
            .is_none()
        );
        assert!(
            FcpError::MissingField { field: "f".into() }
                .details()
                .is_none()
        );
        assert!(
            FcpError::OperationNotGranted {
                operation: "o".into()
            }
            .details()
            .is_none()
        );
        assert!(
            FcpError::ResourceNotAllowed {
                resource: "r".into()
            }
            .details()
            .is_none()
        );
        assert!(
            FcpError::HealthCheckFailed { reason: "r".into() }
                .details()
                .is_none()
        );
        assert!(
            FcpError::ConnectorUnavailable {
                code: 5001,
                message: "x".into()
            }
            .details()
            .is_none()
        );
        assert!(
            FcpError::VersionMismatch {
                expected: "1".into(),
                actual: "2".into()
            }
            .details()
            .is_none()
        );
    }

    #[test]
    fn details_present_capability_denied() {
        let err = FcpError::CapabilityDenied {
            capability: "cap.exec".into(),
            reason: "policy violation".into(),
        };
        let details = err.details().unwrap();
        assert_eq!(details["capability"], "cap.exec");
        assert_eq!(details["reason"], "policy violation");
    }

    #[test]
    fn details_configuration_leaked_secret_are_redaction_safe() {
        let err = FcpError::configuration_leaked_secret("token", "named_secret_field");
        let details = err.details().unwrap();

        assert_eq!(
            details["field_name_hash"],
            "3c469e9d6c5875d37a43f353d4f88e61fcf812c66eee3457465a40b0da4153e0"
        );
        assert_eq!(details["detector"], "named_secret_field");
        assert!(!details.to_string().contains("token"));
        assert_eq!(err.error_code(), "FCP-5006");
        assert!(!err.is_retryable());
    }

    #[test]
    fn details_rate_limited_no_violation() {
        let err = FcpError::RateLimited {
            retry_after_ms: 1000,
            violation: None,
        };
        assert!(err.details().is_none());
    }

    #[test]
    fn details_rate_limited_with_violation() {
        let violation = crate::ThrottleViolation {
            violation_id: crate::ObjectId::from_bytes([2; 32]),
            timestamp_ms: 2000,
            zone_id: crate::ZoneId::owner(),
            connector_id: None,
            operation_id: None,
            limit_type: crate::ratelimit::LimitType::Burst,
            limit_value: 50,
            current_value: 75,
            retry_after_ms: 3000,
        };
        let err = FcpError::RateLimited {
            retry_after_ms: 3000,
            violation: Some(Box::new(violation)),
        };
        let details = err.details().unwrap();
        assert!(details["throttle_violation"].is_object());
    }

    #[test]
    fn details_budget_exceeded_fields() {
        let err = FcpError::BudgetExceeded {
            metric: UsageMetricKind::DurationMs,
            used: 5000,
            limit: 3000,
            window_seconds: 300,
        };
        let details = err.details().unwrap();
        assert_eq!(details["used"], 5000);
        assert_eq!(details["limit"], 3000);
        assert_eq!(details["window_seconds"], 300);
    }

    #[test]
    fn details_zone_violation_fields() {
        let err = FcpError::ZoneViolation {
            source_zone: "z:community".into(),
            target_zone: "z:owner".into(),
            message: "denied".into(),
        };
        let details = err.details().unwrap();
        assert_eq!(details["source_zone"], "z:community");
        assert_eq!(details["target_zone"], "z:owner");
    }

    #[test]
    fn details_taint_violation_fields() {
        let err = FcpError::TaintViolation {
            origin_zone: "z:public".into(),
            target_zone: "z:private".into(),
            capability: "cap.sensitive".into(),
        };
        let details = err.details().unwrap();
        assert_eq!(details["origin_zone"], "z:public");
        assert_eq!(details["target_zone"], "z:private");
        assert_eq!(details["capability"], "cap.sensitive");
    }

    #[test]
    fn details_elevation_required_with_ttl() {
        let err = FcpError::ElevationRequired {
            capability: "cap.destroy".into(),
            ttl_seconds: Some(600),
        };
        let details = err.details().unwrap();
        assert_eq!(details["capability"], "cap.destroy");
        assert_eq!(details["ttl_seconds"], 600);
    }

    #[test]
    fn details_elevation_required_without_ttl() {
        let err = FcpError::ElevationRequired {
            capability: "cap.nuke".into(),
            ttl_seconds: None,
        };
        let details = err.details().unwrap();
        assert_eq!(details["capability"], "cap.nuke");
        assert!(details["ttl_seconds"].is_null());
    }

    #[test]
    fn details_external_with_status_code() {
        let err = FcpError::External {
            service: "payment-gateway".into(),
            message: "declined".into(),
            status_code: Some(422),
            retryable: false,
            retry_after: None,
        };
        let details = err.details().unwrap();
        assert_eq!(details["service"], "payment-gateway");
        assert_eq!(details["status_code"], 422);
    }

    #[test]
    fn details_external_without_status_code() {
        let err = FcpError::External {
            service: "dns".into(),
            message: "resolution failed".into(),
            status_code: None,
            retryable: false,
            retry_after: None,
        };
        let details = err.details().unwrap();
        assert_eq!(details["service"], "dns");
        assert!(details["status_code"].is_null());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Error response hint content tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn hint_elevation_required_with_ttl_mentions_seconds() {
        let err = FcpError::ElevationRequired {
            capability: "cap.admin".into(),
            ttl_seconds: Some(7200),
        };
        let hint = err.to_response().ai_recovery_hint.unwrap();
        assert!(hint.contains("7200"));
    }

    #[test]
    fn hint_elevation_required_without_ttl_no_seconds() {
        let err = FcpError::ElevationRequired {
            capability: "cap.admin".into(),
            ttl_seconds: None,
        };
        let hint = err.to_response().ai_recovery_hint.unwrap();
        assert!(!hint.contains("valid for"));
    }

    #[test]
    fn hint_external_retryable_mentions_retry() {
        let err = FcpError::External {
            service: "api".into(),
            message: "error".into(),
            status_code: Some(503),
            retryable: true,
            retry_after: None,
        };
        let hint = err.to_response().ai_recovery_hint.unwrap();
        assert!(hint.contains("retryable"));
    }

    #[test]
    fn hint_external_non_retryable_mentions_non_retryable() {
        let err = FcpError::External {
            service: "api".into(),
            message: "error".into(),
            status_code: Some(400),
            retryable: false,
            retry_after: None,
        };
        let hint = err.to_response().ai_recovery_hint.unwrap();
        assert!(hint.contains("non-retryable"));
    }

    #[test]
    fn hint_external_with_unknown_status() {
        let err = FcpError::External {
            service: "api".into(),
            message: "error".into(),
            status_code: None,
            retryable: false,
            retry_after: None,
        };
        let hint = err.to_response().ai_recovery_hint.unwrap();
        assert!(hint.contains("unknown"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ErrorCategory serde rename_all snake_case
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn error_category_serde_snake_case_format() {
        let json = serde_json::to_string(&ErrorCategory::External).unwrap();
        assert_eq!(json, "\"external\"");
        let json = serde_json::to_string(&ErrorCategory::Protocol).unwrap();
        assert_eq!(json, "\"protocol\"");
        let json = serde_json::to_string(&ErrorCategory::Auth).unwrap();
        assert_eq!(json, "\"auth\"");
        let json = serde_json::to_string(&ErrorCategory::Internal).unwrap();
        assert_eq!(json, "\"internal\"");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // FcpError as std::error::Error (dyn dispatch)
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn fcp_error_dyn_error_display() {
        let err: Box<dyn std::error::Error> = Box::new(FcpError::ChecksumMismatch);
        assert_eq!(err.to_string(), "Checksum mismatch");
    }

    #[test]
    fn fcp_error_dyn_error_downcast() {
        let err: Box<dyn std::error::Error> = Box::new(FcpError::TokenExpired);
        assert!(err.downcast_ref::<FcpError>().is_some());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // FcpErrorResponse serde edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn error_response_with_details_roundtrip() {
        let resp = FcpErrorResponse {
            code: "FCP-3001".into(),
            message: "Capability denied".into(),
            retryable: false,
            retry_after_ms: None,
            details: Some(serde_json::json!({
                "capability": "cap.write",
                "reason": "no grant"
            })),
            ai_recovery_hint: Some("request grant".into()),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: FcpErrorResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back.code, "FCP-3001");
        assert_eq!(back.details.unwrap()["capability"], "cap.write");
    }

    #[test]
    fn error_response_clone_with_details() {
        let resp = FcpErrorResponse {
            code: "FCP-6004".into(),
            message: "Budget exceeded".into(),
            retryable: true,
            retry_after_ms: Some(60000),
            details: Some(serde_json::json!({"metric": "tokens"})),
            ai_recovery_hint: Some("wait".into()),
        };
        let cloned = resp.clone();
        assert_eq!(resp.code, cloned.code);
        assert_eq!(resp.retryable, cloned.retryable);
        assert_eq!(resp.retry_after_ms, cloned.retry_after_ms);
        assert_eq!(resp.message, cloned.message);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Boundary / edge case tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn rate_limited_zero_retry_after() {
        let err = FcpError::RateLimited {
            retry_after_ms: 0,
            violation: None,
        };
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(Duration::from_millis(0)));
        let resp = err.to_response();
        assert_eq!(resp.retry_after_ms, Some(0));
    }

    #[test]
    fn rate_limited_max_retry_after() {
        let err = FcpError::RateLimited {
            retry_after_ms: u64::MAX,
            violation: None,
        };
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(Duration::from_millis(u64::MAX)));
    }

    #[test]
    fn budget_exceeded_zero_window() {
        let err = FcpError::BudgetExceeded {
            metric: UsageMetricKind::Custom,
            used: 0,
            limit: 0,
            window_seconds: 0,
        };
        assert!(err.is_retryable());
        let msg = err.to_string();
        assert!(msg.contains('0'));
    }

    #[test]
    fn empty_string_fields() {
        let err = FcpError::Internal {
            message: String::new(),
        };
        assert_eq!(err.to_string(), "Internal error: ");

        let err = FcpError::ResourceNotFound {
            resource: String::new(),
        };
        assert_eq!(err.to_string(), "Resource not found: ");

        let err = FcpError::MissingField {
            field: String::new(),
        };
        assert_eq!(err.to_string(), "Missing required field: ");
    }

    #[test]
    fn error_code_format_with_custom_codes() {
        let err = FcpError::InvalidRequest {
            code: 1099,
            message: "custom".into(),
        };
        assert_eq!(err.error_code(), "FCP-1099");

        let err = FcpError::ConnectorUnavailable {
            code: 5999,
            message: "edge".into(),
        };
        assert_eq!(err.error_code(), "FCP-5999");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ErrorCategory equality and hash coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn error_category_all_distinct_hashes() {
        use std::collections::HashSet;
        let categories = [
            ErrorCategory::Protocol,
            ErrorCategory::Auth,
            ErrorCategory::Capability,
            ErrorCategory::Zone,
            ErrorCategory::Connector,
            ErrorCategory::Resource,
            ErrorCategory::External,
            ErrorCategory::Internal,
        ];
        let set: HashSet<ErrorCategory> = categories.iter().copied().collect();
        assert_eq!(set.len(), 8);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Retryable exhaustive coverage for non-retryable variants
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn not_retryable_all_non_retryable_variants() {
        let non_retryable = vec![
            FcpError::InvalidRequest {
                code: 1001,
                message: "x".into(),
            },
            FcpError::MalformedFrame {
                code: 1002,
                message: "x".into(),
            },
            FcpError::MissingField { field: "f".into() },
            FcpError::ChecksumMismatch,
            FcpError::VersionMismatch {
                expected: "1".into(),
                actual: "2".into(),
            },
            FcpError::Unauthorized {
                code: 2001,
                message: "x".into(),
            },
            FcpError::TokenExpired,
            FcpError::InvalidSignature,
            FcpError::CapabilityDenied {
                capability: "c".into(),
                reason: "r".into(),
            },
            FcpError::OperationNotGranted {
                operation: "o".into(),
            },
            FcpError::ResourceNotAllowed {
                resource: "r".into(),
            },
            FcpError::ZoneViolation {
                source_zone: "z:a".into(),
                target_zone: "z:b".into(),
                message: "m".into(),
            },
            FcpError::TaintViolation {
                origin_zone: "z:a".into(),
                target_zone: "z:b".into(),
                capability: "c".into(),
            },
            FcpError::ElevationRequired {
                capability: "c".into(),
                ttl_seconds: None,
            },
            FcpError::NotConfigured,
            FcpError::NotHandshaken,
            FcpError::HealthCheckFailed { reason: "r".into() },
            FcpError::StreamingNotSupported,
            FcpError::ResourceNotFound {
                resource: "r".into(),
            },
            FcpError::Conflict {
                message: "m".into(),
            },
            FcpError::Internal {
                message: "m".into(),
            },
        ];
        for err in non_retryable {
            assert!(
                !err.is_retryable(),
                "Expected non-retryable but got retryable: {err}"
            );
        }
    }

    #[test]
    fn retryable_all_retryable_variants() {
        let retryable = vec![
            FcpError::RateLimited {
                retry_after_ms: 100,
                violation: None,
            },
            FcpError::ResourceExhausted {
                resource: "mem".into(),
            },
            FcpError::BudgetExceeded {
                metric: UsageMetricKind::Tokens,
                used: 1,
                limit: 0,
                window_seconds: 1,
            },
            FcpError::UpstreamTimeout {
                service: "s".into(),
            },
            FcpError::DependencyUnavailable {
                service: "s".into(),
            },
            FcpError::ConnectorUnavailable {
                code: 5001,
                message: "x".into(),
            },
            FcpError::External {
                service: "s".into(),
                message: "m".into(),
                status_code: None,
                retryable: true,
                retry_after: None,
            },
        ];
        for err in retryable {
            assert!(
                err.is_retryable(),
                "Expected retryable but got non-retryable: {err}"
            );
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // retry_after returns None for most variants
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn retry_after_none_for_most_variants() {
        assert!(FcpError::ChecksumMismatch.retry_after().is_none());
        assert!(FcpError::TokenExpired.retry_after().is_none());
        assert!(FcpError::NotConfigured.retry_after().is_none());
        assert!(
            FcpError::Internal {
                message: "x".into()
            }
            .retry_after()
            .is_none()
        );
        assert!(
            FcpError::UpstreamTimeout {
                service: "s".into()
            }
            .retry_after()
            .is_none()
        );
        assert!(
            FcpError::ConnectorUnavailable {
                code: 5001,
                message: "x".into()
            }
            .retry_after()
            .is_none()
        );
        assert!(
            FcpError::ResourceExhausted {
                resource: "x".into()
            }
            .retry_after()
            .is_none()
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // FcpError tagged serde: ensure `category` tag present
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn serde_tagged_category_field_present() {
        let err = FcpError::TokenExpired;
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("\"category\""));
        assert!(json.contains("\"TokenExpired\""));
    }

    #[test]
    fn serde_tagged_external_has_all_fields() {
        let err = FcpError::External {
            service: "svc".into(),
            message: "msg".into(),
            status_code: Some(502),
            retryable: true,
            retry_after: Some(Duration::from_secs(5)),
        };
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("\"category\":\"External\""));
        assert!(json.contains("\"service\":\"svc\""));
        assert!(json.contains("\"status_code\":502"));
        assert!(json.contains("\"retryable\":true"));
        // retry_after serialized as millis
        assert!(json.contains("\"retry_after\":5000"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // FcpResult type alias
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn fcp_result_type_alias_works() {
        // Verify FcpResult is a proper Result alias
        let ok_val: FcpResult<u32> = Ok(42);
        let err_val: FcpResult<u32> = Err(FcpError::NotConfigured);
        assert!(ok_val.is_ok());
        assert!(err_val.is_err());
        // Verify the error variant carries the right message
        if let Err(e) = err_val {
            assert_eq!(e.to_string(), "Connector not configured");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // to_response consistency: message matches Display
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    #[allow(clippy::too_many_lines)]
    fn to_response_message_matches_display_all_variants() {
        let errors: Vec<FcpError> = vec![
            FcpError::InvalidRequest {
                code: 1001,
                message: "test".into(),
            },
            FcpError::MalformedFrame {
                code: 1002,
                message: "frame".into(),
            },
            FcpError::MissingField {
                field: "zone".into(),
            },
            FcpError::ChecksumMismatch,
            FcpError::VersionMismatch {
                expected: "a".into(),
                actual: "b".into(),
            },
            FcpError::Unauthorized {
                code: 2001,
                message: "nope".into(),
            },
            FcpError::TokenExpired,
            FcpError::InvalidSignature,
            FcpError::CapabilityDenied {
                capability: "c".into(),
                reason: "r".into(),
            },
            FcpError::RateLimited {
                retry_after_ms: 100,
                violation: None,
            },
            FcpError::OperationNotGranted {
                operation: "o".into(),
            },
            FcpError::ResourceNotAllowed {
                resource: "r".into(),
            },
            FcpError::ZoneViolation {
                source_zone: "z:a".into(),
                target_zone: "z:b".into(),
                message: "m".into(),
            },
            FcpError::TaintViolation {
                origin_zone: "z:a".into(),
                target_zone: "z:b".into(),
                capability: "c".into(),
            },
            FcpError::ElevationRequired {
                capability: "c".into(),
                ttl_seconds: None,
            },
            FcpError::ConnectorUnavailable {
                code: 5001,
                message: "down".into(),
            },
            FcpError::NotConfigured,
            FcpError::NotHandshaken,
            FcpError::HealthCheckFailed {
                reason: "fail".into(),
            },
            FcpError::StreamingNotSupported,
            FcpError::ResourceNotFound {
                resource: "r".into(),
            },
            FcpError::ResourceExhausted {
                resource: "r".into(),
            },
            FcpError::BudgetExceeded {
                metric: UsageMetricKind::Tokens,
                used: 1,
                limit: 0,
                window_seconds: 1,
            },
            FcpError::Conflict {
                message: "conflict".into(),
            },
            FcpError::External {
                service: "s".into(),
                message: "m".into(),
                status_code: None,
                retryable: false,
                retry_after: None,
            },
            FcpError::UpstreamTimeout {
                service: "s".into(),
            },
            FcpError::DependencyUnavailable {
                service: "s".into(),
            },
            FcpError::Internal {
                message: "m".into(),
            },
        ];
        for err in errors {
            let resp = err.to_response();
            assert_eq!(
                resp.message,
                err.to_string(),
                "Response message should match Display for {:?}",
                err.category()
            );
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // m8j0q.A.3 — CapabilityConstraintErrorKind variant matrix + denial taxonomy
    //
    // These tests pin the wire-format serde shape, the Display / explanation
    // text per kind, and the non-retryability invariant (security denials
    // MUST NEVER retry). Adding a new kind requires extending all five
    // matrix loops below — a refactor that adds a variant but forgets to
    // wire it up to one of these checks fails compile or test before it
    // can ship.
    // ─────────────────────────────────────────────────────────────────────────

    fn denial(kind: CapabilityConstraintErrorKind) -> FcpError {
        FcpError::CapabilityConstraintDenied {
            kind,
            claim_type: "host_allowlist".into(),
            detail: "host=evil.example.com".into(),
        }
    }

    #[test]
    fn constraint_kind_all_returns_every_variant_in_declaration_order() {
        let all = CapabilityConstraintErrorKind::all();
        // Length lock: extending the enum without updating the matrix
        // tests is a compile-time slip that this assert catches.
        assert_eq!(all.len(), 5);
        assert_eq!(
            all,
            [
                CapabilityConstraintErrorKind::ExactMismatch,
                CapabilityConstraintErrorKind::OutOfRange,
                CapabilityConstraintErrorKind::UnsupportedClaimType,
                CapabilityConstraintErrorKind::MissingMandatoryConstraint,
                CapabilityConstraintErrorKind::ConstraintParseError,
            ]
        );
    }

    #[test]
    fn constraint_kind_as_str_matches_serde_snake_case() {
        // The wire format MUST be snake_case of the variant name; audit
        // consumers and replay tools key off these literals.
        assert_eq!(
            CapabilityConstraintErrorKind::ExactMismatch.as_str(),
            "exact_mismatch"
        );
        assert_eq!(
            CapabilityConstraintErrorKind::OutOfRange.as_str(),
            "out_of_range"
        );
        assert_eq!(
            CapabilityConstraintErrorKind::UnsupportedClaimType.as_str(),
            "unsupported_claim_type"
        );
        assert_eq!(
            CapabilityConstraintErrorKind::MissingMandatoryConstraint.as_str(),
            "missing_mandatory_constraint"
        );
        assert_eq!(
            CapabilityConstraintErrorKind::ConstraintParseError.as_str(),
            "constraint_parse_error"
        );
    }

    #[test]
    fn constraint_kind_display_matches_as_str() {
        for kind in CapabilityConstraintErrorKind::all() {
            assert_eq!(format!("{kind}"), kind.as_str());
        }
    }

    #[test]
    fn constraint_kind_serde_round_trip_per_variant() {
        // Conformance vector: every kind round-trips through JSON
        // byte-equivalent. This pins the wire format.
        for kind in CapabilityConstraintErrorKind::all() {
            let json = serde_json::to_string(&kind).expect("serialize");
            assert_eq!(
                json,
                format!("\"{}\"", kind.as_str()),
                "JSON shape MUST be the snake_case literal for {kind}"
            );
            let back: CapabilityConstraintErrorKind =
                serde_json::from_str(&json).expect("deserialize");
            assert_eq!(back, kind);
        }
    }

    #[test]
    fn constraint_kind_explanation_is_non_empty_per_variant() {
        // Every kind MUST carry an operator-readable explanation —
        // operators reading audit logs deserve a one-line description
        // without dumping the full CWT claim back.
        for kind in CapabilityConstraintErrorKind::all() {
            let explanation = kind.explanation();
            assert!(
                !explanation.is_empty(),
                "explanation must be non-empty for {kind}"
            );
            // No kind's explanation should accidentally collide with
            // another kind's explanation (would mask which check failed).
            for other in CapabilityConstraintErrorKind::all() {
                if other != kind {
                    assert_ne!(
                        explanation,
                        other.explanation(),
                        "explanations MUST be distinct: {kind} collides with {other}"
                    );
                }
            }
        }
    }

    #[test]
    fn constraint_denied_display_includes_kind_claim_and_detail() {
        let err = denial(CapabilityConstraintErrorKind::ExactMismatch);
        let display = err.to_string();
        assert!(display.contains("exact_mismatch"), "got: {display}");
        assert!(display.contains("host_allowlist"), "got: {display}");
        assert!(display.contains("evil.example.com"), "got: {display}");
    }

    #[test]
    fn constraint_denied_categorizes_as_capability() {
        for kind in CapabilityConstraintErrorKind::all() {
            assert_eq!(denial(kind).category(), ErrorCategory::Capability);
        }
    }

    #[test]
    fn constraint_denied_uses_fcp_3005_error_code() {
        for kind in CapabilityConstraintErrorKind::all() {
            assert_eq!(denial(kind).numeric_code(), 3005);
            assert_eq!(denial(kind).error_code(), "FCP-3005");
        }
    }

    #[test]
    fn constraint_denied_is_never_retryable() {
        // Security denials MUST NEVER retry. A bug that flips this to
        // true would let a denied request be silently re-issued by a
        // retry loop — exactly the failure mode capability constraints
        // exist to prevent.
        for kind in CapabilityConstraintErrorKind::all() {
            let err = denial(kind);
            assert!(
                !err.is_retryable(),
                "CapabilityConstraintDenied with kind {kind} MUST NOT be retryable"
            );
            assert_eq!(
                err.retry_after(),
                None,
                "non-retryable error MUST have no retry_after for kind {kind}"
            );
        }
    }

    #[test]
    fn constraint_denied_to_response_carries_fcp_3005_and_kind_in_ai_hint() {
        for kind in CapabilityConstraintErrorKind::all() {
            let response = denial(kind).to_response();
            assert_eq!(response.code, "FCP-3005", "wrong code for {kind}");
            let hint = response
                .ai_recovery_hint
                .as_deref()
                .unwrap_or_else(|| panic!("missing ai_hint for {kind}"));
            assert!(
                hint.contains(kind.as_str()),
                "ai_hint must mention kind label for {kind}: got {hint}"
            );
            assert!(
                hint.contains("non-retryable"),
                "ai_hint must signal non-retryability for {kind}: got {hint}"
            );
        }
    }

    #[test]
    fn constraint_denied_detail_json_includes_kind_field() {
        // Wire-format pin: the per-error detail JSON MUST surface the
        // kind in the `kind` key (not the legacy `reason` key).
        for kind in CapabilityConstraintErrorKind::all() {
            let err = denial(kind);
            let detail = err.details().expect("details populated");
            assert_eq!(
                detail.get("kind").and_then(|v| v.as_str()),
                Some(kind.as_str()),
                "detail_json kind field for {kind}"
            );
            assert_eq!(
                detail.get("claim_type").and_then(|v| v.as_str()),
                Some("host_allowlist")
            );
            assert_eq!(
                detail.get("detail").and_then(|v| v.as_str()),
                Some("host=evil.example.com")
            );
        }
    }

    #[test]
    fn constraint_denied_round_trips_through_serde_per_kind() {
        // Whole-error serde round-trip — pins the FcpError variant tag
        // shape AND the nested kind enum together, so a refactor that
        // breaks either layer trips this test.
        for kind in CapabilityConstraintErrorKind::all() {
            let err = denial(kind);
            let json = serde_json::to_string(&err).expect("serialize");
            let back: FcpError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(back.to_string(), err.to_string());
            // Discriminant survives the round-trip.
            match back {
                FcpError::CapabilityConstraintDenied {
                    kind: round_tripped_kind,
                    ..
                } => assert_eq!(round_tripped_kind, kind),
                other => panic!("variant changed across serde for {kind}: {other:?}"),
            }
        }
    }
}
