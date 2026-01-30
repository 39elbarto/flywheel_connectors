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
            Some(d) => serializer.serialize_some(&d.as_millis()),
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

impl FcpError {
    /// Returns the error category for classification.
    #[must_use]
    pub const fn category(&self) -> ErrorCategory {
        match self {
            Self::InvalidRequest { .. }
            | Self::MalformedFrame { .. }
            | Self::ChecksumMismatch
            | Self::VersionMismatch { .. }
            | Self::MissingField { .. } => ErrorCategory::Protocol,

            Self::Unauthorized { .. } | Self::TokenExpired | Self::InvalidSignature => {
                ErrorCategory::Auth
            }

            Self::CapabilityDenied { .. }
            | Self::RateLimited { .. }
            | Self::OperationNotGranted { .. }
            | Self::ResourceNotAllowed { .. } => ErrorCategory::Capability,

            Self::ZoneViolation { .. }
            | Self::TaintViolation { .. }
            | Self::ElevationRequired { .. } => ErrorCategory::Zone,

            Self::ConnectorUnavailable { .. }
            | Self::NotConfigured
            | Self::NotHandshaken
            | Self::HealthCheckFailed { .. }
            | Self::StreamingNotSupported => ErrorCategory::Connector,

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
            Self::InvalidSignature => 2003,

            Self::CapabilityDenied { .. } => 3001,
            Self::RateLimited { .. } => 3002,
            Self::OperationNotGranted { .. } => 3003,
            Self::ResourceNotAllowed { .. } => 3004,

            Self::ZoneViolation { .. } => 4001,
            Self::TaintViolation { .. } => 4002,
            Self::ElevationRequired { .. } => 4003,

            Self::NotConfigured => 5002,
            Self::NotHandshaken => 5003,
            Self::HealthCheckFailed { .. } => 5004,
            Self::StreamingNotSupported => 5005,

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
}
