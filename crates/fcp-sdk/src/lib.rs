//! FCP2 Connector SDK
//!
//! This crate provides the SDK for authoring FCP2-compliant connectors.
//! It re-exports key types from `fcp-core` and provides convenience utilities
//! to make implementing connectors easy and correct.
//!
//! # Quick Start
//!
//! ```ignore
//! use fcp_sdk::prelude::*;
//!
//! #[derive(Debug)]
//! struct MyConnector {
//!     base: BaseConnector,
//! }
//!
//! #[async_trait]
//! impl FcpConnector for MyConnector {
//!     fn id(&self) -> &ConnectorId {
//!         &self.base.id
//!     }
//!
//!     async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
//!         // Configure your connector
//!         self.base.set_configured(true);
//!         Ok(())
//!     }
//!
//!     // ... implement other methods
//! }
//! ```
//!
//! # Architecture
//!
//! The SDK is structured around:
//!
//! - **[`FcpConnector`]**: The core trait all connectors must implement
//! - **[`BaseConnector`]**: A base implementation with common functionality
//! - **[`FcpError`]**: Structured error types with recovery hints
//! - **Archetype traits**: [`Streaming`], [`Bidirectional`], [`Polling`], [`Webhook`]
//!
//! # Error Handling
//!
//! All errors use the FCP error taxonomy:
//!
//! | Code Range | Category |
//! |------------|----------|
//! | FCP-1xxx | Protocol errors |
//! | FCP-2xxx | Auth/Identity errors |
//! | FCP-3xxx | Capability errors |
//! | FCP-4xxx | Zone/Topology errors |
//! | FCP-5xxx | Connector errors |
//! | FCP-6xxx | Resource errors |
//! | FCP-7xxx | External service errors |
//! | FCP-9xxx | Internal errors |

#![forbid(unsafe_code)]
#![warn(missing_docs)]

// ─────────────────────────────────────────────────────────────────────────────
// Re-exports from fcp-core
// ─────────────────────────────────────────────────────────────────────────────

/// Core connector trait and base implementation.
pub use fcp_core::{
    BaseConnector,
    Bidirectional,
    // Capability tokens
    CapabilityGrant,
    CapabilityToken,

    // Identifiers
    ConnectorId,
    ConnectorMetrics,
    CorrelationId,
    // Cost and availability
    CostEstimate,
    CostEstimateConfidence,
    CurrencyCost,
    CursorState,
    // Error types
    ErrorCategory,
    // Events
    EventAck,
    EventCaps,
    EventData,
    EventEnvelope,
    EventNack,
    EventStream,
    FcpConnector,
    FcpError,
    FcpErrorResponse,
    FcpResult,

    // Protocol messages
    HandshakeRequest,
    HandshakeResponse,
    // Health and metrics
    HealthSnapshot,
    HealthState,
    InstanceId,
    Introspection,
    InvokeContext,
    InvokeRequest,
    InvokeResponse,
    InvokeStatus,
    LivenessResponse,
    ObjectId,
    OperationId,
    Polling,
    Principal,
    // Provenance
    Provenance,
    ProvenanceStep,
    RateLimitConfig,
    RateLimitDeclarations,
    RateLimitEnforcement,
    RateLimitPool,
    RateLimitScope,
    RateLimitStatus,
    RateLimitUnit,
    ReadinessResponse,
    ReplayBufferInfo,
    RequestId,
    RequestResponse,
    ResourceAvailability,
    SelfCheckReport,
    SelfCheckStatus,
    SessionId,
    ShutdownAck,
    ShutdownRequest,
    SimulateRequest,
    SimulateResponse,
    Streaming,
    SubscribeRequest,
    SubscribeResponse,
    SubscribeResult,
    TaintFlag,
    TaintLevel,
    ThreadInfo,
    ThreadKind,
    // Observability
    TraceContext,
    TrustLevel,
    UnsubscribeRequest,
    UsageMetric,
    UsageMetricKind,
    Webhook,
    ZoneId,

    // Core connector infrastructure
    async_trait,
};

/// Re-exports from fcp-manifest for connector configuration.
pub use fcp_manifest::{
    ConnectorArchetype, ConnectorCrdtType, ConnectorRuntimeFormat, ConnectorStateModel,
};

// ─────────────────────────────────────────────────────────────────────────────
// SDK-specific modules
// ─────────────────────────────────────────────────────────────────────────────

pub mod formatting;
pub mod prelude;
pub mod ratelimit;
pub mod retry;
pub mod runtime;
pub mod streaming;

/// Formatting helpers with safe fallback behavior.
pub use formatting::{
    ErrorClass, FormatError, FormatMode, Formatter, RenderResult, classify_error_message,
    is_parse_error_message,
};

/// Retry policy helpers.
pub use retry::{RetryDecision, RetryPolicy};

// ─────────────────────────────────────────────────────────────────────────────
// Schema validation helpers
// ─────────────────────────────────────────────────────────────────────────────

/// JSON Schema validation errors produced by the SDK.
#[derive(Debug, Clone, thiserror::Error)]
pub enum SchemaValidationError {
    /// The provided schema is invalid and could not be compiled.
    #[error("invalid JSON Schema: {message}")]
    InvalidSchema {
        /// Human-readable error message.
        message: String,
    },

    /// The value failed schema validation.
    #[error("schema validation failed: {message}")]
    ValidationFailed {
        /// Human-readable summary message.
        message: String,
        /// Individual validation errors (formatted strings).
        errors: Vec<String>,
    },
}

/// Compiled JSON Schema validator for repeated use.
#[derive(Debug, Clone)]
pub struct SchemaValidator {
    validator: std::sync::Arc<jsonschema::Validator>,
}

impl SchemaValidator {
    /// Compile a JSON Schema into a reusable validator.
    ///
    /// # Errors
    /// Returns [`SchemaValidationError::InvalidSchema`] if the schema is invalid.
    pub fn compile(schema: &serde_json::Value) -> Result<Self, SchemaValidationError> {
        let validator = jsonschema::Validator::new(schema).map_err(|e| {
            SchemaValidationError::InvalidSchema {
                message: e.to_string(),
            }
        })?;
        Ok(Self {
            validator: std::sync::Arc::new(validator),
        })
    }

    /// Validate a JSON value against the compiled schema.
    ///
    /// # Errors
    /// Returns [`SchemaValidationError::ValidationFailed`] if validation fails.
    pub fn validate(&self, value: &serde_json::Value) -> Result<(), SchemaValidationError> {
        let details: Vec<String> = self
            .validator
            .iter_errors(value)
            .map(|error| {
                let path = error.instance_path.to_string();
                let message = error.masked().to_string();
                if path.is_empty() {
                    message
                } else {
                    format!("{path}: {message}")
                }
            })
            .collect();

        if details.is_empty() {
            Ok(())
        } else {
            let message = details.join("; ");
            Err(SchemaValidationError::ValidationFailed {
                message,
                errors: details,
            })
        }
    }
}

/// Compile and validate a JSON value against a JSON Schema in one step.
///
/// # Errors
/// Returns [`SchemaValidationError`] if the schema is invalid or validation fails.
pub fn validate_json_schema(
    schema: &serde_json::Value,
    value: &serde_json::Value,
) -> Result<(), SchemaValidationError> {
    SchemaValidator::compile(schema)?.validate(value)
}

const INVALID_REQUEST_SCHEMA_CODE: u16 = 1001;
const INVALID_REQUEST_LIMITS_CODE: u16 = 1004;
const MAX_SCHEMA_ERRORS: usize = 5;

fn format_schema_errors(errors: &[String]) -> String {
    if errors.is_empty() {
        return "schema validation failed".to_string();
    }

    let mut message = errors
        .iter()
        .take(MAX_SCHEMA_ERRORS)
        .cloned()
        .collect::<Vec<_>>()
        .join("; ");

    if errors.len() > MAX_SCHEMA_ERRORS {
        use std::fmt::Write;

        let _ = write!(
            message,
            "; +{} more",
            errors.len().saturating_sub(MAX_SCHEMA_ERRORS)
        );
    }

    message
}

/// Validate input payloads against a JSON Schema and map failures to `FcpError::InvalidRequest`.
///
/// # Errors
/// Returns `FcpError::InvalidRequest` when the input value does not match the schema, or
/// `FcpError::Internal` if the schema itself is invalid.
pub fn validate_input(
    schema: &serde_json::Value,
    value: &serde_json::Value,
) -> Result<(), FcpError> {
    validate_input_with_limits(schema, value, &Limits::default())
}

/// Validate output payloads against a JSON Schema and map failures to `FcpError::Internal`.
///
/// # Errors
/// Returns `FcpError::Internal` when the output value does not match the schema or the schema is
/// invalid.
pub fn validate_output(
    schema: &serde_json::Value,
    value: &serde_json::Value,
) -> Result<(), FcpError> {
    validate_output_with_limits(schema, value, &Limits::default())
}

/// Validate input payloads against limits and a JSON Schema.
///
/// # Errors
/// Returns `FcpError::InvalidRequest` when the input value does not match the schema or violates
/// limits, or `FcpError::Internal` if the schema itself is invalid.
pub fn validate_input_with_limits(
    schema: &serde_json::Value,
    value: &serde_json::Value,
    limits: &Limits,
) -> Result<(), FcpError> {
    match validate_limits(value, limits) {
        Ok(()) => {}
        Err(LimitCheckError::Serialization(message)) => {
            return Err(FcpError::Internal {
                message: format!("failed to measure payload size: {message}"),
            });
        }
        Err(LimitCheckError::Violation(violation)) => {
            return Err(FcpError::InvalidRequest {
                code: INVALID_REQUEST_LIMITS_CODE,
                message: violation.message(),
            });
        }
    }

    match validate_json_schema(schema, value) {
        Ok(()) => Ok(()),
        Err(SchemaValidationError::InvalidSchema { message }) => Err(FcpError::Internal {
            message: format!("input schema invalid: {message}"),
        }),
        Err(SchemaValidationError::ValidationFailed { errors, .. }) => {
            Err(FcpError::InvalidRequest {
                code: INVALID_REQUEST_SCHEMA_CODE,
                message: format!(
                    "input schema validation failed: {}",
                    format_schema_errors(&errors)
                ),
            })
        }
    }
}

/// Validate output payloads against limits and a JSON Schema.
///
/// # Errors
/// Returns `FcpError::Internal` when the output value violates limits, does not match the schema,
/// or the schema is invalid.
pub fn validate_output_with_limits(
    schema: &serde_json::Value,
    value: &serde_json::Value,
    limits: &Limits,
) -> Result<(), FcpError> {
    match validate_limits(value, limits) {
        Ok(()) => {}
        Err(LimitCheckError::Serialization(message)) => {
            return Err(FcpError::Internal {
                message: format!("failed to measure payload size: {message}"),
            });
        }
        Err(LimitCheckError::Violation(violation)) => {
            return Err(FcpError::Internal {
                message: format!("output payload exceeds limits: {}", violation.message()),
            });
        }
    }

    match validate_json_schema(schema, value) {
        Ok(()) => Ok(()),
        Err(SchemaValidationError::InvalidSchema { message }) => Err(FcpError::Internal {
            message: format!("output schema invalid: {message}"),
        }),
        Err(SchemaValidationError::ValidationFailed { errors, .. }) => Err(FcpError::Internal {
            message: format!(
                "output schema validation failed: {}",
                format_schema_errors(&errors)
            ),
        }),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Payload limits helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Recommended payload limits for connector inputs/outputs.
///
/// Defaults are conservative to prevent pathological payloads while remaining
/// large enough for common connector requests.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Maximum serialized payload size in bytes.
    pub max_bytes: Option<usize>,
    /// Maximum number of elements in any array.
    pub max_array_len: Option<usize>,
    /// Maximum nesting depth (root = depth 1).
    pub max_depth: Option<usize>,
}

impl Limits {
    /// Default max payload size (256 KiB).
    pub const DEFAULT_MAX_BYTES: usize = 256 * 1024;
    /// Default max array length.
    pub const DEFAULT_MAX_ARRAY_LEN: usize = 1_000;
    /// Default max nesting depth (root = depth 1).
    pub const DEFAULT_MAX_DEPTH: usize = 32;

    /// Create limits with all values enabled.
    #[must_use]
    pub const fn new(max_bytes: usize, max_array_len: usize, max_depth: usize) -> Self {
        Self {
            max_bytes: Some(max_bytes),
            max_array_len: Some(max_array_len),
            max_depth: Some(max_depth),
        }
    }

    /// Disable all limits (use with caution).
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            max_bytes: None,
            max_array_len: None,
            max_depth: None,
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::new(
            Self::DEFAULT_MAX_BYTES,
            Self::DEFAULT_MAX_ARRAY_LEN,
            Self::DEFAULT_MAX_DEPTH,
        )
    }
}

#[derive(Debug, Clone)]
enum LimitViolation {
    PayloadTooLarge {
        actual: usize,
        max: usize,
    },
    ArrayTooLong {
        path: String,
        len: usize,
        max: usize,
    },
    DepthTooDeep {
        path: String,
        depth: usize,
        max: usize,
    },
}

#[derive(Debug, Clone)]
enum LimitCheckError {
    Violation(LimitViolation),
    Serialization(String),
}

impl LimitViolation {
    fn message(&self) -> String {
        match self {
            Self::PayloadTooLarge { actual, max } => {
                format!("payload size {actual} bytes exceeds limit {max} bytes")
            }
            Self::ArrayTooLong { path, len, max } => {
                format!("array length {len} exceeds limit {max} at {path}")
            }
            Self::DepthTooDeep { path, depth, max } => {
                format!("max depth {max} exceeded at {path} (depth {depth})")
            }
        }
    }
}

#[derive(Debug, Clone)]
enum PathSegment {
    Key(String),
    Index(usize),
}

fn format_path(segments: &[PathSegment]) -> String {
    if segments.is_empty() {
        return "$".to_string();
    }

    let mut path = String::from("$");
    for segment in segments {
        match segment {
            PathSegment::Key(key) => {
                path.push('/');
                path.push_str(&escape_json_pointer(key));
            }
            PathSegment::Index(index) => {
                path.push('/');
                path.push_str(&index.to_string());
            }
        }
    }
    path
}

fn escape_json_pointer(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

fn check_limits(
    value: &serde_json::Value,
    limits: &Limits,
    depth: usize,
    path: &mut Vec<PathSegment>,
) -> Result<(), LimitViolation> {
    if let Some(max_depth) = limits.max_depth {
        if depth > max_depth {
            return Err(LimitViolation::DepthTooDeep {
                path: format_path(path),
                depth,
                max: max_depth,
            });
        }
    }

    match value {
        serde_json::Value::Array(items) => {
            if let Some(max_array_len) = limits.max_array_len {
                if items.len() > max_array_len {
                    return Err(LimitViolation::ArrayTooLong {
                        path: format_path(path),
                        len: items.len(),
                        max: max_array_len,
                    });
                }
            }
            for (index, item) in items.iter().enumerate() {
                path.push(PathSegment::Index(index));
                check_limits(item, limits, depth.saturating_add(1), path)?;
                path.pop();
            }
        }
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                path.push(PathSegment::Key(key.clone()));
                check_limits(value, limits, depth.saturating_add(1), path)?;
                path.pop();
            }
        }
        _ => {}
    }

    Ok(())
}

fn validate_limits(value: &serde_json::Value, limits: &Limits) -> Result<(), LimitCheckError> {
    if let Some(max_bytes) = limits.max_bytes {
        let size = serde_json::to_vec(value)
            .map_err(|err| LimitCheckError::Serialization(err.to_string()))?;
        if size.len() > max_bytes {
            return Err(LimitCheckError::Violation(
                LimitViolation::PayloadTooLarge {
                    actual: size.len(),
                    max: max_bytes,
                },
            ));
        }
    }

    if limits.max_array_len.is_some() || limits.max_depth.is_some() {
        let mut path = Vec::new();
        check_limits(value, limits, 1, &mut path).map_err(LimitCheckError::Violation)?;
    }

    Ok(())
}

/// Enforce payload size, array length, and depth limits.
///
/// # Errors
/// Returns `FcpError::InvalidRequest` when limits are exceeded.
pub fn enforce_limits(value: &serde_json::Value, limits: &Limits) -> Result<(), FcpError> {
    match validate_limits(value, limits) {
        Ok(()) => Ok(()),
        Err(LimitCheckError::Serialization(message)) => Err(FcpError::Internal {
            message: format!("failed to measure payload size: {message}"),
        }),
        Err(LimitCheckError::Violation(violation)) => Err(FcpError::InvalidRequest {
            code: INVALID_REQUEST_LIMITS_CODE,
            message: violation.message(),
        }),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Re-export commonly used external crates
// ─────────────────────────────────────────────────────────────────────────────

pub use serde;
pub use serde_json;
pub use thiserror;
pub use tracing;

#[cfg(test)]
mod tests {
    use super::{SchemaValidator, validate_json_schema};
    use serde_json::json;

    #[test]
    fn validate_schema_success_and_failure() {
        let schema = json!({
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": { "type": "string" }
            }
        });

        let ok_value = json!({ "name": "fcp" });
        let bad_value = json!({});

        assert!(validate_json_schema(&schema, &ok_value).is_ok());
        assert!(validate_json_schema(&schema, &bad_value).is_err());

        let validator = SchemaValidator::compile(&schema).expect("schema compiles");
        assert!(validator.validate(&ok_value).is_ok());
        assert!(validator.validate(&bad_value).is_err());
    }
}
