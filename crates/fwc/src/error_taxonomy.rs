//! Structured FCP error taxonomy for `fwc`.
//!
//! Defines the canonical `FCP_ERR_*` error code vocabulary, categories,
//! exit-code mapping, and machine-readable recovery guidance.  Every
//! user-facing error emitted by `fwc` should ultimately route through
//! this taxonomy so agents and scripts can programmatically distinguish
//! failure classes and decide on retry, escalation, or fallback.
//!
//! # Design principles
//!
//! 1. **Stable string codes** — `FCP_ERR_RATE_LIMITED` will never change
//!    meaning; new codes are additive.
//! 2. **Category + exit-code determinism** — given a code, the category
//!    and process exit code are fixed at compile time.
//! 3. **Recovery is first-class** — every code carries a default recovery
//!    action, suggested command, and alternative.  Callers may override.
//! 4. **Retryability is explicit** — codes declare whether automatic retry
//!    is safe, so the retry controller (CUAL-N.2) can make decisions
//!    without heuristic guessing.

use serde::{Deserialize, Serialize};

// ── Error code enum ─────────────────────────────────────────────────────

/// Canonical FCP error code.
///
/// Each variant maps 1:1 to a stable `FCP_ERR_*` string constant, a
/// category, a CLI exit code, and default recovery metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FcpErrorCode {
    // ── Parse / CLI (exit 2–4) ──────────────────────────────────────
    /// CLI argument parsing failed.
    FcpErrParseFailed,
    /// Unrecognised command or subcommand.
    FcpErrUnknownCommand,
    /// Dangerous or ambiguous typo correction blocked.
    FcpErrAmbiguousCorrection,

    // ── Validation (exit 5) ─────────────────────────────────────────
    /// Generic input validation failure.
    FcpErrValidationFailed,
    /// Inline `--input` JSON is not valid.
    FcpErrInvalidInput,
    /// A required field is missing from the request.
    FcpErrMissingField,
    /// Input does not conform to the operation's JSON Schema.
    FcpErrSchemaViolation,
    /// `--set key=value` binding could not be applied.
    FcpErrBindingFailed,
    /// Connector selector matched nothing.
    FcpErrConnectorNotFound,
    /// Connector selector matched multiple candidates.
    FcpErrAmbiguousConnector,
    /// Operation selector matched nothing.
    FcpErrOperationNotFound,
    /// Operation selector matched multiple candidates.
    FcpErrAmbiguousOperation,

    // ── Auth (exit 5 for now, 2 when host-backed) ───────────────────
    /// Caller is not authenticated or token is invalid.
    FcpErrUnauthorized,
    /// Capability or approval token has expired.
    FcpErrTokenExpired,
    /// Cryptographic signature verification failed.
    FcpErrInvalidSignature,
    /// A capability token is required but was not provided.
    FcpErrMissingCapabilityToken,
    /// The provided capability token could not be parsed.
    FcpErrInvalidCapabilityToken,
    /// The provided approval token could not be parsed.
    FcpErrInvalidApprovalToken,

    // ── Rate-limit (exit 7) ─────────────────────────────────────────
    /// The operation was rate-limited; retry after the indicated delay.
    FcpErrRateLimited,
    /// Usage budget for the current window is exhausted.
    FcpErrBudgetExceeded,

    // ── Capability / policy (exit 6) ────────────────────────────────
    /// The required capability is not granted.
    FcpErrCapabilityDenied,
    /// The specific operation is not in the capability grant set.
    FcpErrOperationNotGranted,
    /// Policy explicitly denied this action.
    FcpErrPolicyDenied,
    /// Cross-zone access violated zone isolation rules.
    FcpErrZoneViolation,
    /// Elevated privileges are required for this operation.
    FcpErrElevationRequired,

    // ── Connector (exit 7) ──────────────────────────────────────────
    /// The target connector is unreachable or has failed health checks.
    FcpErrConnectorUnavailable,
    /// The connector has not been configured.
    FcpErrConnectorNotConfigured,
    /// The connector health check returned a failure.
    FcpErrHealthCheckFailed,
    /// Streaming is not supported by this connector.
    FcpErrStreamingNotSupported,
    /// Circuit breaker is open; the connector is temporarily blocked.
    FcpErrCircuitOpen,

    // ── Transport (exit 8) ──────────────────────────────────────────
    /// Network or transport-layer failure.
    FcpErrTransportFailed,
    /// Upstream service did not respond within the timeout window.
    FcpErrUpstreamTimeout,
    /// A required dependency service is unavailable.
    FcpErrDependencyUnavailable,

    // ── Resource (exit 7) ───────────────────────────────────────────
    /// The requested resource does not exist.
    FcpErrResourceNotFound,
    /// The resource pool is exhausted.
    FcpErrResourceExhausted,
    /// A write conflict was detected.
    FcpErrConflict,

    // ── External (exit 7) ───────────────────────────────────────────
    /// The external service returned an error.
    FcpErrExternalService,

    // ── Internal (exit 1) ───────────────────────────────────────────
    /// An unexpected internal error occurred.
    FcpErrInternal,
}

/// Total number of error codes.
pub const ERROR_CODE_COUNT: usize = 38;

// ── Error category ──────────────────────────────────────────────────────

/// High-level error category for grouping and exit-code mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FwcErrorCategory {
    /// CLI argument parsing or command resolution.
    Parse,
    /// Input validation, schema, or selector errors.
    Validation,
    /// Authentication and token errors.
    Auth,
    /// Rate limiting and budget exhaustion.
    RateLimit,
    /// Capability, policy, and zone enforcement.
    Policy,
    /// Connector lifecycle, health, and availability.
    Connector,
    /// Network and transport errors.
    Transport,
    /// External service failures.
    External,
    /// Resource availability and conflict.
    Resource,
    /// Unexpected internal errors.
    Internal,
}

impl FwcErrorCategory {
    /// Machine-readable tag for JSON output.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Parse => "parse",
            Self::Validation => "validation",
            Self::Auth => "auth",
            Self::RateLimit => "rate_limit",
            Self::Policy => "policy",
            Self::Connector => "connector",
            Self::Transport => "transport",
            Self::External => "external",
            Self::Resource => "resource",
            Self::Internal => "internal",
        }
    }

    /// CLI exit code for this category.
    pub const fn exit_code(self) -> u8 {
        match self {
            Self::Internal => 1,
            Self::Parse => 2,
            Self::Validation | Self::Auth => 5,
            Self::Policy => 6,
            Self::Connector | Self::RateLimit | Self::Resource | Self::External => 7,
            Self::Transport => 8,
        }
    }
}

// ── Error code methods ──────────────────────────────────────────────────

impl FcpErrorCode {
    /// Stable string constant (e.g. `"FCP_ERR_RATE_LIMITED"`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FcpErrParseFailed => "FCP_ERR_PARSE_FAILED",
            Self::FcpErrUnknownCommand => "FCP_ERR_UNKNOWN_COMMAND",
            Self::FcpErrAmbiguousCorrection => "FCP_ERR_AMBIGUOUS_CORRECTION",
            Self::FcpErrValidationFailed => "FCP_ERR_VALIDATION_FAILED",
            Self::FcpErrInvalidInput => "FCP_ERR_INVALID_INPUT",
            Self::FcpErrMissingField => "FCP_ERR_MISSING_FIELD",
            Self::FcpErrSchemaViolation => "FCP_ERR_SCHEMA_VIOLATION",
            Self::FcpErrBindingFailed => "FCP_ERR_BINDING_FAILED",
            Self::FcpErrConnectorNotFound => "FCP_ERR_CONNECTOR_NOT_FOUND",
            Self::FcpErrAmbiguousConnector => "FCP_ERR_AMBIGUOUS_CONNECTOR",
            Self::FcpErrOperationNotFound => "FCP_ERR_OPERATION_NOT_FOUND",
            Self::FcpErrAmbiguousOperation => "FCP_ERR_AMBIGUOUS_OPERATION",
            Self::FcpErrUnauthorized => "FCP_ERR_UNAUTHORIZED",
            Self::FcpErrTokenExpired => "FCP_ERR_TOKEN_EXPIRED",
            Self::FcpErrInvalidSignature => "FCP_ERR_INVALID_SIGNATURE",
            Self::FcpErrMissingCapabilityToken => "FCP_ERR_MISSING_CAPABILITY_TOKEN",
            Self::FcpErrInvalidCapabilityToken => "FCP_ERR_INVALID_CAPABILITY_TOKEN",
            Self::FcpErrInvalidApprovalToken => "FCP_ERR_INVALID_APPROVAL_TOKEN",
            Self::FcpErrRateLimited => "FCP_ERR_RATE_LIMITED",
            Self::FcpErrBudgetExceeded => "FCP_ERR_BUDGET_EXCEEDED",
            Self::FcpErrCapabilityDenied => "FCP_ERR_CAPABILITY_DENIED",
            Self::FcpErrOperationNotGranted => "FCP_ERR_OPERATION_NOT_GRANTED",
            Self::FcpErrPolicyDenied => "FCP_ERR_POLICY_DENIED",
            Self::FcpErrZoneViolation => "FCP_ERR_ZONE_VIOLATION",
            Self::FcpErrElevationRequired => "FCP_ERR_ELEVATION_REQUIRED",
            Self::FcpErrConnectorUnavailable => "FCP_ERR_CONNECTOR_UNAVAILABLE",
            Self::FcpErrConnectorNotConfigured => "FCP_ERR_CONNECTOR_NOT_CONFIGURED",
            Self::FcpErrHealthCheckFailed => "FCP_ERR_HEALTH_CHECK_FAILED",
            Self::FcpErrStreamingNotSupported => "FCP_ERR_STREAMING_NOT_SUPPORTED",
            Self::FcpErrCircuitOpen => "FCP_ERR_CIRCUIT_OPEN",
            Self::FcpErrTransportFailed => "FCP_ERR_TRANSPORT_FAILED",
            Self::FcpErrUpstreamTimeout => "FCP_ERR_UPSTREAM_TIMEOUT",
            Self::FcpErrDependencyUnavailable => "FCP_ERR_DEPENDENCY_UNAVAILABLE",
            Self::FcpErrResourceNotFound => "FCP_ERR_RESOURCE_NOT_FOUND",
            Self::FcpErrResourceExhausted => "FCP_ERR_RESOURCE_EXHAUSTED",
            Self::FcpErrConflict => "FCP_ERR_CONFLICT",
            Self::FcpErrExternalService => "FCP_ERR_EXTERNAL_SERVICE",
            Self::FcpErrInternal => "FCP_ERR_INTERNAL",
        }
    }

    /// Error category for this code.
    pub const fn category(self) -> FwcErrorCategory {
        match self {
            Self::FcpErrParseFailed
            | Self::FcpErrUnknownCommand
            | Self::FcpErrAmbiguousCorrection => FwcErrorCategory::Parse,

            Self::FcpErrValidationFailed
            | Self::FcpErrInvalidInput
            | Self::FcpErrMissingField
            | Self::FcpErrSchemaViolation
            | Self::FcpErrBindingFailed
            | Self::FcpErrConnectorNotFound
            | Self::FcpErrAmbiguousConnector
            | Self::FcpErrOperationNotFound
            | Self::FcpErrAmbiguousOperation => FwcErrorCategory::Validation,

            Self::FcpErrUnauthorized
            | Self::FcpErrTokenExpired
            | Self::FcpErrInvalidSignature
            | Self::FcpErrMissingCapabilityToken
            | Self::FcpErrInvalidCapabilityToken
            | Self::FcpErrInvalidApprovalToken => FwcErrorCategory::Auth,

            Self::FcpErrRateLimited | Self::FcpErrBudgetExceeded => FwcErrorCategory::RateLimit,

            Self::FcpErrCapabilityDenied
            | Self::FcpErrOperationNotGranted
            | Self::FcpErrPolicyDenied
            | Self::FcpErrZoneViolation
            | Self::FcpErrElevationRequired => FwcErrorCategory::Policy,

            Self::FcpErrConnectorUnavailable
            | Self::FcpErrConnectorNotConfigured
            | Self::FcpErrHealthCheckFailed
            | Self::FcpErrStreamingNotSupported
            | Self::FcpErrCircuitOpen => FwcErrorCategory::Connector,

            Self::FcpErrTransportFailed
            | Self::FcpErrUpstreamTimeout
            | Self::FcpErrDependencyUnavailable => FwcErrorCategory::Transport,

            Self::FcpErrResourceNotFound | Self::FcpErrResourceExhausted | Self::FcpErrConflict => {
                FwcErrorCategory::Resource
            }

            Self::FcpErrExternalService => FwcErrorCategory::External,

            Self::FcpErrInternal => FwcErrorCategory::Internal,
        }
    }

    /// CLI exit code for this error.
    pub const fn exit_code(self) -> u8 {
        self.category().exit_code()
    }

    /// Whether automatic retry is safe for this error class.
    ///
    /// Codes that are inherently transient (rate-limit, timeout, transport)
    /// return `true`.  Codes that represent permanent rejection (auth,
    /// policy, validation) return `false`.
    pub const fn retryable(self) -> bool {
        matches!(
            self,
            Self::FcpErrRateLimited
                | Self::FcpErrBudgetExceeded
                | Self::FcpErrUpstreamTimeout
                | Self::FcpErrTransportFailed
                | Self::FcpErrDependencyUnavailable
                | Self::FcpErrConnectorUnavailable
                | Self::FcpErrCircuitOpen
                | Self::FcpErrExternalService
                | Self::FcpErrHealthCheckFailed
                | Self::FcpErrResourceExhausted
        )
    }

    /// Whether user action can resolve this error (as opposed to a
    /// transient infrastructure issue or an unrecoverable bug).
    pub const fn user_recoverable(self) -> bool {
        matches!(
            self,
            Self::FcpErrParseFailed
                | Self::FcpErrUnknownCommand
                | Self::FcpErrAmbiguousCorrection
                | Self::FcpErrValidationFailed
                | Self::FcpErrInvalidInput
                | Self::FcpErrMissingField
                | Self::FcpErrSchemaViolation
                | Self::FcpErrBindingFailed
                | Self::FcpErrConnectorNotFound
                | Self::FcpErrAmbiguousConnector
                | Self::FcpErrOperationNotFound
                | Self::FcpErrAmbiguousOperation
                | Self::FcpErrMissingCapabilityToken
                | Self::FcpErrConnectorNotConfigured
                | Self::FcpErrElevationRequired
        )
    }

    /// Default recovery hint for this error code.
    pub const fn default_recovery(self) -> Recovery {
        match self {
            Self::FcpErrParseFailed => Recovery {
                action: "Fix the command syntax",
                command: "fwc guide",
                alternative: "Use --help on the subcommand for usage details",
            },
            Self::FcpErrUnknownCommand => Recovery {
                action: "Check the command name",
                command: "fwc guide",
                alternative: "Use `fwc search <keyword>` to find commands",
            },
            Self::FcpErrAmbiguousCorrection => Recovery {
                action: "Spell out the full command name to avoid ambiguity",
                command: "fwc guide",
                alternative: "Use `fwc list` to see all available commands",
            },
            Self::FcpErrValidationFailed | Self::FcpErrSchemaViolation => Recovery {
                action: "Fix the input to match the operation schema",
                command: "fwc schema <connector> <operation>",
                alternative: "Use `fwc template <connector> <operation>` for a scaffold",
            },
            Self::FcpErrInvalidInput => Recovery {
                action: "Provide valid JSON input",
                command: "fwc template <connector> <operation>",
                alternative: "Use --file to read input from a file instead",
            },
            Self::FcpErrMissingField => Recovery {
                action: "Add the required field to your input",
                command: "fwc schema <connector> <operation>",
                alternative: "Use `fwc template` to generate a scaffold with all fields",
            },
            Self::FcpErrBindingFailed => Recovery {
                action: "Check the --set key=value syntax and types",
                command: "fwc schema <connector> <operation>",
                alternative: "Use --input with full JSON instead of --set bindings",
            },
            Self::FcpErrConnectorNotFound => Recovery {
                action: "Check the connector name spelling",
                command: "fwc list",
                alternative: "Use `fwc search <keyword>` to find connectors",
            },
            Self::FcpErrAmbiguousConnector => Recovery {
                action: "Use a more specific connector selector",
                command: "fwc list",
                alternative: "Use the full connector ID (e.g. github:request-response:1.0.0)",
            },
            Self::FcpErrOperationNotFound => Recovery {
                action: "Check the operation name spelling",
                command: "fwc ops <connector>",
                alternative: "Use `fwc search <keyword>` to find operations",
            },
            Self::FcpErrAmbiguousOperation => Recovery {
                action: "Use a more specific operation selector",
                command: "fwc ops <connector>",
                alternative: "Use the full operation ID (e.g. issues.create)",
            },
            Self::FcpErrUnauthorized | Self::FcpErrInvalidSignature => Recovery {
                action: "Re-authenticate or refresh credentials",
                command: "fwc config <connector>",
                alternative: "Check that your API key or token is still valid",
            },
            Self::FcpErrTokenExpired => Recovery {
                action: "Refresh the expired token",
                command: "fwc config <connector>",
                alternative: "Tokens can be refreshed via the credential store",
            },
            Self::FcpErrMissingCapabilityToken => Recovery {
                action: "Provide a capability token for live invocation",
                command: "fwc invoke --capability-token <token>",
                alternative: "Use `fwc simulate` for a dry-run without a token",
            },
            Self::FcpErrInvalidCapabilityToken | Self::FcpErrInvalidApprovalToken => Recovery {
                action: "Provide a valid token",
                command: "fwc invoke --capability-token-file <path>",
                alternative: "Regenerate the token from the issuing authority",
            },
            Self::FcpErrRateLimited => Recovery {
                action: "Wait for the rate-limit window to reset",
                command: "fwc invoke --retry 3",
                alternative: "Use `fwc budget <connector>` to check current usage",
            },
            Self::FcpErrBudgetExceeded => Recovery {
                action: "Wait for the budget window to reset",
                command: "fwc budget <connector>",
                alternative: "Request a budget increase or adjust the operation scope",
            },
            Self::FcpErrCapabilityDenied | Self::FcpErrOperationNotGranted => Recovery {
                action: "Request the required capability grant",
                command: "fwc capabilities <connector>",
                alternative: "Check zone policy for the required permission",
            },
            Self::FcpErrPolicyDenied => Recovery {
                action: "Review and adjust the policy",
                command: "fwc policy show",
                alternative: "Contact your administrator for a policy exception",
            },
            Self::FcpErrZoneViolation => Recovery {
                action: "Ensure the operation stays within its zone boundary",
                command: "fwc net <connector> <operation>",
                alternative: "Request cross-zone access if needed",
            },
            Self::FcpErrElevationRequired => Recovery {
                action: "Provide an elevation token for this operation",
                command: "fwc invoke --approval-token <token>",
                alternative: "Use `fwc simulate` to preview without elevation",
            },
            Self::FcpErrConnectorUnavailable | Self::FcpErrHealthCheckFailed => Recovery {
                action: "Check the connector health status",
                command: "fwc doctor <connector>",
                alternative: "Wait and retry — the connector may be restarting",
            },
            Self::FcpErrConnectorNotConfigured => Recovery {
                action: "Configure the connector before use",
                command: "fwc config <connector>",
                alternative: "Use `fwc install <connector>` for first-time setup",
            },
            Self::FcpErrStreamingNotSupported => Recovery {
                action: "Use a request-response invocation instead",
                command: "fwc invoke <connector> <operation>",
                alternative: "Check `fwc show <connector>` for supported archetypes",
            },
            Self::FcpErrCircuitOpen => Recovery {
                action: "Wait for the circuit breaker cooldown to expire",
                command: "fwc circuit status",
                alternative: "Use `fwc circuit reset <connector>` to force-close",
            },
            Self::FcpErrTransportFailed | Self::FcpErrDependencyUnavailable => Recovery {
                action: "Check network connectivity",
                command: "fwc doctor",
                alternative: "Retry after verifying the target service is reachable",
            },
            Self::FcpErrUpstreamTimeout => Recovery {
                action: "Retry with a longer timeout or smaller payload",
                command: "fwc invoke --retry 3",
                alternative: "Check the upstream service status page",
            },
            Self::FcpErrResourceNotFound => Recovery {
                action: "Verify the resource identifier",
                command: "fwc ops <connector>",
                alternative: "The resource may have been deleted or moved",
            },
            Self::FcpErrResourceExhausted => Recovery {
                action: "Free resources or wait for capacity",
                command: "fwc budget <connector>",
                alternative: "Reduce concurrent operations to free capacity",
            },
            Self::FcpErrConflict => Recovery {
                action: "Resolve the conflict and retry",
                command: "fwc invoke <connector> <operation>",
                alternative: "Use an idempotency key to prevent duplicate writes",
            },
            Self::FcpErrExternalService => Recovery {
                action: "Check the external service status",
                command: "fwc health <connector>",
                alternative: "The error may be transient — retry after a delay",
            },
            Self::FcpErrInternal => Recovery {
                action: "Report this as a bug",
                command: "fwc doctor",
                alternative: "Retry the operation — if it persists, file an issue",
            },
        }
    }

    /// Look up an error code by its string constant.
    pub fn from_str(s: &str) -> Option<Self> {
        ALL_CODES.iter().find(|c| c.as_str() == s).copied()
    }
}

impl std::fmt::Display for FcpErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Static recovery hint for an error code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Recovery {
    /// What the user should do.
    pub action: &'static str,
    /// Suggested CLI command.
    pub command: &'static str,
    /// Alternative approach.
    pub alternative: &'static str,
}

impl Serialize for Recovery {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry("action", self.action)?;
        map.serialize_entry("command", self.command)?;
        map.serialize_entry("alternative", self.alternative)?;
        map.end()
    }
}

// ── Structured error envelope ───────────────────────────────────────────

/// A fully-structured error ready for JSON or TOON rendering.
///
/// This is the output type that `fwc` dispatch functions should produce
/// for any user-facing error.  It carries the canonical code, category,
/// human message, optional details, and recovery guidance.
#[derive(Clone, Debug, Serialize)]
pub struct StructuredError {
    /// Canonical error code (e.g. `FCP_ERR_RATE_LIMITED`).
    pub code: &'static str,
    /// Error category tag.
    pub category: &'static str,
    /// Human-readable error message.
    pub message: String,
    /// Whether the operation can be automatically retried.
    pub retryable: bool,
    /// Whether user action can resolve this error.
    pub recoverable: bool,
    /// Recovery guidance.
    pub recovery: Recovery,
    /// Optional structured details (schema path, retry-after ms, etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
    /// CLI exit code.
    pub exit_code: u8,
}

impl StructuredError {
    /// Build a `StructuredError` from an error code and message.
    pub fn new(code: FcpErrorCode, message: impl Into<String>) -> Self {
        Self {
            code: code.as_str(),
            category: code.category().tag(),
            message: message.into(),
            retryable: code.retryable(),
            recoverable: code.user_recoverable(),
            recovery: code.default_recovery(),
            details: None,
            exit_code: code.exit_code(),
        }
    }

    /// Attach optional details.
    #[must_use]
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    /// Convert to a JSON `Value` suitable for embedding in a
    /// `DispatchOutcome` payload.
    pub fn to_value(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_else(|_| {
            serde_json::json!({
                "code": self.code,
                "category": self.category,
                "message": self.message,
                "retryable": self.retryable,
                "recoverable": self.recoverable,
                "exit_code": self.exit_code,
            })
        })
    }
}

// ── Mapping from fcp-core FcpError ──────────────────────────────────────

/// Map an `fcp_core::FcpError` variant to its canonical `FcpErrorCode`.
pub fn classify_fcp_error(err: &fcp_core::FcpError) -> FcpErrorCode {
    match err {
        fcp_core::FcpError::InvalidRequest { .. } | fcp_core::FcpError::MalformedFrame { .. } => {
            FcpErrorCode::FcpErrValidationFailed
        }
        fcp_core::FcpError::MissingField { .. } => FcpErrorCode::FcpErrMissingField,
        fcp_core::FcpError::ChecksumMismatch | fcp_core::FcpError::VersionMismatch { .. } => {
            FcpErrorCode::FcpErrTransportFailed
        }
        fcp_core::FcpError::Unauthorized { .. } => FcpErrorCode::FcpErrUnauthorized,
        fcp_core::FcpError::TokenExpired => FcpErrorCode::FcpErrTokenExpired,
        fcp_core::FcpError::InvalidSignature => FcpErrorCode::FcpErrInvalidSignature,
        fcp_core::FcpError::CapabilityDenied { .. } => FcpErrorCode::FcpErrCapabilityDenied,
        fcp_core::FcpError::RateLimited { .. } => FcpErrorCode::FcpErrRateLimited,
        fcp_core::FcpError::OperationNotGranted { .. } => FcpErrorCode::FcpErrOperationNotGranted,
        fcp_core::FcpError::ResourceNotAllowed { .. } => FcpErrorCode::FcpErrPolicyDenied,
        fcp_core::FcpError::ZoneViolation { .. } | fcp_core::FcpError::TaintViolation { .. } => {
            FcpErrorCode::FcpErrZoneViolation
        }
        fcp_core::FcpError::ElevationRequired { .. } => FcpErrorCode::FcpErrElevationRequired,
        fcp_core::FcpError::ConnectorUnavailable { .. } => FcpErrorCode::FcpErrConnectorUnavailable,
        fcp_core::FcpError::NotConfigured => FcpErrorCode::FcpErrConnectorNotConfigured,
        fcp_core::FcpError::NotHandshaken => FcpErrorCode::FcpErrConnectorNotConfigured,
        fcp_core::FcpError::HealthCheckFailed { .. } => FcpErrorCode::FcpErrHealthCheckFailed,
        fcp_core::FcpError::StreamingNotSupported => FcpErrorCode::FcpErrStreamingNotSupported,
        fcp_core::FcpError::ResourceNotFound { .. } => FcpErrorCode::FcpErrResourceNotFound,
        fcp_core::FcpError::ResourceExhausted { .. } => FcpErrorCode::FcpErrResourceExhausted,
        fcp_core::FcpError::BudgetExceeded { .. } => FcpErrorCode::FcpErrBudgetExceeded,
        fcp_core::FcpError::Conflict { .. } => FcpErrorCode::FcpErrConflict,
        fcp_core::FcpError::External { .. } => FcpErrorCode::FcpErrExternalService,
        fcp_core::FcpError::UpstreamTimeout { .. } => FcpErrorCode::FcpErrUpstreamTimeout,
        fcp_core::FcpError::DependencyUnavailable { .. } => {
            FcpErrorCode::FcpErrDependencyUnavailable
        }
        fcp_core::FcpError::Internal { .. } => FcpErrorCode::FcpErrInternal,
    }
}

/// Build a `StructuredError` from an `fcp_core::FcpError`.
pub fn structured_from_fcp_error(err: &fcp_core::FcpError) -> StructuredError {
    let code = classify_fcp_error(err);
    let mut se = StructuredError::new(code, err.to_string());

    // Attach error-specific details.
    match err {
        fcp_core::FcpError::RateLimited { retry_after_ms, .. } => {
            se.details = Some(serde_json::json!({ "retry_after_ms": retry_after_ms }));
        }
        fcp_core::FcpError::BudgetExceeded {
            metric,
            used,
            limit,
            window_seconds,
        } => {
            se.details = Some(serde_json::json!({
                "metric": format!("{metric:?}"),
                "used": used,
                "limit": limit,
                "window_seconds": window_seconds,
            }));
        }
        fcp_core::FcpError::External {
            service,
            status_code,
            retryable,
            ..
        } => {
            se.details = Some(serde_json::json!({
                "service": service,
                "status_code": status_code,
                "retryable": retryable,
            }));
        }
        fcp_core::FcpError::ZoneViolation {
            source_zone,
            target_zone,
            ..
        } => {
            se.details = Some(serde_json::json!({
                "source_zone": source_zone,
                "target_zone": target_zone,
            }));
        }
        fcp_core::FcpError::CapabilityDenied { capability, reason } => {
            se.details = Some(serde_json::json!({
                "capability": capability,
                "reason": reason,
            }));
        }
        _ => {}
    }

    se
}

// ── All codes (for lookup / iteration) ──────────────────────────────────

/// All error codes, in declaration order.
pub static ALL_CODES: &[FcpErrorCode] = &[
    FcpErrorCode::FcpErrParseFailed,
    FcpErrorCode::FcpErrUnknownCommand,
    FcpErrorCode::FcpErrAmbiguousCorrection,
    FcpErrorCode::FcpErrValidationFailed,
    FcpErrorCode::FcpErrInvalidInput,
    FcpErrorCode::FcpErrMissingField,
    FcpErrorCode::FcpErrSchemaViolation,
    FcpErrorCode::FcpErrBindingFailed,
    FcpErrorCode::FcpErrConnectorNotFound,
    FcpErrorCode::FcpErrAmbiguousConnector,
    FcpErrorCode::FcpErrOperationNotFound,
    FcpErrorCode::FcpErrAmbiguousOperation,
    FcpErrorCode::FcpErrUnauthorized,
    FcpErrorCode::FcpErrTokenExpired,
    FcpErrorCode::FcpErrInvalidSignature,
    FcpErrorCode::FcpErrMissingCapabilityToken,
    FcpErrorCode::FcpErrInvalidCapabilityToken,
    FcpErrorCode::FcpErrInvalidApprovalToken,
    FcpErrorCode::FcpErrRateLimited,
    FcpErrorCode::FcpErrBudgetExceeded,
    FcpErrorCode::FcpErrCapabilityDenied,
    FcpErrorCode::FcpErrOperationNotGranted,
    FcpErrorCode::FcpErrPolicyDenied,
    FcpErrorCode::FcpErrZoneViolation,
    FcpErrorCode::FcpErrElevationRequired,
    FcpErrorCode::FcpErrConnectorUnavailable,
    FcpErrorCode::FcpErrConnectorNotConfigured,
    FcpErrorCode::FcpErrHealthCheckFailed,
    FcpErrorCode::FcpErrStreamingNotSupported,
    FcpErrorCode::FcpErrCircuitOpen,
    FcpErrorCode::FcpErrTransportFailed,
    FcpErrorCode::FcpErrUpstreamTimeout,
    FcpErrorCode::FcpErrDependencyUnavailable,
    FcpErrorCode::FcpErrResourceNotFound,
    FcpErrorCode::FcpErrResourceExhausted,
    FcpErrorCode::FcpErrConflict,
    FcpErrorCode::FcpErrExternalService,
    FcpErrorCode::FcpErrInternal,
];

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_codes_count_matches_constant() {
        assert_eq!(ALL_CODES.len(), ERROR_CODE_COUNT);
    }

    #[test]
    fn every_code_has_fcp_err_prefix() {
        for code in ALL_CODES {
            assert!(
                code.as_str().starts_with("FCP_ERR_"),
                "Code {:?} missing FCP_ERR_ prefix: {}",
                code,
                code.as_str()
            );
        }
    }

    #[test]
    fn no_duplicate_string_constants() {
        let mut seen = std::collections::HashSet::new();
        for code in ALL_CODES {
            assert!(
                seen.insert(code.as_str()),
                "Duplicate error code string: {}",
                code.as_str()
            );
        }
    }

    #[test]
    fn exit_codes_are_in_valid_range() {
        for code in ALL_CODES {
            let exit = code.exit_code();
            assert!(exit <= 8, "Exit code {} for {:?} exceeds max 8", exit, code);
            assert_ne!(exit, 0, "Error code {:?} must not have exit 0", code);
        }
    }

    #[test]
    fn category_exit_code_consistency() {
        for code in ALL_CODES {
            let cat_exit = code.category().exit_code();
            let code_exit = code.exit_code();
            assert_eq!(
                cat_exit, code_exit,
                "Category exit {} != code exit {} for {:?}",
                cat_exit, code_exit, code
            );
        }
    }

    #[test]
    fn parse_codes_exit_2_or_3_or_4() {
        let parse_codes = [
            FcpErrorCode::FcpErrParseFailed,
            FcpErrorCode::FcpErrUnknownCommand,
            FcpErrorCode::FcpErrAmbiguousCorrection,
        ];
        for code in &parse_codes {
            assert_eq!(code.exit_code(), 2, "Parse code {:?} should exit 2", code);
        }
    }

    #[test]
    fn validation_codes_exit_5() {
        let validation_codes = [
            FcpErrorCode::FcpErrValidationFailed,
            FcpErrorCode::FcpErrInvalidInput,
            FcpErrorCode::FcpErrMissingField,
            FcpErrorCode::FcpErrSchemaViolation,
            FcpErrorCode::FcpErrBindingFailed,
            FcpErrorCode::FcpErrConnectorNotFound,
        ];
        for code in &validation_codes {
            assert_eq!(
                code.exit_code(),
                5,
                "Validation code {:?} should exit 5",
                code
            );
        }
    }

    #[test]
    fn auth_codes_exit_5() {
        let auth_codes = [
            FcpErrorCode::FcpErrUnauthorized,
            FcpErrorCode::FcpErrTokenExpired,
            FcpErrorCode::FcpErrInvalidSignature,
        ];
        for code in &auth_codes {
            assert_eq!(code.exit_code(), 5, "Auth code {:?} should exit 5", code);
        }
    }

    #[test]
    fn policy_codes_exit_6() {
        let policy_codes = [
            FcpErrorCode::FcpErrCapabilityDenied,
            FcpErrorCode::FcpErrPolicyDenied,
            FcpErrorCode::FcpErrZoneViolation,
            FcpErrorCode::FcpErrElevationRequired,
        ];
        for code in &policy_codes {
            assert_eq!(code.exit_code(), 6, "Policy code {:?} should exit 6", code);
        }
    }

    #[test]
    fn rate_limit_is_retryable() {
        assert!(FcpErrorCode::FcpErrRateLimited.retryable());
        assert!(FcpErrorCode::FcpErrBudgetExceeded.retryable());
    }

    #[test]
    fn validation_is_not_retryable() {
        assert!(!FcpErrorCode::FcpErrValidationFailed.retryable());
        assert!(!FcpErrorCode::FcpErrInvalidInput.retryable());
        assert!(!FcpErrorCode::FcpErrMissingField.retryable());
    }

    #[test]
    fn auth_is_not_retryable() {
        assert!(!FcpErrorCode::FcpErrUnauthorized.retryable());
        assert!(!FcpErrorCode::FcpErrTokenExpired.retryable());
        assert!(!FcpErrorCode::FcpErrInvalidSignature.retryable());
    }

    #[test]
    fn transport_is_retryable() {
        assert!(FcpErrorCode::FcpErrTransportFailed.retryable());
        assert!(FcpErrorCode::FcpErrUpstreamTimeout.retryable());
        assert!(FcpErrorCode::FcpErrDependencyUnavailable.retryable());
    }

    #[test]
    fn parse_errors_are_user_recoverable() {
        assert!(FcpErrorCode::FcpErrParseFailed.user_recoverable());
        assert!(FcpErrorCode::FcpErrUnknownCommand.user_recoverable());
    }

    #[test]
    fn internal_is_not_user_recoverable() {
        assert!(!FcpErrorCode::FcpErrInternal.user_recoverable());
    }

    #[test]
    fn every_code_has_a_recovery() {
        for code in ALL_CODES {
            let r = code.default_recovery();
            assert!(!r.action.is_empty(), "Empty recovery action for {:?}", code);
            assert!(
                !r.command.is_empty(),
                "Empty recovery command for {:?}",
                code
            );
            assert!(
                !r.alternative.is_empty(),
                "Empty recovery alternative for {:?}",
                code
            );
        }
    }

    #[test]
    fn from_str_round_trips() {
        for code in ALL_CODES {
            let s = code.as_str();
            let parsed = FcpErrorCode::from_str(s);
            assert_eq!(parsed, Some(*code), "from_str({}) did not round-trip", s);
        }
    }

    #[test]
    fn from_str_returns_none_for_unknown() {
        assert_eq!(FcpErrorCode::from_str("FCP_ERR_NONEXISTENT"), None);
        assert_eq!(FcpErrorCode::from_str(""), None);
        assert_eq!(FcpErrorCode::from_str("RATE_LIMITED"), None);
    }

    #[test]
    fn structured_error_serializes_to_json() {
        let se = StructuredError::new(
            FcpErrorCode::FcpErrRateLimited,
            "Rate limited: retry after 5000ms",
        )
        .with_details(serde_json::json!({ "retry_after_ms": 5000 }));

        let v = se.to_value();
        assert_eq!(v["code"], "FCP_ERR_RATE_LIMITED");
        assert_eq!(v["category"], "rate_limit");
        assert_eq!(v["retryable"], true);
        assert_eq!(v["exit_code"], 7);
        assert_eq!(v["details"]["retry_after_ms"], 5000);
        assert!(v["recovery"]["action"].is_string());
        assert!(v["recovery"]["command"].is_string());
    }

    #[test]
    fn structured_error_without_details() {
        let se = StructuredError::new(FcpErrorCode::FcpErrParseFailed, "Expected subcommand");
        let v = se.to_value();
        assert_eq!(v["code"], "FCP_ERR_PARSE_FAILED");
        assert!(v.get("details").is_none() || v["details"].is_null());
    }

    #[test]
    fn missing_capability_token_recovery_stays_on_live_auth_path() {
        let se = StructuredError::new(
            FcpErrorCode::FcpErrMissingCapabilityToken,
            "Live invoke requires a capability token",
        );
        let v = se.to_value();
        assert_eq!(v["category"], "auth");
        assert_eq!(
            v["recovery"]["command"],
            "fwc invoke --capability-token <token>"
        );
        assert!(
            v["recovery"]["action"]
                .as_str()
                .unwrap()
                .contains("live invocation")
        );
        assert!(
            v["recovery"]["alternative"]
                .as_str()
                .unwrap()
                .contains("simulate")
        );
        assert!(
            !v["recovery"]["alternative"]
                .as_str()
                .unwrap()
                .contains("--offline")
        );
        assert!(
            !v["recovery"]["alternative"]
                .as_str()
                .unwrap()
                .contains("placeholder")
        );
    }

    #[test]
    fn elevation_required_recovery_uses_approval_token_not_placeholder_copy() {
        let se = StructuredError::new(
            FcpErrorCode::FcpErrElevationRequired,
            "Live invoke requires approval",
        );
        let v = se.to_value();
        assert_eq!(
            v["recovery"]["command"],
            "fwc invoke --approval-token <token>"
        );
        assert!(
            v["recovery"]["alternative"]
                .as_str()
                .unwrap()
                .contains("simulate")
        );
        assert!(
            !v["recovery"]["command"]
                .as_str()
                .unwrap()
                .contains("placeholder")
        );
        assert!(!v["recovery"]["command"].as_str().unwrap().contains("test"));
    }

    #[test]
    fn classify_fcp_rate_limited() {
        let err = fcp_core::FcpError::RateLimited {
            retry_after_ms: 5000,
            violation: None,
        };
        assert_eq!(classify_fcp_error(&err), FcpErrorCode::FcpErrRateLimited);
    }

    #[test]
    fn classify_fcp_unauthorized() {
        let err = fcp_core::FcpError::Unauthorized {
            code: 2001,
            message: "bad token".to_owned(),
        };
        assert_eq!(classify_fcp_error(&err), FcpErrorCode::FcpErrUnauthorized);
    }

    #[test]
    fn classify_fcp_zone_violation() {
        let err = fcp_core::FcpError::ZoneViolation {
            source_zone: "z:public".to_owned(),
            target_zone: "z:private".to_owned(),
            message: "denied".to_owned(),
        };
        assert_eq!(classify_fcp_error(&err), FcpErrorCode::FcpErrZoneViolation);
    }

    #[test]
    fn classify_fcp_internal() {
        let err = fcp_core::FcpError::Internal {
            message: "panic".to_owned(),
        };
        assert_eq!(classify_fcp_error(&err), FcpErrorCode::FcpErrInternal);
    }

    #[test]
    fn structured_from_fcp_error_rate_limited() {
        let err = fcp_core::FcpError::RateLimited {
            retry_after_ms: 3000,
            violation: None,
        };
        let se = structured_from_fcp_error(&err);
        assert_eq!(se.code, "FCP_ERR_RATE_LIMITED");
        assert!(se.retryable);
        assert_eq!(se.details.as_ref().unwrap()["retry_after_ms"], 3000);
    }

    #[test]
    fn structured_from_fcp_error_capability_denied() {
        let err = fcp_core::FcpError::CapabilityDenied {
            capability: "github.issues.create".to_owned(),
            reason: "not granted".to_owned(),
        };
        let se = structured_from_fcp_error(&err);
        assert_eq!(se.code, "FCP_ERR_CAPABILITY_DENIED");
        assert!(!se.retryable);
        assert_eq!(se.exit_code, 6);
        assert_eq!(
            se.details.as_ref().unwrap()["capability"],
            "github.issues.create"
        );
    }

    #[test]
    fn display_shows_fcp_err_string() {
        assert_eq!(
            format!("{}", FcpErrorCode::FcpErrRateLimited),
            "FCP_ERR_RATE_LIMITED"
        );
        assert_eq!(
            format!("{}", FcpErrorCode::FcpErrInternal),
            "FCP_ERR_INTERNAL"
        );
    }

    #[test]
    fn serde_round_trip() {
        let code = FcpErrorCode::FcpErrRateLimited;
        let json = serde_json::to_string(&code).unwrap();
        let parsed: FcpErrorCode = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, code);
    }

    #[test]
    fn category_tags_are_valid_identifiers() {
        let categories = [
            FwcErrorCategory::Parse,
            FwcErrorCategory::Validation,
            FwcErrorCategory::Auth,
            FwcErrorCategory::RateLimit,
            FwcErrorCategory::Policy,
            FwcErrorCategory::Connector,
            FwcErrorCategory::Transport,
            FwcErrorCategory::External,
            FwcErrorCategory::Resource,
            FwcErrorCategory::Internal,
        ];
        for cat in &categories {
            let tag = cat.tag();
            assert!(
                tag.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "Invalid category tag: {}",
                tag
            );
        }
    }

    #[test]
    fn every_fcp_error_variant_classifies() {
        // Ensure classify_fcp_error covers all FcpError variants
        let test_errors: Vec<fcp_core::FcpError> = vec![
            fcp_core::FcpError::InvalidRequest {
                code: 1001,
                message: "bad".into(),
            },
            fcp_core::FcpError::MalformedFrame {
                code: 1002,
                message: "bad".into(),
            },
            fcp_core::FcpError::MissingField { field: "x".into() },
            fcp_core::FcpError::ChecksumMismatch,
            fcp_core::FcpError::VersionMismatch {
                expected: "2".into(),
                actual: "1".into(),
            },
            fcp_core::FcpError::Unauthorized {
                code: 2001,
                message: "bad".into(),
            },
            fcp_core::FcpError::TokenExpired,
            fcp_core::FcpError::InvalidSignature,
            fcp_core::FcpError::CapabilityDenied {
                capability: "x".into(),
                reason: "no".into(),
            },
            fcp_core::FcpError::RateLimited {
                retry_after_ms: 1000,
                violation: None,
            },
            fcp_core::FcpError::OperationNotGranted {
                operation: "x".into(),
            },
            fcp_core::FcpError::ResourceNotAllowed {
                resource: "x".into(),
            },
            fcp_core::FcpError::ZoneViolation {
                source_zone: "a".into(),
                target_zone: "b".into(),
                message: "no".into(),
            },
            fcp_core::FcpError::TaintViolation {
                origin_zone: "a".into(),
                target_zone: "b".into(),
                capability: "x".into(),
            },
            fcp_core::FcpError::ElevationRequired {
                capability: "x".into(),
                ttl_seconds: None,
            },
            fcp_core::FcpError::ConnectorUnavailable {
                code: 5001,
                message: "down".into(),
            },
            fcp_core::FcpError::NotConfigured,
            fcp_core::FcpError::NotHandshaken,
            fcp_core::FcpError::HealthCheckFailed {
                reason: "bad".into(),
            },
            fcp_core::FcpError::StreamingNotSupported,
            fcp_core::FcpError::ResourceNotFound {
                resource: "x".into(),
            },
            fcp_core::FcpError::ResourceExhausted {
                resource: "x".into(),
            },
            fcp_core::FcpError::BudgetExceeded {
                metric: fcp_core::UsageMetricKind::Requests,
                used: 100,
                limit: 50,
                window_seconds: 60,
            },
            fcp_core::FcpError::Conflict {
                message: "dup".into(),
            },
            fcp_core::FcpError::External {
                service: "github".into(),
                message: "500".into(),
                status_code: Some(500),
                retryable: true,
                retry_after: None,
            },
            fcp_core::FcpError::UpstreamTimeout {
                service: "github".into(),
            },
            fcp_core::FcpError::DependencyUnavailable {
                service: "redis".into(),
            },
            fcp_core::FcpError::Internal {
                message: "panic".into(),
            },
        ];

        for err in &test_errors {
            let code = classify_fcp_error(err);
            // Just verify it doesn't panic and returns a valid code
            assert!(
                code.as_str().starts_with("FCP_ERR_"),
                "classify({:?}) returned invalid code: {}",
                err,
                code.as_str()
            );
        }
    }
}
