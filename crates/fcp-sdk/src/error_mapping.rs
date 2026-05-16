//! Canonical connector error-mapping contract.
//!
//! Connector authors implement [`ConnectorErrorMapping`] on their connector
//! error type so retry/runtime helpers can convert `fcp-async-core` deadline,
//! cancellation, and runtime failures into both connector-specific errors and
//! the standard FCP error taxonomy.

use std::fmt;
use std::time::Duration;

use fcp_async_core::AsyncError;

use crate::FcpError;

/// Trait for mapping `AsyncError` to connector-specific error types.
///
/// Every connector must implement this to handle deadline/cancellation
/// errors from `ExecutionContext` operations.
///
/// # Example
///
/// ```ignore
/// impl ConnectorErrorMapping for MyConnectorError {
///     fn from_async_error(error: AsyncError) -> Self {
///         match error {
///             AsyncError::Timeout { timeout_ms } => Self::DeadlineExceeded {
///                 message: format!("request deadline exceeded after {timeout_ms}ms"),
///             },
///             AsyncError::Cancelled => Self::RequestCancelled,
///             other => Self::Runtime { message: other.to_string() },
///         }
///     }
///
///     fn to_fcp_error(&self) -> FcpError { /* ... */ }
/// }
/// ```
pub trait ConnectorErrorMapping: fmt::Display + fmt::Debug + Send + Sync {
    /// Map an `AsyncError` (timeout, cancellation, etc.) to this connector's error type.
    fn from_async_error(error: AsyncError) -> Self
    where
        Self: Sized;

    /// Convert this connector error to the standard `FcpError` taxonomy.
    fn to_fcp_error(&self) -> FcpError;

    /// Whether this error is retryable.
    fn is_retryable(&self) -> bool;

    /// Suggested retry-after delay, if available.
    fn retry_after(&self) -> Option<Duration> {
        None
    }
}

/// Map an `AsyncError` from context operations to a standard `FcpError`.
///
/// This is the canonical mapping for context-level errors (timeout, cancellation).
/// Connector-specific error types should delegate to this for the `AsyncError` arm.
#[must_use]
pub fn map_async_to_fcp_error(error: &AsyncError) -> FcpError {
    match error {
        AsyncError::Timeout { timeout_ms } => FcpError::External {
            service: "runtime".into(),
            message: format!("request deadline exceeded after {timeout_ms}ms"),
            status_code: Some(504),
            retryable: true,
            retry_after: None,
        },
        AsyncError::Cancelled => FcpError::External {
            service: "runtime".into(),
            message: "request cancelled".into(),
            status_code: None,
            retryable: false,
            retry_after: None,
        },
        other => FcpError::Internal {
            message: other.to_string(),
        },
    }
}
