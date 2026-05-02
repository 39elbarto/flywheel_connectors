//! Signal connector error types.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_sdk::migration::ConnectorErrorMapping;
use thiserror::Error;

/// Signal connector errors.
#[derive(Error, Debug)]
pub enum SignalError {
    /// The signal-cli bridge process / REST daemon is not running.
    #[error("Signal bridge not running")]
    BridgeNotRunning,

    /// Timed out waiting for signal-cli bridge response.
    #[error("Signal bridge timeout after {timeout_ms}ms")]
    BridgeTimeout { timeout_ms: u64 },

    /// signal-cli bridge returned an error.
    #[error("Signal bridge error (exit {exit_code}): {stderr}")]
    BridgeError { exit_code: i32, stderr: String },

    /// HTTP transport error.
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Authentication / authorization error.
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    /// Invalid phone number format.
    #[error("Invalid phone number: {0}")]
    InvalidPhoneNumber(String),

    /// Attachment handling error.
    #[error("Attachment error: {0}")]
    AttachmentError(String),

    /// Group not found.
    #[error("Group not found: {0}")]
    GroupNotFound(String),

    /// Rate limited by Signal service.
    #[error("Rate limited, retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(String),

    /// Runtime/async error.
    #[error("Async runtime error: {0}")]
    Async(String),
}

impl SignalError {
    /// Whether this error is retryable.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_)
            | Self::RateLimited { .. }
            | Self::Async(_)
            | Self::BridgeTimeout { .. } => true,
            Self::BridgeNotRunning
            | Self::BridgeError { .. }
            | Self::Json(_)
            | Self::Unauthorized(_)
            | Self::InvalidPhoneNumber(_)
            | Self::AttachmentError(_)
            | Self::GroupNotFound(_)
            | Self::Config(_) => false,
        }
    }

    /// Suggested retry-after delay.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after_ms } => Some(Duration::from_millis(*retry_after_ms)),
            _ => None,
        }
    }

    /// Convert to FCP error taxonomy.
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::BridgeNotRunning => FcpError::External {
                service: "signal".into(),
                message: "Signal bridge is not running".into(),
                status_code: None,
                retryable: false,
                retry_after: None,
            },
            Self::BridgeTimeout { timeout_ms } => FcpError::External {
                service: "signal".into(),
                message: format!("Signal bridge timed out after {timeout_ms}ms"),
                status_code: None,
                retryable: true,
                retry_after: None,
            },
            Self::BridgeError { exit_code, stderr } => FcpError::External {
                service: "signal".into(),
                message: format!("Bridge error (exit {exit_code}): {stderr}"),
                status_code: None,
                retryable: false,
                retry_after: None,
            },
            Self::Http(e) => FcpError::External {
                service: "signal".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: true,
                retry_after: None,
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
            Self::Unauthorized(msg) => FcpError::Unauthorized {
                code: 2001,
                message: msg.clone(),
            },
            Self::InvalidPhoneNumber(msg) => FcpError::InvalidRequest {
                code: 1005,
                message: format!("Invalid phone number: {msg}"),
            },
            Self::AttachmentError(msg) => FcpError::InvalidRequest {
                code: 1006,
                message: format!("Attachment error: {msg}"),
            },
            Self::GroupNotFound(msg) => FcpError::InvalidRequest {
                code: 1004,
                message: format!("Group not found: {msg}"),
            },
            Self::RateLimited { retry_after_ms } => FcpError::RateLimited {
                retry_after_ms: *retry_after_ms,
                violation: None,
            },
            Self::Config(msg) => FcpError::InvalidRequest {
                code: 1001,
                message: format!("Configuration error: {msg}"),
            },
            Self::Async(msg) => FcpError::Internal {
                message: format!("Async runtime error: {msg}"),
            },
        }
    }

    /// Create from signal-cli REST API error response and HTTP status.
    #[must_use]
    pub fn from_api_response(status: u16, body: &str) -> Self {
        match status {
            401 => Self::Unauthorized(body.to_string()),
            404 => Self::GroupNotFound(body.to_string()),
            429 => Self::RateLimited {
                retry_after_ms: 30_000,
            },
            _ => {
                if let Ok(err_resp) = serde_json::from_str::<crate::types::ApiErrorResponse>(body) {
                    Self::Config(err_resp.error.unwrap_or_else(|| format!("HTTP {status}")))
                } else {
                    Self::Config(format!("HTTP {status}: {body}"))
                }
            }
        }
    }
}

impl ConnectorErrorMapping for SignalError {
    fn from_async_error(error: AsyncError) -> Self {
        match error {
            AsyncError::Timeout { timeout_ms } => Self::BridgeTimeout { timeout_ms },
            AsyncError::Cancelled => Self::Async("Operation cancelled".into()),
            other => Self::Async(other.to_string()),
        }
    }

    fn to_fcp_error(&self) -> FcpError {
        Self::to_fcp_error(self)
    }

    fn is_retryable(&self) -> bool {
        Self::is_retryable(self)
    }

    fn retry_after(&self) -> Option<Duration> {
        Self::retry_after(self)
    }
}

pub type SignalResult<T> = Result<T, SignalError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_not_running_not_retryable() {
        let err = SignalError::BridgeNotRunning;
        assert!(!err.is_retryable());
        assert!(err.retry_after().is_none());
    }

    #[test]
    fn bridge_timeout_is_retryable() {
        let err = SignalError::BridgeTimeout { timeout_ms: 5000 };
        assert!(err.is_retryable());
        assert!(err.retry_after().is_none());
    }

    #[test]
    fn bridge_error_not_retryable() {
        let err = SignalError::BridgeError {
            exit_code: 1,
            stderr: "fatal error".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn http_error_is_retryable() {
        let err = SignalError::Http(
            reqwest::Client::new()
                .get("://invalid")
                .build()
                .unwrap_err(),
        );
        assert!(err.is_retryable());
    }

    #[test]
    fn rate_limited_is_retryable() {
        let err = SignalError::RateLimited {
            retry_after_ms: 5000,
        };
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn unauthorized_not_retryable() {
        let err = SignalError::Unauthorized("bad token".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn invalid_phone_not_retryable() {
        let err = SignalError::InvalidPhoneNumber("abc".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn attachment_error_not_retryable() {
        let err = SignalError::AttachmentError("file too large".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn group_not_found_not_retryable() {
        let err = SignalError::GroupNotFound("Z3JvdXBfaWQ=".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn config_not_retryable() {
        let err = SignalError::Config("missing phone_number".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn async_error_is_retryable() {
        let err = SignalError::Async("runtime shut down".into());
        assert!(err.is_retryable());
    }

    #[test]
    fn rate_limited_maps_to_fcp() {
        let err = SignalError::RateLimited {
            retry_after_ms: 10_000,
        };
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::RateLimited { .. }));
    }

    #[test]
    fn unauthorized_maps_to_fcp() {
        let err = SignalError::Unauthorized("denied".into());
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::Unauthorized { .. }));
    }

    #[test]
    fn config_maps_to_invalid_request() {
        let err = SignalError::Config("missing field".into());
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn json_maps_to_internal() {
        let err =
            SignalError::Json(serde_json::from_str::<serde_json::Value>("{{bad}}").unwrap_err());
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::Internal { .. }));
    }

    #[test]
    fn from_async_timeout() {
        let err = SignalError::from_async_error(AsyncError::Timeout { timeout_ms: 5000 });
        assert!(matches!(
            err,
            SignalError::BridgeTimeout { timeout_ms: 5000 }
        ));
        assert!(err.is_retryable());
    }

    #[test]
    fn from_async_cancelled() {
        let err = SignalError::from_async_error(AsyncError::Cancelled);
        assert!(matches!(err, SignalError::Async(_)));
    }

    #[test]
    fn from_async_channel_closed() {
        let err = SignalError::from_async_error(AsyncError::ChannelClosed);
        assert!(matches!(err, SignalError::Async(_)));
    }

    #[test]
    fn from_api_response_401() {
        let err = SignalError::from_api_response(401, "unauthorized");
        assert!(matches!(err, SignalError::Unauthorized(_)));
    }

    #[test]
    fn from_api_response_404() {
        let err = SignalError::from_api_response(404, "group not found");
        assert!(matches!(err, SignalError::GroupNotFound(_)));
    }

    #[test]
    fn from_api_response_429() {
        let err = SignalError::from_api_response(429, "too many requests");
        assert!(matches!(err, SignalError::RateLimited { .. }));
    }

    #[test]
    fn from_api_response_500() {
        let err = SignalError::from_api_response(500, "internal error");
        assert!(matches!(err, SignalError::Config(_)));
    }

    #[test]
    fn error_display_bridge_timeout() {
        let err = SignalError::BridgeTimeout { timeout_ms: 10_000 };
        let display = format!("{err}");
        assert!(display.contains("10000"));
    }

    #[test]
    fn error_display_bridge_error() {
        let err = SignalError::BridgeError {
            exit_code: 127,
            stderr: "command not found".into(),
        };
        let display = format!("{err}");
        assert!(display.contains("127"));
        assert!(display.contains("command not found"));
    }

    #[test]
    fn bridge_not_running_maps_to_external() {
        let err = SignalError::BridgeNotRunning;
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::External { .. }));
    }

    #[test]
    fn group_not_found_maps_to_invalid_request() {
        let err = SignalError::GroupNotFound("g1".into());
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn http_maps_to_external() {
        let err = SignalError::Http(
            reqwest::Client::new()
                .get("://invalid")
                .build()
                .unwrap_err(),
        );
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::External { .. }));
    }
}
