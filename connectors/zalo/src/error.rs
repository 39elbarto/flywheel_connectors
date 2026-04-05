//! Zalo connector error types and FCP error mapping.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_core::FcpError;
use fcp_sdk::migration::ConnectorErrorMapping;

/// Result alias for Zalo connector operations.
pub type ZaloResult<T> = Result<T, ZaloError>;

/// Zalo connector errors.
#[derive(Debug, thiserror::Error)]
pub enum ZaloError {
    /// HTTP transport error.
    #[error("HTTP transport error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization error.
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    /// Zalo API returned an error response.
    #[error("Zalo API error ({status_code}): {message}")]
    Api { status_code: u16, message: String },

    /// Rate limited by Zalo API.
    #[error("Rate limited (retry after {retry_after_ms}ms)")]
    RateLimited { retry_after_ms: u64 },

    /// Connector not configured.
    #[error("Connector not configured: {0}")]
    NotConfigured(String),

    /// Async operation error (timeout, cancellation).
    #[error("Async error: {0}")]
    Async(String),

    /// Invalid input (bad user ID, path traversal, etc.).
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Webhook verification failure.
    #[error("Webhook error: {0}")]
    Webhook(String),
}

impl ZaloError {
    /// Whether this error is retryable.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http(e) => e.is_timeout() || e.is_connect(),
            Self::RateLimited { .. } => true,
            Self::Api { status_code, .. } => {
                matches!(status_code, 500 | 502 | 503 | 504 | 429)
            }
            Self::Json(_)
            | Self::NotConfigured(_)
            | Self::Async(_)
            | Self::InvalidInput(_)
            | Self::Webhook(_) => false,
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
            Self::Http(e) => FcpError::External {
                service: "zalo".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON parse error: {e}"),
            },
            Self::Api {
                status_code,
                message,
            } => FcpError::External {
                service: "zalo".into(),
                message: format!("Zalo API error {status_code}: {message}"),
                status_code: Some(*status_code),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::RateLimited { retry_after_ms } => FcpError::RateLimited {
                retry_after_ms: *retry_after_ms,
                violation: None,
            },
            Self::NotConfigured(msg) => FcpError::InvalidRequest {
                code: 1001,
                message: format!("Not configured: {msg}"),
            },
            Self::Async(msg) => FcpError::Internal {
                message: format!("Async error: {msg}"),
            },
            Self::InvalidInput(msg) => FcpError::InvalidRequest {
                code: 1005,
                message: msg.clone(),
            },
            Self::Webhook(msg) => FcpError::InvalidRequest {
                code: 1007,
                message: format!("Webhook error: {msg}"),
            },
        }
    }
}

impl ConnectorErrorMapping for ZaloError {
    fn from_async_error(error: AsyncError) -> Self {
        match error {
            AsyncError::Timeout { timeout_ms } => {
                Self::Async(format!("request deadline exceeded after {timeout_ms}ms"))
            }
            AsyncError::Cancelled => Self::Async("operation cancelled".into()),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limited_is_retryable() {
        let err = ZaloError::RateLimited {
            retry_after_ms: 5_000,
        };
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn not_configured_is_not_retryable() {
        let err = ZaloError::NotConfigured("missing access token".into());
        assert!(!err.is_retryable());
        assert!(err.retry_after().is_none());
    }

    #[test]
    fn api_server_error_is_retryable() {
        let err = ZaloError::Api {
            status_code: 503,
            message: "Service unavailable".into(),
        };
        assert!(err.is_retryable());

        let terminal = ZaloError::Api {
            status_code: 400,
            message: "Bad request".into(),
        };
        assert!(!terminal.is_retryable());
    }

    #[test]
    fn rate_limited_maps_to_fcp_rate_limited() {
        let err = ZaloError::RateLimited {
            retry_after_ms: 3_000,
        };
        let fcp = ConnectorErrorMapping::to_fcp_error(&err);
        match fcp {
            FcpError::RateLimited {
                retry_after_ms,
                violation,
            } => {
                assert_eq!(retry_after_ms, 3_000);
                assert!(violation.is_none());
            }
            other => panic!("Expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn webhook_error_maps_to_invalid_request() {
        let err = ZaloError::Webhook("invalid signature".into());
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1007);
                assert!(message.contains("invalid signature"));
            }
            other => panic!("Expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn not_configured_maps_to_invalid_request() {
        let err = ZaloError::NotConfigured("missing access token".into());
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1001);
                assert!(message.contains("missing access token"));
            }
            other => panic!("Expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn async_timeout_mapping() {
        let err = ZaloError::from_async_error(AsyncError::Timeout { timeout_ms: 2_000 });
        assert_eq!(
            err.to_string(),
            "Async error: request deadline exceeded after 2000ms"
        );
        assert!(!err.is_retryable());
    }

    #[test]
    fn async_cancelled_mapping() {
        let err = ZaloError::from_async_error(AsyncError::Cancelled);
        assert!(matches!(err, ZaloError::Async(_)));
        assert!(err.to_string().contains("cancelled"));
    }

    #[test]
    fn json_error_maps_to_internal() {
        let json_err: serde_json::Error = serde_json::from_str::<String>("not json").unwrap_err();
        let err = ZaloError::Json(json_err);
        assert!(!err.is_retryable());
        let fcp = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp, FcpError::Internal { .. }));
    }

    #[test]
    fn http_error_maps_to_external() {
        let err = ZaloError::Http(
            reqwest::Client::new()
                .get("://invalid")
                .build()
                .unwrap_err(),
        );
        let fcp = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp, FcpError::External { service, .. } if service == "zalo"));
    }

    #[test]
    fn invalid_input_not_retryable() {
        let err = ZaloError::InvalidInput("bad user id".into());
        assert!(!err.is_retryable());
        let fcp = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn error_display_format() {
        let err = ZaloError::Api {
            status_code: 404,
            message: "User not found".into(),
        };
        let display = format!("{err}");
        assert!(display.contains("Zalo API error"));
        assert!(display.contains("404"));
    }
}
