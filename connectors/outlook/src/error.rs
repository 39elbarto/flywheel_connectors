//! Error types for the Outlook connector.

use std::time::Duration;

use fcp_core::FcpError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum OutlookError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("API error ({status_code}): {message}")]
    Api { status_code: u16, message: String },

    #[error("rate limited")]
    RateLimited { retry_after_ms: u64 },

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("not found: {0}")]
    NotFound(String),
}

pub type OutlookResult<T> = Result<T, OutlookError>;

impl OutlookError {
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Config(message) => FcpError::InvalidRequest {
                code: 1003,
                message: message.clone(),
            },
            Self::Http(error) if error.is_timeout() => FcpError::UpstreamTimeout {
                service: "outlook".into(),
            },
            Self::Http(error) => FcpError::External {
                service: "outlook".into(),
                message: error.to_string(),
                status_code: None,
                retryable: error.is_connect() || error.is_timeout(),
                retry_after: None,
            },
            Self::Api { status_code, message } => FcpError::External {
                service: "outlook".into(),
                message: message.clone(),
                status_code: Some(*status_code),
                retryable: matches!(status_code, 429 | 500 | 502 | 503 | 504),
                retry_after: None,
            },
            Self::RateLimited { retry_after_ms } => FcpError::RateLimited {
                retry_after_ms: *retry_after_ms,
                violation: None,
            },
            Self::Unauthorized(message) => FcpError::Unauthorized {
                code: 2001, message: message.clone(),
            },
            Self::NotFound(message) => FcpError::External {
                service: "outlook".into(),
                message: message.clone(),
                status_code: Some(404),
                retryable: false,
                retry_after: None,
            },
        }
    }

    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Http(_) | Self::RateLimited { .. } | Self::Api { status_code: 429 | 500 | 502 | 503 | 504, .. }
        )
    }

    #[must_use]
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after_ms } => Some(Duration::from_millis(*retry_after_ms)),
            _ => None,
        }
    }
}

impl fcp_sdk::migration::ConnectorErrorMapping for OutlookError {
    fn from_async_error(error: fcp_async_core::AsyncError) -> Self {
        match error {
            fcp_async_core::AsyncError::Timeout { timeout_ms } => Self::Api {
                status_code: 408,
                message: format!("deadline exceeded after {timeout_ms}ms"),
            },
            fcp_async_core::AsyncError::Cancelled => Self::Api {
                status_code: 0,
                message: "request cancelled".into(),
            },
            other => Self::Api {
                status_code: 0,
                message: other.to_string(),
            },
        }
    }

    fn to_fcp_error(&self) -> FcpError {
        self.to_fcp_error()
    }

    fn is_retryable(&self) -> bool {
        self.is_retryable()
    }

    fn retry_after(&self) -> Option<Duration> {
        self.retry_after()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_error_maps_to_invalid_request() {
        let err = OutlookError::Config("bad config".into());
        assert!(matches!(err.to_fcp_error(), FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn api_500_maps_to_retryable_external() {
        let err = OutlookError::Api { status_code: 500, message: "internal".into() };
        match err.to_fcp_error() {
            FcpError::External { retryable, status_code, .. } => {
                assert!(retryable);
                assert_eq!(status_code, Some(500));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn api_400_maps_to_non_retryable() {
        let err = OutlookError::Api { status_code: 400, message: "bad".into() };
        match err.to_fcp_error() {
            FcpError::External { retryable, .. } => assert!(!retryable),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_maps_to_rate_limited() {
        let err = OutlookError::RateLimited { retry_after_ms: 5000 };
        assert!(matches!(err.to_fcp_error(), FcpError::RateLimited { .. }));
    }

    #[test]
    fn unauthorized_maps_to_unauthorized() {
        let err = OutlookError::Unauthorized("invalid token".into());
        assert!(matches!(err.to_fcp_error(), FcpError::Unauthorized { .. }));
    }

    #[test]
    fn not_found_maps_to_external_404() {
        let err = OutlookError::NotFound("message not found".into());
        match err.to_fcp_error() {
            FcpError::External { status_code, retryable, .. } => {
                assert_eq!(status_code, Some(404));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_is_retryable() {
        let err = OutlookError::RateLimited { retry_after_ms: 1000 };
        assert!(err.is_retryable());
    }

    #[test]
    fn config_error_is_not_retryable() {
        assert!(!OutlookError::Config("bad".into()).is_retryable());
    }

    #[test]
    fn unauthorized_is_not_retryable() {
        assert!(!OutlookError::Unauthorized("expired".into()).is_retryable());
    }

    #[test]
    fn not_found_is_not_retryable() {
        assert!(!OutlookError::NotFound("gone".into()).is_retryable());
    }

    #[test]
    fn retry_after_returns_duration_for_rate_limited() {
        let err = OutlookError::RateLimited { retry_after_ms: 3000 };
        assert_eq!(err.retry_after(), Some(Duration::from_millis(3000)));
    }

    #[test]
    fn retry_after_returns_none_for_other_errors() {
        assert!(OutlookError::Config("bad".into()).retry_after().is_none());
    }

    #[test]
    fn error_display_config() {
        assert_eq!(
            OutlookError::Config("missing".into()).to_string(),
            "configuration error: missing"
        );
    }

    #[test]
    fn error_display_api() {
        let err = OutlookError::Api { status_code: 503, message: "down".into() };
        assert_eq!(err.to_string(), "API error (503): down");
    }

    #[test]
    fn error_display_rate_limited() {
        let err = OutlookError::RateLimited { retry_after_ms: 1000 };
        assert_eq!(err.to_string(), "rate limited");
    }

    #[test]
    fn error_display_unauthorized() {
        assert_eq!(
            OutlookError::Unauthorized("expired".into()).to_string(),
            "unauthorized: expired"
        );
    }

    #[test]
    fn error_display_not_found() {
        assert_eq!(
            OutlookError::NotFound("msg-123".into()).to_string(),
            "not found: msg-123"
        );
    }

    #[test]
    fn connector_error_mapping_from_timeout() {
        use fcp_sdk::migration::ConnectorErrorMapping;
        let err = OutlookError::from_async_error(
            fcp_async_core::AsyncError::Timeout { timeout_ms: 5000 },
        );
        assert!(matches!(err, OutlookError::Api { status_code: 408, .. }));
    }

    #[test]
    fn connector_error_mapping_from_cancelled() {
        use fcp_sdk::migration::ConnectorErrorMapping;
        let err = OutlookError::from_async_error(fcp_async_core::AsyncError::Cancelled);
        assert!(err.to_string().contains("cancelled"));
    }
}
