//! Error types for the `ZaloUser` connector.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_core::FcpError;
use fcp_sdk::migration::ConnectorErrorMapping;
use thiserror::Error;

/// `ZaloUser` connector errors.
#[derive(Error, Debug)]
pub enum ZaloUserError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// API error response
    #[error("ZaloUser API error ({status_code}): {message}")]
    Api { status_code: u16, message: String },

    /// Rate limited
    #[error("Rate limited, retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },

    /// Not configured
    #[error("Connector not configured")]
    NotConfigured,
}

impl ConnectorErrorMapping for ZaloUserError {
    fn from_async_error(error: AsyncError) -> Self {
        match error {
            AsyncError::Timeout { timeout_ms } => Self::Api {
                status_code: 408,
                message: format!("deadline exceeded after {timeout_ms}ms"),
            },
            AsyncError::Cancelled => Self::Api {
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
        match self {
            Self::Http(e) => {
                if e.is_timeout() {
                    FcpError::UpstreamTimeout {
                        service: "zalouser".into(),
                    }
                } else {
                    FcpError::External {
                        service: "zalouser".into(),
                        message: e.to_string(),
                        status_code: e.status().map(|s| s.as_u16()),
                        retryable: self.is_retryable(),
                        retry_after: None,
                    }
                }
            }
            Self::Api {
                status_code,
                message,
            } => {
                if *status_code == 429 {
                    FcpError::RateLimited {
                        retry_after_ms: 30_000,
                        violation: None,
                    }
                } else {
                    FcpError::External {
                        service: "zalouser".into(),
                        message: message.clone(),
                        status_code: Some(*status_code),
                        retryable: self.is_retryable(),
                        retry_after: self.retry_after(),
                    }
                }
            }
            Self::RateLimited { retry_after_ms } => FcpError::RateLimited {
                retry_after_ms: *retry_after_ms,
                violation: None,
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
            Self::NotConfigured => FcpError::NotConfigured,
        }
    }

    fn is_retryable(&self) -> bool {
        match self {
            Self::Http(e) => e.is_connect() || e.is_timeout(),
            Self::RateLimited { .. } => true,
            Self::Api { status_code, .. } => matches!(status_code, 429 | 500..=599),
            _ => false,
        }
    }

    fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after_ms } => {
                Some(Duration::from_millis(*retry_after_ms))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_error_maps_to_external() {
        let err = ZaloUserError::Api {
            status_code: 500,
            message: "Internal Server Error".into(),
        };
        assert!(matches!(err.to_fcp_error(), FcpError::External { .. }));
        assert!(err.is_retryable());
    }

    #[test]
    fn rate_limited_maps_correctly() {
        let err = ZaloUserError::RateLimited {
            retry_after_ms: 5000,
        };
        assert!(matches!(err.to_fcp_error(), FcpError::RateLimited { .. }));
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(Duration::from_millis(5000)));
    }

    #[test]
    fn not_configured_maps_correctly() {
        let err = ZaloUserError::NotConfigured;
        assert!(matches!(err.to_fcp_error(), FcpError::NotConfigured));
        assert!(!err.is_retryable());
    }

    #[test]
    fn json_error_maps_to_internal() {
        let json_err: serde_json::Error = serde_json::from_str::<String>("invalid").unwrap_err();
        let err = ZaloUserError::Json(json_err);
        assert!(matches!(err.to_fcp_error(), FcpError::Internal { .. }));
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_429_maps_to_rate_limited() {
        let err = ZaloUserError::Api {
            status_code: 429,
            message: "Too Many Requests".into(),
        };
        assert!(matches!(err.to_fcp_error(), FcpError::RateLimited { .. }));
    }

    #[test]
    fn from_async_timeout() {
        let err = ZaloUserError::from_async_error(AsyncError::Timeout { timeout_ms: 5000 });
        assert!(matches!(
            err,
            ZaloUserError::Api {
                status_code: 408,
                ..
            }
        ));
    }

    #[test]
    fn from_async_cancelled() {
        let err = ZaloUserError::from_async_error(AsyncError::Cancelled);
        assert!(matches!(
            err,
            ZaloUserError::Api {
                status_code: 0,
                ..
            }
        ));
    }

    #[test]
    fn display_formats() {
        let err = ZaloUserError::Api {
            status_code: 404,
            message: "Not Found".into(),
        };
        assert_eq!(
            err.to_string(),
            "ZaloUser API error (404): Not Found"
        );
    }

    #[test]
    fn api_502_is_retryable() {
        let err = ZaloUserError::Api {
            status_code: 502,
            message: "Bad Gateway".into(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_400_is_not_retryable() {
        let err = ZaloUserError::Api {
            status_code: 400,
            message: "Bad Request".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn not_configured_has_no_retry_after() {
        let err = ZaloUserError::NotConfigured;
        assert_eq!(err.retry_after(), None);
    }
}
