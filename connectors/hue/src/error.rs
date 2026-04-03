//! Error types for the `Hue` connector.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_core::FcpError;
use fcp_sdk::migration::ConnectorErrorMapping;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HueError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Hue API error ({status}): {message}")]
    Api { status: u16, message: String },

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Rate limited
    #[error("Rate limited, retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },

    /// Not configured
    #[error("Connector not configured")]
    NotConfigured,
}

pub type HueResult<T> = Result<T, HueError>;

impl ConnectorErrorMapping for HueError {
    fn from_async_error(error: AsyncError) -> Self {
        match error {
            AsyncError::Timeout { timeout_ms } => Self::Api {
                status: 408,
                message: format!("deadline exceeded after {timeout_ms}ms"),
            },
            AsyncError::Cancelled => Self::Api {
                status: 0,
                message: "request cancelled".into(),
            },
            other => Self::Api {
                status: 0,
                message: other.to_string(),
            },
        }
    }

    fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Config(message) => FcpError::InvalidRequest {
                code: 1003,
                message: message.clone(),
            },
            Self::Http(error) if error.is_timeout() => FcpError::UpstreamTimeout {
                service: "hue".into(),
            },
            Self::Http(error) => FcpError::External {
                service: "hue".into(),
                message: error.to_string(),
                status_code: error.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: None,
            },
            Self::Api { status, message } => {
                if *status == 429 {
                    FcpError::RateLimited {
                        retry_after_ms: 30_000,
                        violation: None,
                    }
                } else {
                    FcpError::External {
                        service: "hue".into(),
                        message: message.clone(),
                        status_code: Some(*status),
                        retryable: self.is_retryable(),
                        retry_after: self.retry_after(),
                    }
                }
            }
            Self::RateLimited { retry_after_ms } => FcpError::RateLimited {
                retry_after_ms: *retry_after_ms,
                violation: None,
            },
            Self::Json(error) => FcpError::Internal {
                message: format!("Failed to decode Hue response: {error}"),
            },
            Self::NotConfigured => FcpError::NotConfigured,
        }
    }

    fn is_retryable(&self) -> bool {
        match self {
            Self::Http(e) => e.is_connect() || e.is_timeout(),
            Self::RateLimited { .. } => true,
            Self::Api { status, .. } => matches!(status, 429 | 500..=599),
            Self::Config(_) | Self::Json(_) | Self::NotConfigured => false,
        }
    }

    fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after_ms } => Some(Duration::from_millis(*retry_after_ms)),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_error_maps_to_external() {
        let err = HueError::Api {
            status: 500,
            message: "Internal Server Error".into(),
        };
        assert!(matches!(err.to_fcp_error(), FcpError::External { .. }));
        assert!(err.is_retryable());
    }

    #[test]
    fn rate_limited_maps_correctly() {
        let err = HueError::RateLimited {
            retry_after_ms: 5000,
        };
        assert!(matches!(err.to_fcp_error(), FcpError::RateLimited { .. }));
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(Duration::from_millis(5000)));
    }

    #[test]
    fn not_configured_maps_correctly() {
        let err = HueError::NotConfigured;
        assert!(matches!(err.to_fcp_error(), FcpError::NotConfigured));
        assert!(!err.is_retryable());
    }

    #[test]
    fn json_error_maps_to_internal() {
        let json_err: serde_json::Error = serde_json::from_str::<String>("invalid").unwrap_err();
        let err = HueError::Json(json_err);
        assert!(matches!(err.to_fcp_error(), FcpError::Internal { .. }));
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_429_maps_to_rate_limited() {
        let err = HueError::Api {
            status: 429,
            message: "Too Many Requests".into(),
        };
        assert!(matches!(err.to_fcp_error(), FcpError::RateLimited { .. }));
    }

    #[test]
    fn from_async_timeout() {
        let err = HueError::from_async_error(AsyncError::Timeout { timeout_ms: 5000 });
        assert!(matches!(err, HueError::Api { status: 408, .. }));
    }

    #[test]
    fn from_async_cancelled() {
        let err = HueError::from_async_error(AsyncError::Cancelled);
        assert!(matches!(err, HueError::Api { status: 0, .. }));
    }

    #[test]
    fn display_formats() {
        let err = HueError::Api {
            status: 404,
            message: "Not Found".into(),
        };
        assert_eq!(err.to_string(), "Hue API error (404): Not Found");
    }

    #[test]
    fn config_error_maps_to_invalid_request() {
        let err = HueError::Config("bad config".into());
        assert!(matches!(
            err.to_fcp_error(),
            FcpError::InvalidRequest { .. }
        ));
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_503_is_retryable() {
        let err = HueError::Api {
            status: 503,
            message: "Service Unavailable".into(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_400_is_not_retryable() {
        let err = HueError::Api {
            status: 400,
            message: "Bad Request".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn not_configured_has_no_retry_after() {
        let err = HueError::NotConfigured;
        assert_eq!(err.retry_after(), None);
    }
}
