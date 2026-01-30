//! Twitter-specific error types.

use std::time::Duration;

use fcp_core::FcpError;
use thiserror::Error;

/// Twitter-specific errors.
#[derive(Error, Debug)]
pub enum TwitterError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// OAuth signature generation failed
    #[error("OAuth error: {0}")]
    OAuth(String),

    /// Twitter API returned an error
    #[error("Twitter API error {status}: {message}")]
    Api {
        status: u16,
        message: String,
        error_code: Option<i32>,
        retry_after: Option<u64>,
    },

    /// Rate limited
    #[error("Rate limited, retry after {retry_after} seconds")]
    RateLimited { retry_after: u64 },

    /// Stream error
    #[error("Stream error: {0}")]
    Stream(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Not configured
    #[error("Connector not configured")]
    NotConfigured,
}

impl TwitterError {
    /// Check if this error is retryable.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) => true,
            Self::Api { status, .. } => *status >= 500 || *status == 429 || *status == 503,
            Self::RateLimited { .. } => true,
            Self::Stream(_) => true,
            _ => false,
        }
    }

    /// Get the suggested retry delay.
    #[must_use]
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after } => Some(Duration::from_secs(*retry_after)),
            Self::Api { retry_after, .. } => retry_after.map(Duration::from_secs),
            _ => None,
        }
    }

    /// Convert to FCP error.
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Http(e) => FcpError::External {
                service: "twitter".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
            Self::OAuth(msg) => FcpError::Unauthorized {
                code: 2001,
                message: format!("OAuth error: {msg}"),
            },
            Self::Api {
                status,
                message,
                retry_after,
                ..
            } => {
                if *status == 429 {
                    FcpError::RateLimited {
                        retry_after_ms: retry_after.unwrap_or(60) * 1000,
                        violation: None,
                    }
                } else if *status == 401 {
                    FcpError::Unauthorized {
                        code: 2001,
                        message: message.clone(),
                    }
                } else if *status == 403 {
                    FcpError::CapabilityDenied {
                        capability: "twitter.api".into(),
                        reason: message.clone(),
                    }
                } else {
                    FcpError::External {
                        service: "twitter".into(),
                        message: message.clone(),
                        status_code: Some(*status),
                        retryable: self.is_retryable(),
                        retry_after: self.retry_after(),
                    }
                }
            }
            Self::RateLimited { retry_after } => FcpError::RateLimited {
                retry_after_ms: retry_after * 1000,
                violation: None,
            },
            Self::Stream(msg) => FcpError::ConnectorUnavailable {
                code: 5001,
                message: format!("Twitter stream error: {msg}"),
            },
            Self::Config(msg) => FcpError::ConnectorUnavailable {
                code: 5001,
                message: format!("Configuration error: {msg}"),
            },
            Self::NotConfigured => FcpError::NotConfigured,
        }
    }
}

/// Result type for Twitter operations.
pub type TwitterResult<T> = Result<T, TwitterError>;

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_core::FcpError;

    #[test]
    fn test_api_error_maps_to_capability_denied() {
        let err = TwitterError::Api {
            status: 403,
            message: "forbidden".into(),
            error_code: None,
            retry_after: None,
        };

        let fcp = err.to_fcp_error();
        assert!(matches!(
            fcp,
            FcpError::CapabilityDenied {
                capability,
                reason
            } if capability == "twitter.api" && reason == "forbidden"
        ));
    }

    #[test]
    fn test_api_error_maps_to_unauthorized() {
        let err = TwitterError::Api {
            status: 401,
            message: "unauthorized".into(),
            error_code: None,
            retry_after: None,
        };

        let fcp = err.to_fcp_error();
        assert!(matches!(
            fcp,
            FcpError::Unauthorized { code: 2001, message }
                if message == "unauthorized"
        ));
    }

    #[test]
    fn test_api_error_maps_to_rate_limited() {
        let err = TwitterError::Api {
            status: 429,
            message: "rate limited".into(),
            error_code: None,
            retry_after: Some(5),
        };

        let fcp = err.to_fcp_error();
        assert!(matches!(
            fcp,
            FcpError::RateLimited {
                retry_after_ms: 5000,
                violation: None
            }
        ));
    }

    #[test]
    fn test_api_error_maps_to_external() {
        let err = TwitterError::Api {
            status: 500,
            message: "server error".into(),
            error_code: None,
            retry_after: None,
        };

        let fcp = err.to_fcp_error();
        assert!(matches!(
            fcp,
            FcpError::External {
                service,
                message,
                status_code: Some(500),
                retryable: true,
                retry_after: None
            } if service == "twitter" && message == "server error"
        ));
    }
}
