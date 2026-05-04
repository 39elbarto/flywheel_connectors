//! Google Meet-specific error types.

use std::time::Duration;

use fcp_prelude::FcpError;
use thiserror::Error;

/// Google Meet-specific errors.
#[derive(Error, Debug)]
pub enum GoogleMeetError {
    /// HTTP request failed.
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Google Meet API returned an error.
    #[error("Google Meet API error: {message} (code: {code})")]
    Api {
        /// HTTP-like error code.
        code: u32,
        /// Error message.
        message: String,
    },

    /// Connector configuration is invalid.
    #[error("Invalid Google Meet configuration: {message}")]
    InvalidConfig {
        /// Error message.
        message: String,
    },

    /// Rate limited.
    #[error("Rate limited, retry after {retry_after_secs}s")]
    RateLimited {
        /// Suggested retry delay in seconds.
        retry_after_secs: u64,
    },

    /// Invalid or expired token.
    #[error("Invalid or expired Google Meet credentials")]
    Unauthorized,

    /// Resource not found.
    #[error("Google Meet resource not found: {resource}")]
    ResourceNotFound {
        /// Resource identifier.
        resource: String,
    },
}

impl GoogleMeetError {
    /// Check whether this error is retryable.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::RateLimited { .. } => true,
            Self::Api { code, .. } => matches!(code, 408 | 429 | 500 | 502 | 503 | 504),
            _ => false,
        }
    }

    /// Suggested retry delay.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after_secs } => Some(Duration::from_secs(*retry_after_secs)),
            _ => None,
        }
    }

    /// Convert to an FCP error.
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Http(error) => FcpError::External {
                service: "google-meet".into(),
                message: error.to_string(),
                status_code: error.status().map(|status| status.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Json(error) => FcpError::Internal {
                message: format!("JSON error: {error}"),
            },
            Self::InvalidConfig { message } => FcpError::InvalidRequest {
                code: 1003,
                message: message.clone(),
            },
            Self::Api { code, message } => match *code {
                401 => FcpError::Unauthorized {
                    code: 2001,
                    message: "Invalid or insufficient Google Meet credentials".into(),
                },
                403 => FcpError::Unauthorized {
                    code: 2003,
                    message: format!(
                        "Google Meet denied the request; check scopes, preview enrollment, or workspace policy: {message}"
                    ),
                },
                404 => FcpError::ResourceNotFound {
                    resource: message.clone(),
                },
                429 => FcpError::RateLimited {
                    retry_after_ms: 60_000,
                    violation: None,
                },
                _ => FcpError::External {
                    service: "google-meet".into(),
                    message: message.clone(),
                    status_code: Some((*code).try_into().unwrap_or(500)),
                    retryable: self.is_retryable(),
                    retry_after: self.retry_after(),
                },
            },
            Self::RateLimited { retry_after_secs } => FcpError::RateLimited {
                retry_after_ms: retry_after_secs * 1000,
                violation: None,
            },
            Self::Unauthorized => FcpError::Unauthorized {
                code: 2001,
                message: "Invalid or expired Google Meet credentials".into(),
            },
            Self::ResourceNotFound { resource } => FcpError::ResourceNotFound {
                resource: resource.clone(),
            },
        }
    }
}

/// Result type for Google Meet operations.
pub type GoogleMeetResult<T> = Result<T, GoogleMeetError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retryable_classification_matches_http_shape() {
        assert!(
            GoogleMeetError::RateLimited {
                retry_after_secs: 5
            }
            .is_retryable()
        );
        assert!(
            GoogleMeetError::Api {
                code: 503,
                message: "unavailable".to_string()
            }
            .is_retryable()
        );
        assert!(
            !GoogleMeetError::Api {
                code: 403,
                message: "forbidden".to_string()
            }
            .is_retryable()
        );
    }

    #[test]
    fn forbidden_maps_to_actionable_auth_error() {
        let fcp = GoogleMeetError::Api {
            code: 403,
            message: "accessNotConfigured".to_string(),
        }
        .to_fcp_error();
        assert!(
            matches!(fcp, FcpError::Unauthorized { code: 2003, message } if message.contains("preview"))
        );
    }
}
