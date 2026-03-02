//! YouTube-specific error types.

use std::time::Duration;

use fcp_core::FcpError;
use thiserror::Error;

/// YouTube-specific errors.
#[derive(Error, Debug)]
pub enum YouTubeError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// YouTube API returned an error
    #[error("YouTube API error: {message} (status {status_code:?})")]
    Api {
        message: String,
        status_code: Option<u16>,
    },

    /// Rate limited / quota exceeded
    #[error("Rate limited, retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },

    /// Quota exceeded (daily limit)
    #[error("YouTube API quota exceeded")]
    QuotaExceeded,

    /// Invalid or expired API key / OAuth token
    #[error("Invalid or expired YouTube credentials")]
    Unauthorized,

    /// Resource not found (404)
    #[error("Resource not found: {resource}")]
    NotFound { resource: String },

    /// Forbidden (comments disabled, etc.)
    #[error("Forbidden: {message}")]
    Forbidden { message: String },
}

impl YouTubeError {
    /// Check if this error is retryable.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) => true,
            Self::RateLimited { .. } => true,
            Self::Api { status_code, .. } => matches!(status_code, Some(500..=599 | 429)),
            _ => false,
        }
    }

    /// Get the suggested retry delay.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after_ms } => Some(Duration::from_millis(*retry_after_ms)),
            _ => None,
        }
    }

    /// Convert to FCP error.
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Http(e) => FcpError::External {
                service: "youtube".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Api {
                message,
                status_code,
            } => {
                if *status_code == Some(401) {
                    FcpError::Unauthorized {
                        code: 2001,
                        message: "Invalid or expired YouTube credentials".into(),
                    }
                } else if *status_code == Some(403) {
                    FcpError::Unauthorized {
                        code: 2001,
                        message: message.clone(),
                    }
                } else if *status_code == Some(429) {
                    FcpError::RateLimited {
                        retry_after_ms: 60_000,
                        violation: None,
                    }
                } else {
                    FcpError::External {
                        service: "youtube".into(),
                        message: message.clone(),
                        status_code: *status_code,
                        retryable: self.is_retryable(),
                        retry_after: self.retry_after(),
                    }
                }
            }
            Self::RateLimited { retry_after_ms } => FcpError::RateLimited {
                retry_after_ms: *retry_after_ms,
                violation: None,
            },
            Self::QuotaExceeded => FcpError::RateLimited {
                retry_after_ms: 86_400_000, // 24 hours
                violation: None,
            },
            Self::Unauthorized => FcpError::Unauthorized {
                code: 2001,
                message: "Invalid or expired YouTube credentials".into(),
            },
            Self::NotFound { resource } => FcpError::ResourceNotFound {
                resource: resource.clone(),
            },
            Self::Forbidden { message } => FcpError::Unauthorized {
                code: 2002,
                message: message.clone(),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
        }
    }
}

/// Result type for YouTube operations.
pub type YouTubeResult<T> = Result<T, YouTubeError>;
