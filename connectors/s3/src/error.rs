//! S3-specific error types.

use std::time::Duration;

use fcp_core::FcpError;
use thiserror::Error;

/// S3-specific errors.
#[derive(Error, Debug)]
pub enum S3Error {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// S3 API returned an error
    #[error("S3 API error: {message} (code: {code})")]
    Api {
        code: String,
        message: String,
        status_code: Option<u16>,
    },

    /// Rate limited
    #[error("Rate limited")]
    RateLimited { retry_after_ms: u64 },

    /// Unauthorized (invalid credentials)
    #[error("Unauthorized")]
    Unauthorized,

    /// Object not found
    #[error("Object not found: {key}")]
    NotFound { key: String },

    /// Bucket not found
    #[error("Bucket not found: {bucket}")]
    BucketNotFound { bucket: String },
}

impl S3Error {
    /// Check if this error is retryable.
    ///
    /// Note: not `const fn` because we match on string error codes in `Api`.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) => true,
            Self::RateLimited { .. } => true,
            Self::Api { status_code, .. } => {
                matches!(status_code, Some(500..=599 | 429))
            }
            Self::Unauthorized | Self::NotFound { .. } | Self::BucketNotFound { .. } => false,
            Self::Json(_) => false,
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
                service: "s3".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Api {
                code,
                message,
                status_code,
            } => {
                if *status_code == Some(401) || *status_code == Some(403) {
                    FcpError::Unauthorized {
                        code: 2001,
                        message: "Invalid S3 credentials".into(),
                    }
                } else if *status_code == Some(429) {
                    FcpError::RateLimited {
                        retry_after_ms: 30_000,
                        violation: None,
                    }
                } else if *status_code == Some(404) {
                    FcpError::ResourceNotFound {
                        resource: message.clone(),
                    }
                } else {
                    FcpError::External {
                        service: "s3".into(),
                        message: format!("{code}: {message}"),
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
            Self::Unauthorized => FcpError::Unauthorized {
                code: 2001,
                message: "Invalid S3 credentials".into(),
            },
            Self::NotFound { key } => FcpError::ResourceNotFound {
                resource: format!("object:{key}"),
            },
            Self::BucketNotFound { bucket } => FcpError::ResourceNotFound {
                resource: format!("bucket:{bucket}"),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
        }
    }
}

/// Result type for S3 operations.
pub type S3Result<T> = Result<T, S3Error>;
