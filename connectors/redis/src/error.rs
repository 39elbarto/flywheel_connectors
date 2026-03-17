//! Redis-specific error types.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_core::FcpError;
use fcp_sdk::migration::ConnectorErrorMapping;
use thiserror::Error;

/// Result alias for Redis operations.
pub type RedisResult<T> = Result<T, RedisError>;

/// Redis-specific errors.
#[derive(Error, Debug)]
pub enum RedisError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Redis command returned an error
    #[error("Redis command error: {message}")]
    Command { message: String },

    /// Redis connection error
    #[error("Redis connection error: {0}")]
    Connection(String),

    /// Authentication failed (401)
    #[error("Authentication failed: invalid or expired API token")]
    Unauthorized,

    /// Forbidden (403)
    #[error("Forbidden: insufficient permissions")]
    Forbidden,

    /// Rate limited (429)
    #[error("Rate limited, retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },

    /// Redis API returned an error
    #[error("Redis API error ({status_code}): {message}")]
    Api { status_code: u16, message: String },

    /// Key not found
    #[error("Key not found: {key}")]
    KeyNotFound { key: String },

    /// Type mismatch
    #[error("Type mismatch: expected {expected}, got {actual}")]
    TypeMismatch { expected: String, actual: String },

    /// Timeout
    #[error("Redis timeout: {0}")]
    Timeout(String),
}

impl RedisError {
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::RateLimited { .. } | Self::Connection(_) | Self::Timeout(_) => {
                true
            }
            Self::Api { status_code, .. } => matches!(status_code, 500..=599 | 429),
            _ => false,
        }
    }

    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after_ms } => Some(Duration::from_millis(*retry_after_ms)),
            _ => None,
        }
    }

    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Http(e) => FcpError::External {
                service: "redis".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
            Self::Command { message } => FcpError::External {
                service: "redis".into(),
                message: message.clone(),
                status_code: None,
                retryable: false,
                retry_after: None,
            },
            Self::Connection(msg) => FcpError::External {
                service: "redis".into(),
                message: msg.clone(),
                status_code: None,
                retryable: true,
                retry_after: None,
            },
            Self::Unauthorized => FcpError::External {
                service: "redis".into(),
                message: "Authentication failed".into(),
                status_code: Some(401),
                retryable: false,
                retry_after: None,
            },
            Self::Forbidden => FcpError::External {
                service: "redis".into(),
                message: "Insufficient permissions".into(),
                status_code: Some(403),
                retryable: false,
                retry_after: None,
            },
            Self::RateLimited { retry_after_ms } => FcpError::External {
                service: "redis".into(),
                message: format!("Rate limited, retry after {retry_after_ms}ms"),
                status_code: Some(429),
                retryable: true,
                retry_after: self.retry_after(),
            },
            Self::Api {
                status_code,
                message,
            } => FcpError::External {
                service: "redis".into(),
                message: message.clone(),
                status_code: Some(*status_code),
                retryable: self.is_retryable(),
                retry_after: None,
            },
            Self::KeyNotFound { key } => FcpError::External {
                service: "redis".into(),
                message: format!("Key not found: {key}"),
                status_code: Some(404),
                retryable: false,
                retry_after: None,
            },
            Self::TypeMismatch { expected, actual } => FcpError::External {
                service: "redis".into(),
                message: format!("Type mismatch: expected {expected}, got {actual}"),
                status_code: None,
                retryable: false,
                retry_after: None,
            },
            Self::Timeout(msg) => FcpError::External {
                service: "redis".into(),
                message: msg.clone(),
                status_code: None,
                retryable: true,
                retry_after: None,
            },
        }
    }
}

impl ConnectorErrorMapping for RedisError {
    fn from_async_error(error: AsyncError) -> Self {
        match error {
            AsyncError::Timeout { timeout_ms } => {
                Self::Timeout(format!("deadline exceeded after {timeout_ms}ms"))
            }
            AsyncError::Cancelled => Self::Api {
                status_code: 499,
                message: "request cancelled".into(),
            },
            other => Self::Api {
                status_code: 500,
                message: other.to_string(),
            },
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
