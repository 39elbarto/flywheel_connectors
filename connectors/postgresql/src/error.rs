//! `PostgreSQL`-specific error types.

use std::time::Duration;

use fcp_core::FcpError;
use thiserror::Error;

/// Result alias for `PostgreSQL` operations.
pub type PostgresResult<T> = Result<T, PostgresError>;

/// `PostgreSQL`-specific errors.
#[derive(Error, Debug)]
pub enum PostgresError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// `PostgreSQL` connection error
    #[error("PostgreSQL connection error: {0}")]
    Connection(String),

    /// `PostgreSQL` authentication error
    #[error("PostgreSQL authentication error: {0}")]
    Auth(String),

    /// `PostgreSQL` query error
    #[error("PostgreSQL query error: {0}")]
    Query(String),

    /// `PostgreSQL` transaction error
    #[error("PostgreSQL transaction error: {0}")]
    Transaction(String),

    /// `PostgreSQL` schema error
    #[error("PostgreSQL schema error: {0}")]
    Schema(String),

    /// `PostgreSQL` constraint violation
    #[error("PostgreSQL constraint violation: {0}")]
    ConstraintViolation(String),

    /// `PostgreSQL` timeout
    #[error("PostgreSQL timeout: {0}")]
    Timeout(String),

    /// `PostgreSQL` permission denied
    #[error("PostgreSQL permission denied: {0}")]
    PermissionDenied(String),

    /// Rate limited (429)
    #[error("PostgreSQL rate limited (retry after {retry_after_ms}ms)")]
    RateLimited { retry_after_ms: u64 },

    /// API error with status code
    #[error("PostgreSQL API error ({status_code}): {message}")]
    Api { status_code: u16, message: String },
}

impl PostgresError {
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
                service: "postgresql".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
            Self::Connection(msg) => FcpError::External {
                service: "postgresql".into(),
                message: msg.clone(),
                status_code: None,
                retryable: true,
                retry_after: None,
            },
            Self::Auth(msg) => FcpError::External {
                service: "postgresql".into(),
                message: msg.clone(),
                status_code: Some(401),
                retryable: false,
                retry_after: None,
            },
            Self::Query(msg) => FcpError::External {
                service: "postgresql".into(),
                message: msg.clone(),
                status_code: None,
                retryable: false,
                retry_after: None,
            },
            Self::Transaction(msg) => FcpError::External {
                service: "postgresql".into(),
                message: msg.clone(),
                status_code: None,
                retryable: false,
                retry_after: None,
            },
            Self::Schema(msg) => FcpError::External {
                service: "postgresql".into(),
                message: msg.clone(),
                status_code: None,
                retryable: false,
                retry_after: None,
            },
            Self::ConstraintViolation(msg) => FcpError::External {
                service: "postgresql".into(),
                message: msg.clone(),
                status_code: Some(409),
                retryable: false,
                retry_after: None,
            },
            Self::Timeout(msg) => FcpError::External {
                service: "postgresql".into(),
                message: msg.clone(),
                status_code: None,
                retryable: true,
                retry_after: None,
            },
            Self::PermissionDenied(msg) => FcpError::External {
                service: "postgresql".into(),
                message: msg.clone(),
                status_code: Some(403),
                retryable: false,
                retry_after: None,
            },
            Self::RateLimited { retry_after_ms } => FcpError::External {
                service: "postgresql".into(),
                message: format!("Rate limited, retry after {retry_after_ms}ms"),
                status_code: Some(429),
                retryable: true,
                retry_after: self.retry_after(),
            },
            Self::Api {
                status_code,
                message,
            } => FcpError::External {
                service: "postgresql".into(),
                message: message.clone(),
                status_code: Some(*status_code),
                retryable: self.is_retryable(),
                retry_after: None,
            },
        }
    }
}
