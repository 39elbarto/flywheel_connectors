//! Browser-specific error types.

use std::time::Duration;

use fcp_core::FcpError;

/// Browser automation error.
#[derive(Debug, thiserror::Error)]
pub enum BrowserError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Browser API error: {message}")]
    Api {
        message: String,
        status_code: Option<u16>,
    },

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Timeout: {message}")]
    Timeout { message: String },
}

pub type BrowserResult<T> = Result<T, BrowserError>;

impl BrowserError {
    /// Check if this error is retryable.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::Timeout { .. } => true,
            Self::Api { status_code, .. } => matches!(status_code, Some(500..=599 | 429)),
            Self::InvalidConfig(_) | Self::Serialization(_) => false,
        }
    }

    /// Get the suggested retry delay.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::Api {
                status_code: Some(429),
                ..
            } => Some(Duration::from_secs(5)),
            _ => None,
        }
    }

    /// Convert to FCP error.
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Http(e) => FcpError::External {
                service: "browser".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Api {
                message,
                status_code,
            } => {
                if *status_code == Some(429) {
                    FcpError::RateLimited {
                        retry_after_ms: 5_000,
                        violation: None,
                    }
                } else {
                    FcpError::External {
                        service: "browser".into(),
                        message: message.clone(),
                        status_code: *status_code,
                        retryable: self.is_retryable(),
                        retry_after: self.retry_after(),
                    }
                }
            }
            Self::InvalidConfig(msg) => FcpError::Internal {
                message: format!("Invalid browser config: {msg}"),
            },
            Self::Serialization(e) => FcpError::Internal {
                message: format!("Serialization error: {e}"),
            },
            Self::Timeout { message } => FcpError::External {
                service: "browser".into(),
                message: message.clone(),
                status_code: Some(408),
                retryable: true,
                retry_after: Some(Duration::from_secs(1)),
            },
        }
    }
}
