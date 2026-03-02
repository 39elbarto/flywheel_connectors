//! GitHub-specific error types.

use std::time::Duration;

use fcp_core::FcpError;
use thiserror::Error;

/// GitHub-specific errors.
#[derive(Error, Debug)]
pub enum GitHubError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// GitHub API returned an error
    #[error("GitHub API error: {message} (status {status_code:?})")]
    Api {
        message: String,
        status_code: Option<u16>,
        documentation_url: Option<String>,
    },

    /// Rate limited (primary or secondary)
    #[error("Rate limited, retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },

    /// Invalid or expired token
    #[error("Invalid or expired GitHub token")]
    Unauthorized,

    /// Resource not found (404)
    #[error("Resource not found: {resource}")]
    NotFound { resource: String },

    /// Validation error (422)
    #[error("Validation error: {message}")]
    ValidationError { message: String },

    /// Merge conflict or not mergeable
    #[error("Merge conflict: {message}")]
    MergeConflict { message: String },
}

impl GitHubError {
    /// Check if this error is retryable.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) => true,
            Self::RateLimited { .. } => true,
            Self::Api { status_code, .. } => matches!(status_code, Some(500..=599 | 429 | 403)),
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
                service: "github".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Api {
                message,
                status_code,
                ..
            } => {
                if *status_code == Some(401) || *status_code == Some(403) {
                    FcpError::Unauthorized {
                        code: 2001,
                        message: "Invalid or insufficient GitHub token".into(),
                    }
                } else if *status_code == Some(429) {
                    FcpError::RateLimited {
                        retry_after_ms: 60_000,
                        violation: None,
                    }
                } else {
                    FcpError::External {
                        service: "github".into(),
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
            Self::Unauthorized => FcpError::Unauthorized {
                code: 2001,
                message: "Invalid or expired GitHub token".into(),
            },
            Self::NotFound { resource } => FcpError::ResourceNotFound {
                resource: resource.clone(),
            },
            Self::ValidationError { message } => FcpError::InvalidRequest {
                code: 1003,
                message: message.clone(),
            },
            Self::MergeConflict { message } => FcpError::Conflict {
                message: message.clone(),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
        }
    }
}

/// Result type for GitHub operations.
pub type GitHubResult<T> = Result<T, GitHubError>;
