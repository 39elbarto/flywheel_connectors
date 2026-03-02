//! Figma-specific error types.

use std::time::Duration;

use fcp_core::FcpError;
use thiserror::Error;

/// Figma-specific errors.
#[derive(Error, Debug)]
pub enum FigmaError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Figma API returned an error
    #[error("Figma API error: {status} - {message}")]
    Api {
        status: u16,
        message: String,
    },

    /// Rate limited
    #[error("Rate limited, retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },

    /// Invalid or expired token
    #[error("Invalid or expired Figma token")]
    Unauthorized,

    /// File not found
    #[error("File not found: {file_key}")]
    FileNotFound { file_key: String },

    /// Comment not found
    #[error("Comment not found: {comment_id}")]
    CommentNotFound { comment_id: String },

    /// Webhook not found
    #[error("Webhook not found: {webhook_id}")]
    WebhookNotFound { webhook_id: String },
}

impl FigmaError {
    /// Check if this error is retryable.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::RateLimited { .. } => true,
            Self::Api { status, message } => {
                // Figma transient errors
                *status == 429
                    || *status >= 500
                    || message.contains("timeout")
                    || message.contains("temporarily unavailable")
            }
            _ => false,
        }
    }

    /// Get the suggested retry delay.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after_secs } => {
                Some(Duration::from_secs(*retry_after_secs))
            }
            _ => None,
        }
    }

    /// Convert to FCP error.
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Http(e) => FcpError::External {
                service: "figma".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Api { status, message } => {
                if *status == 403 || *status == 401 {
                    FcpError::Unauthorized {
                        code: 2001,
                        message: "Invalid or insufficient Figma token".into(),
                    }
                } else if *status == 429 {
                    FcpError::RateLimited {
                        retry_after_ms: 60_000,
                        violation: None,
                    }
                } else if *status == 404 {
                    FcpError::ResourceNotFound {
                        resource: message.clone(),
                    }
                } else {
                    FcpError::External {
                        service: "figma".into(),
                        message: message.clone(),
                        status_code: Some(*status),
                        retryable: self.is_retryable(),
                        retry_after: self.retry_after(),
                    }
                }
            }
            Self::RateLimited { retry_after_secs } => FcpError::RateLimited {
                retry_after_ms: retry_after_secs * 1000,
                violation: None,
            },
            Self::Unauthorized => FcpError::Unauthorized {
                code: 2001,
                message: "Invalid or expired Figma token".into(),
            },
            Self::FileNotFound { file_key } => FcpError::ResourceNotFound {
                resource: format!("file:{file_key}"),
            },
            Self::CommentNotFound { comment_id } => FcpError::ResourceNotFound {
                resource: format!("comment:{comment_id}"),
            },
            Self::WebhookNotFound { webhook_id } => FcpError::ResourceNotFound {
                resource: format!("webhook:{webhook_id}"),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
        }
    }
}

/// Result type for Figma operations.
pub type FigmaResult<T> = Result<T, FigmaError>;
