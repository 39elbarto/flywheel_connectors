//! Gmail-specific error types.

use std::time::Duration;

use fcp_core::FcpError;
use thiserror::Error;

/// Gmail-specific errors.
#[derive(Error, Debug)]
pub enum GmailError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Gmail API returned an error
    #[error("Gmail API error: {message} (code: {code})")]
    Api { code: u32, message: String },

    /// Rate limited
    #[error("Rate limited, retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },

    /// Invalid or expired token
    #[error("Invalid or expired Gmail credentials")]
    Unauthorized,

    /// Message not found
    #[error("Message not found: {message_id}")]
    MessageNotFound { message_id: String },

    /// Thread not found
    #[error("Thread not found: {thread_id}")]
    ThreadNotFound { thread_id: String },

    /// Label not found
    #[error("Label not found: {label}")]
    LabelNotFound { label: String },
}

impl GmailError {
    /// Check if this error is retryable.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::RateLimited { .. } => true,
            Self::Api { code, .. } => {
                matches!(code, 429 | 500 | 502 | 503)
            }
            _ => false,
        }
    }

    /// Get the suggested retry delay.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after_secs } => Some(Duration::from_secs(*retry_after_secs)),
            _ => None,
        }
    }

    /// Convert to FCP error.
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Http(e) => FcpError::External {
                service: "gmail".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Api { code, message } => {
                if *code == 401 {
                    FcpError::Unauthorized {
                        code: 2001,
                        message: "Invalid or insufficient Gmail credentials".into(),
                    }
                } else if *code == 429 {
                    FcpError::RateLimited {
                        retry_after_ms: 60_000,
                        violation: None,
                    }
                } else if *code == 404 {
                    FcpError::ResourceNotFound {
                        resource: message.clone(),
                    }
                } else {
                    FcpError::External {
                        service: "gmail".into(),
                        message: message.clone(),
                        status_code: Some((*code).try_into().unwrap_or(500)),
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
                message: "Invalid or expired Gmail credentials".into(),
            },
            Self::MessageNotFound { message_id } => FcpError::ResourceNotFound {
                resource: format!("message:{message_id}"),
            },
            Self::ThreadNotFound { thread_id } => FcpError::ResourceNotFound {
                resource: format!("thread:{thread_id}"),
            },
            Self::LabelNotFound { label } => FcpError::ResourceNotFound {
                resource: format!("label:{label}"),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
        }
    }
}

/// Result type for Gmail operations.
pub type GmailResult<T> = Result<T, GmailError>;
