//! Slack-specific error types.

use std::time::Duration;

use fcp_core::FcpError;
use thiserror::Error;

/// Slack-specific errors.
#[derive(Error, Debug)]
pub enum SlackError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Slack API returned an error
    #[error("Slack API error: {error} (code: {code:?})")]
    Api {
        error: String,
        code: Option<String>,
        ok: bool,
    },

    /// Rate limited
    #[error("Rate limited, retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },

    /// Invalid or expired token
    #[error("Invalid or expired Slack token")]
    Unauthorized,

    /// Channel not found
    #[error("Channel not found: {channel}")]
    ChannelNotFound { channel: String },

    /// User not found
    #[error("User not found: {user}")]
    UserNotFound { user: String },
}

impl SlackError {
    /// Check if this error is retryable.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::RateLimited { .. } => true,
            Self::Api { error, .. } => {
                // Slack transient errors
                matches!(
                    error.as_str(),
                    "internal_error" | "request_timeout" | "service_unavailable" | "fatal_error"
                )
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
                service: "slack".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Api { error, .. } => {
                if error == "not_authed" || error == "invalid_auth" || error == "token_revoked" {
                    FcpError::Unauthorized {
                        code: 2001,
                        message: "Invalid or insufficient Slack token".into(),
                    }
                } else if error == "ratelimited" {
                    FcpError::RateLimited {
                        retry_after_ms: 60_000,
                        violation: None,
                    }
                } else if error == "channel_not_found" {
                    FcpError::ResourceNotFound {
                        resource: "channel".into(),
                    }
                } else if error == "user_not_found" {
                    FcpError::ResourceNotFound {
                        resource: "user".into(),
                    }
                } else {
                    FcpError::External {
                        service: "slack".into(),
                        message: error.clone(),
                        status_code: None,
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
                message: "Invalid or expired Slack token".into(),
            },
            Self::ChannelNotFound { channel } => FcpError::ResourceNotFound {
                resource: format!("channel:{channel}"),
            },
            Self::UserNotFound { user } => FcpError::ResourceNotFound {
                resource: format!("user:{user}"),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
        }
    }
}

/// Result type for Slack operations.
pub type SlackResult<T> = Result<T, SlackError>;
