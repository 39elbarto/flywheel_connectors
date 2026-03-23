//! Error types for the Telegram connector.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_core::FcpError;
use fcp_sdk::migration::ConnectorErrorMapping;
use thiserror::Error;

/// Convenience alias used throughout the connector.
pub type TelegramResult<T> = Result<T, TelegramError>;

/// Telegram API errors.
#[derive(Debug, Error)]
pub enum TelegramError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Telegram API error ({code}): {description}")]
    Api { code: i32, description: String },

    #[error("Invalid chat ID: {0}")]
    InvalidChatId(String),
}

impl TelegramError {
    /// Check if this error is retryable.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http(error) => error.is_timeout() || error.is_connect(),
            Self::Api { code, .. } => *code == 429 || *code >= 500,
            Self::InvalidChatId(_) => false,
        }
    }

    /// Get the suggested retry delay.
    #[must_use]
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::Api { code, .. } if *code == 429 => Some(Duration::from_secs(30)),
            _ => None,
        }
    }

    /// Convert to an FCP-native error.
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Http(error) => FcpError::External {
                service: "telegram".into(),
                message: error.to_string(),
                status_code: error.status().map(|status| status.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Api { code, description } => {
                if *code == 429 {
                    FcpError::RateLimited {
                        retry_after_ms: 30_000,
                        violation: None,
                    }
                } else if *code == 401 {
                    FcpError::Unauthorized {
                        code: 2001,
                        message: description.clone(),
                    }
                } else if *code == 403 {
                    FcpError::CapabilityDenied {
                        capability: "telegram.api".into(),
                        reason: description.clone(),
                    }
                } else {
                    FcpError::External {
                        service: "telegram".into(),
                        message: description.clone(),
                        status_code: Some(u16::try_from(*code).unwrap_or(0)),
                        retryable: self.is_retryable(),
                        retry_after: self.retry_after(),
                    }
                }
            }
            Self::InvalidChatId(message) => FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid chat ID: {message}"),
            },
        }
    }
}

impl ConnectorErrorMapping for TelegramError {
    fn from_async_error(error: AsyncError) -> Self {
        match error {
            AsyncError::Timeout { timeout_ms } => Self::Api {
                code: 408,
                description: format!("deadline exceeded after {timeout_ms}ms"),
            },
            AsyncError::Cancelled => Self::Api {
                code: 0,
                description: "request cancelled".into(),
            },
            other => Self::Api {
                code: 0,
                description: other.to_string(),
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
