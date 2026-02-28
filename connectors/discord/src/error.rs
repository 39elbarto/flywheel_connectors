//! Discord-specific error types.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_core::FcpError;
use fcp_sdk::migration::ConnectorErrorMapping;
use thiserror::Error;

/// Discord-specific errors.
#[derive(Error, Debug)]
pub enum DiscordError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// WebSocket error
    #[error("WebSocket error: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),

    /// Discord API returned an error
    #[error("Discord API error {code}: {message}")]
    Api {
        code: i32,
        message: String,
        retry_after: Option<f64>,
    },

    /// Rate limited
    #[error("Rate limited, retry after {retry_after} seconds")]
    RateLimited { retry_after: f64 },

    /// Generic gateway error
    #[error("Gateway error: {0}")]
    Gateway(String),
}

impl DiscordError {
    /// Check if this error is retryable.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) => true,
            Self::WebSocket(_) => true,
            Self::Api { code, .. } => *code >= 500 || *code == 429,
            Self::RateLimited { .. } => true,
            Self::Gateway(_) => true,
            _ => false,
        }
    }

    /// Get the suggested retry delay.
    #[must_use]
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after } => Some(Duration::from_secs_f64(*retry_after)),
            Self::Api { retry_after, .. } => retry_after.map(Duration::from_secs_f64),
            _ => None,
        }
    }

    /// Convert to FCP error.
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        ConnectorErrorMapping::to_fcp_error(self)
    }

    fn fcp_error_impl(&self) -> FcpError {
        match self {
            Self::Http(e) => FcpError::External {
                service: "discord".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::WebSocket(e) => FcpError::External {
                service: "discord_gateway".into(),
                message: e.to_string(),
                status_code: None,
                retryable: self.is_retryable(),
                retry_after: None,
            },
            Self::Api {
                code,
                message,
                retry_after,
            } => {
                if *code == 429 {
                    // Clamp retry_after to reasonable bounds to prevent overflow
                    let retry_secs = retry_after.unwrap_or(30.0).clamp(0.0, 3600.0);
                    FcpError::RateLimited {
                        retry_after_ms: (retry_secs * 1000.0) as u64,
                        violation: None,
                    }
                } else {
                    FcpError::External {
                        service: "discord".into(),
                        message: message.clone(),
                        status_code: u16::try_from(*code).ok(),
                        retryable: self.is_retryable(),
                        retry_after: self.retry_after(),
                    }
                }
            }
            Self::RateLimited { retry_after } => {
                // Clamp retry_after to reasonable bounds to prevent overflow
                let retry_secs = retry_after.clamp(0.0, 3600.0);
                FcpError::RateLimited {
                    retry_after_ms: (retry_secs * 1000.0) as u64,
                    violation: None,
                }
            }
            Self::Gateway(msg) => FcpError::ConnectorUnavailable {
                code: 5001,
                message: format!("Discord Gateway error: {msg}"),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
        }
    }
}

impl ConnectorErrorMapping for DiscordError {
    fn from_async_error(error: AsyncError) -> Self {
        match error {
            AsyncError::Timeout { timeout_ms } => Self::Api {
                code: 408,
                message: format!("request context deadline exceeded after {timeout_ms}ms"),
                retry_after: None,
            },
            AsyncError::Cancelled => Self::Api {
                code: 499,
                message: "request context cancelled".into(),
                retry_after: None,
            },
            other => Self::Gateway(other.to_string()),
        }
    }

    fn to_fcp_error(&self) -> FcpError {
        self.fcp_error_impl()
    }

    fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::WebSocket(_) | Self::RateLimited { .. } | Self::Gateway(_) => {
                true
            }
            Self::Api { code, .. } => *code >= 500 || *code == 429,
            _ => false,
        }
    }

    fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after } => Some(Duration::from_secs_f64(*retry_after)),
            Self::Api { retry_after, .. } => retry_after.map(Duration::from_secs_f64),
            _ => None,
        }
    }
}

/// Result type for Discord operations.
pub type DiscordResult<T> = Result<T, DiscordError>;
