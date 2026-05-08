//! Inworld-specific error mapping.

use std::time::Duration;

use fcp_prelude::FcpError;
use thiserror::Error;

pub type InworldResult<T> = Result<T, InworldError>;

#[derive(Error, Debug)]
pub enum InworldError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("URL error: {0}")]
    Url(#[from] url::ParseError),

    #[error("Inworld API error ({status_code}): {message}")]
    Api {
        status_code: u16,
        message: String,
        retry_after_ms: Option<u64>,
    },

    #[error("Inworld authentication failed")]
    Unauthorized,

    #[error("Inworld request was rate limited")]
    RateLimited { retry_after_ms: Option<u64> },

    #[error("Invalid Inworld input: {0}")]
    InvalidInput(String),

    #[error("Inworld websocket error: {message}")]
    WebSocket { message: String, retryable: bool },

    #[error("Configured credential mode requires host-side injection")]
    CredentialInjectionRequired,
}

impl InworldError {
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::RateLimited { .. } => true,
            Self::Api { status_code, .. } => matches!(*status_code, 408 | 425 | 429 | 500..=599),
            Self::WebSocket { retryable, .. } => *retryable,
            _ => false,
        }
    }

    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after_ms } | Self::Api { retry_after_ms, .. } => {
                match retry_after_ms {
                    Some(ms) => Some(Duration::from_millis(*ms)),
                    None => None,
                }
            }
            _ => None,
        }
    }

    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::InvalidInput(message) => FcpError::InvalidRequest {
                code: 1003,
                message: message.clone(),
            },
            Self::Json(error) => FcpError::InvalidRequest {
                code: 1003,
                message: format!("invalid JSON payload: {error}"),
            },
            Self::Url(error) => FcpError::InvalidRequest {
                code: 1003,
                message: format!("invalid URL: {error}"),
            },
            Self::Unauthorized => FcpError::External {
                service: "inworld".into(),
                message: "authentication failed".into(),
                status_code: Some(401),
                retryable: false,
                retry_after: None,
            },
            Self::RateLimited { retry_after_ms } => FcpError::External {
                service: "inworld".into(),
                message: "rate limited".into(),
                status_code: Some(429),
                retryable: true,
                retry_after: retry_after_ms.map(Duration::from_millis),
            },
            Self::Api {
                status_code,
                message,
                retry_after_ms: _,
            } => FcpError::External {
                service: "inworld".into(),
                message: message.clone(),
                status_code: Some(*status_code),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Http(error) => FcpError::External {
                service: "inworld".into(),
                message: error.to_string(),
                status_code: error.status().map(|status| status.as_u16()),
                retryable: self.is_retryable(),
                retry_after: None,
            },
            Self::WebSocket { message, .. } => FcpError::External {
                service: "inworld".into(),
                message: message.clone(),
                status_code: None,
                retryable: self.is_retryable(),
                retry_after: None,
            },
            Self::CredentialInjectionRequired => FcpError::InvalidRequest {
                code: 1003,
                message:
                    "credential_id mode requires host-side WebSocket/HTTP credential injection"
                        .into(),
            },
        }
    }
}

impl fcp_sdk::migration::ConnectorErrorMapping for InworldError {
    fn from_async_error(error: fcp_async_core::AsyncError) -> Self {
        match error {
            fcp_async_core::AsyncError::Timeout { timeout_ms } => Self::Api {
                status_code: 408,
                message: format!("deadline exceeded after {timeout_ms}ms"),
                retry_after_ms: None,
            },
            fcp_async_core::AsyncError::Cancelled => Self::Api {
                status_code: 499,
                message: "request cancelled".into(),
                retry_after_ms: None,
            },
            other => Self::WebSocket {
                message: other.to_string(),
                retryable: true,
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
