//! Error types for the Synology Chat connector.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_sdk::migration::{ConnectorErrorMapping, map_async_to_fcp_error};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SynologyChatError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("api error: status={status}, message={message}")]
    Api {
        status: u16,
        message: String,
        retry_after_ms: Option<u64>,
    },

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("async error: {0}")]
    Async(AsyncError),
}

pub type SynologyChatResult<T> = Result<T, SynologyChatError>;

impl SynologyChatError {
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        ConnectorErrorMapping::to_fcp_error(self)
    }

    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Config(_) | Self::InvalidInput(_) | Self::Json(_) => false,
            Self::Http(error) => error.is_connect() || error.is_timeout(),
            Self::Api { status, .. } => matches!(status, 429 | 500 | 502 | 503 | 504),
            Self::Async(error) => matches!(error, AsyncError::Timeout { .. }),
        }
    }

    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::Api {
                retry_after_ms: Some(retry_after_ms),
                ..
            } => Some(Duration::from_millis(*retry_after_ms)),
            _ => None,
        }
    }

    fn fcp_error_impl(&self) -> FcpError {
        match self {
            Self::Config(message) => FcpError::InvalidRequest {
                code: 1003,
                message: message.clone(),
            },
            Self::InvalidInput(message) => FcpError::InvalidRequest {
                code: 1005,
                message: message.clone(),
            },
            Self::Http(error) if error.is_timeout() => FcpError::UpstreamTimeout {
                service: "synology_chat".into(),
            },
            Self::Http(error) => FcpError::External {
                service: "synology_chat".into(),
                message: error.to_string(),
                status_code: error.status().map(|status| status.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Api {
                status: 429,
                retry_after_ms: Some(retry_after_ms),
                ..
            } => FcpError::RateLimited {
                retry_after_ms: *retry_after_ms,
                violation: None,
            },
            Self::Api {
                status,
                message,
                retry_after_ms: _,
            } => FcpError::External {
                service: "synology_chat".into(),
                message: message.clone(),
                status_code: Some(*status),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Json(error) => FcpError::MalformedFrame {
                code: 1006,
                message: format!("Failed to decode Synology Chat response: {error}"),
            },
            Self::Async(error) => map_async_to_fcp_error(error),
        }
    }
}

impl ConnectorErrorMapping for SynologyChatError {
    fn from_async_error(error: AsyncError) -> Self {
        Self::Async(error)
    }

    fn to_fcp_error(&self) -> FcpError {
        self.fcp_error_impl()
    }

    fn is_retryable(&self) -> bool {
        Self::is_retryable(self)
    }

    fn retry_after(&self) -> Option<Duration> {
        Self::retry_after(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_server_error_is_retryable() {
        let error = SynologyChatError::Api {
            status: 503,
            message: "unavailable".into(),
            retry_after_ms: None,
        };
        assert!(error.is_retryable());
        assert_eq!(error.retry_after(), None);
    }

    #[test]
    fn invalid_input_maps_to_invalid_request() {
        let error = SynologyChatError::InvalidInput("payload must be an object".into());
        match error.to_fcp_error() {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1005);
                assert!(message.contains("payload must be an object"));
            }
            other => assert!(matches!(other, FcpError::InvalidRequest { .. })),
        }
    }

    #[test]
    fn api_retry_after_maps_to_rate_limited() {
        let error = SynologyChatError::Api {
            status: 429,
            message: "slow down".into(),
            retry_after_ms: Some(7000),
        };
        match error.to_fcp_error() {
            FcpError::RateLimited {
                retry_after_ms,
                violation,
            } => {
                assert_eq!(retry_after_ms, 7000);
                assert!(violation.is_none());
            }
            other => assert!(matches!(other, FcpError::RateLimited { .. })),
        }
    }

    #[test]
    fn timeout_async_error_maps_through_connector_trait() {
        let error = SynologyChatError::from_async_error(AsyncError::Timeout { timeout_ms: 5000 });
        assert!(error.is_retryable());
        match error {
            SynologyChatError::Async(AsyncError::Timeout { timeout_ms }) => {
                assert_eq!(timeout_ms, 5000);
            }
            other => assert!(matches!(
                other,
                SynologyChatError::Async(AsyncError::Timeout { .. })
            )),
        }
    }

    #[test]
    fn cancelled_async_error_maps_to_standard_fcp_error() {
        let error = SynologyChatError::from_async_error(AsyncError::Cancelled);
        match error.to_fcp_error() {
            FcpError::External {
                message, retryable, ..
            } => {
                assert!(message.contains("cancelled"));
                assert!(!retryable);
            }
            other => assert!(matches!(other, FcpError::External { .. })),
        }
    }
}
