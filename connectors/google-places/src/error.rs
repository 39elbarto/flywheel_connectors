//! Error types for the `Google Places` connector.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_sdk::migration::ConnectorErrorMapping;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GooglePlacesError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("api error: status={status}, message={message}")]
    Api { status: u16, message: String },

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("internal error: {0}")]
    Internal(String),
}

pub type GooglePlacesResult<T> = Result<T, GooglePlacesError>;

impl GooglePlacesError {
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Config(message) => FcpError::InvalidRequest {
                code: 1003,
                message: message.clone(),
            },
            Self::Http(error) if error.is_timeout() => FcpError::UpstreamTimeout {
                service: "google_places".into(),
            },
            Self::Http(error) => FcpError::External {
                service: "google_places".into(),
                message: error.to_string(),
                status_code: None,
                retryable: error.is_connect() || error.is_timeout(),
                retry_after: None,
            },
            Self::Api { status, message } => FcpError::External {
                service: "google_places".into(),
                message: message.clone(),
                status_code: Some(*status),
                retryable: matches!(status, 429 | 500 | 502 | 503 | 504),
                retry_after: None,
            },
            Self::Json(error) => FcpError::Internal {
                message: format!("Failed to decode Google Places response: {error}"),
            },
            Self::Internal(message) => FcpError::Internal {
                message: message.clone(),
            },
        }
    }

    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http(error) => error.is_timeout() || error.is_connect(),
            Self::Api { status, .. } => matches!(status, 429 | 500 | 502 | 503 | 504),
            Self::Config(_) | Self::Json(_) | Self::Internal(_) => false,
        }
    }

    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::Api { status, .. } if *status == 429 => Some(Duration::from_secs(30)),
            _ => None,
        }
    }
}

impl ConnectorErrorMapping for GooglePlacesError {
    fn from_async_error(error: AsyncError) -> Self {
        match error {
            AsyncError::Timeout { timeout_ms } => {
                Self::Internal(format!("request deadline exceeded after {timeout_ms}ms"))
            }
            AsyncError::Cancelled => Self::Internal("operation cancelled".into()),
            other => Self::Internal(other.to_string()),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn async_timeout_maps_to_internal() {
        let err = GooglePlacesError::from_async_error(AsyncError::Timeout { timeout_ms: 5000 });
        assert!(matches!(
            err,
            GooglePlacesError::Internal(ref msg) if msg.contains("5000")
        ));
        // Should not be retryable (internal errors are not retryable)
        assert!(!err.is_retryable());
    }

    #[test]
    fn async_cancelled_maps_to_internal() {
        let err = GooglePlacesError::from_async_error(AsyncError::Cancelled);
        assert!(matches!(
            err,
            GooglePlacesError::Internal(ref msg) if msg.contains("cancelled")
        ));
    }

    #[test]
    fn async_channel_closed_maps_to_internal() {
        let err = GooglePlacesError::from_async_error(AsyncError::ChannelClosed);
        assert!(matches!(err, GooglePlacesError::Internal(_)));
    }

    #[test]
    fn api_429_is_retryable_with_retry_after() {
        let err = GooglePlacesError::Api {
            status: 429,
            message: "rate limited".into(),
        };
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn api_500_is_retryable() {
        let err = GooglePlacesError::Api {
            status: 500,
            message: "server error".into(),
        };
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), None);
    }

    #[test]
    fn api_400_is_not_retryable() {
        let err = GooglePlacesError::Api {
            status: 400,
            message: "bad request".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn config_error_is_not_retryable() {
        let err = GooglePlacesError::Config("bad config".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn internal_to_fcp_error_maps_correctly() {
        let err = GooglePlacesError::Internal("something broke".into());
        assert!(matches!(
            err.to_fcp_error(),
            FcpError::Internal { ref message } if message == "something broke"
        ));
    }
}
