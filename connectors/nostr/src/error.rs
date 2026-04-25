//! Nostr connector error types with FCP error mapping.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_core::FcpError;
use fcp_sdk::migration::ConnectorErrorMapping;
use fcp_streaming::StreamError;

/// Alias for `Result<T, NostrError>`.
pub type NostrResult<T> = Result<T, NostrError>;

/// Domain errors for the Nostr connector.
#[derive(Debug, thiserror::Error)]
pub enum NostrError {
    /// HTTP transport error (reqwest).
    #[error("HTTP transport error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization error.
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    /// Nostr relay protocol error (e.g. unexpected frame, NOTICE).
    #[error("Relay error: {0}")]
    Relay(String),

    /// Cryptographic operation error (key parse, signing).
    #[error("Crypto error: {0}")]
    Crypto(String),

    /// Async runtime error.
    #[error("Async error: {0}")]
    Async(String),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(String),

    /// Invalid input to an operation.
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// WebSocket stream error.
    #[error("Stream error: {0}")]
    Stream(String),
}

impl From<StreamError> for NostrError {
    fn from(error: StreamError) -> Self {
        Self::Stream(error.to_string())
    }
}

impl NostrError {
    /// Whether this error is potentially retryable.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http(error) => error.is_timeout() || error.is_connect(),
            Self::Stream(_) | Self::Relay(_) => true,
            Self::Json(_)
            | Self::Crypto(_)
            | Self::Async(_)
            | Self::Config(_)
            | Self::InvalidInput(_) => false,
        }
    }

    /// Retry-after duration hint, if applicable.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        None
    }

    /// Map to the canonical FCP error type.
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Http(error) => FcpError::External {
                service: "nostr".into(),
                message: error.to_string(),
                status_code: error.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Json(error) => FcpError::Internal {
                message: format!("JSON parse error: {error}"),
            },
            Self::Relay(message) => FcpError::External {
                service: "nostr".into(),
                message: message.clone(),
                status_code: None,
                retryable: true,
                retry_after: None,
            },
            Self::Crypto(message) => FcpError::InvalidRequest {
                code: 1001,
                message: format!("Crypto error: {message}"),
            },
            Self::Async(message) => FcpError::Internal {
                message: format!("Async error: {message}"),
            },
            Self::Config(message) => FcpError::InvalidRequest {
                code: 1001,
                message: format!("Configuration error: {message}"),
            },
            Self::InvalidInput(message) => FcpError::InvalidRequest {
                code: 1005,
                message: message.clone(),
            },
            Self::Stream(message) => FcpError::External {
                service: "nostr".into(),
                message: format!("stream error: {message}"),
                status_code: None,
                retryable: true,
                retry_after: None,
            },
        }
    }
}

impl ConnectorErrorMapping for NostrError {
    fn from_async_error(error: AsyncError) -> Self {
        match error {
            AsyncError::Timeout { timeout_ms } => {
                Self::Async(format!("request deadline exceeded after {timeout_ms}ms"))
            }
            AsyncError::Cancelled => Self::Async("operation cancelled".into()),
            other => Self::Async(other.to_string()),
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
    fn relay_error_is_retryable() {
        let err = NostrError::Relay("connection reset".into());
        assert!(err.is_retryable());
        assert!(err.retry_after().is_none());
    }

    #[test]
    fn crypto_error_is_not_retryable() {
        let err = NostrError::Crypto("invalid key".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn config_error_maps_to_invalid_request() {
        let err = NostrError::Config("relay_urls empty".into());
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1001);
                assert!(message.contains("relay_urls empty"));
            }
            other => assert!(matches!(other, FcpError::InvalidRequest { .. })),
        }
    }

    #[test]
    fn invalid_input_maps_to_invalid_request() {
        let err = NostrError::InvalidInput("content is required".into());
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1005);
                assert_eq!(message, "content is required");
            }
            other => assert!(matches!(other, FcpError::InvalidRequest { .. })),
        }
    }

    #[test]
    fn relay_error_maps_to_external() {
        let err = NostrError::Relay("NOTICE: blocked".into());
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::External {
                service, retryable, ..
            } => {
                assert_eq!(service, "nostr");
                assert!(retryable);
            }
            other => assert!(matches!(other, FcpError::External { .. })),
        }
    }

    #[test]
    fn stream_error_is_retryable() {
        let err = NostrError::Stream("connection closed".into());
        assert!(err.is_retryable());
    }

    #[test]
    fn stream_error_maps_to_external() {
        let err = NostrError::Stream("timeout".into());
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::External {
                service, retryable, ..
            } => {
                assert_eq!(service, "nostr");
                assert!(retryable);
            }
            other => assert!(matches!(other, FcpError::External { .. })),
        }
    }

    #[test]
    fn json_error_maps_to_internal() {
        let err: NostrError = serde_json::from_str::<serde_json::Value>("{{bad}}")
            .unwrap_err()
            .into();
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::Internal { .. }));
    }

    #[test]
    fn async_error_mapping_preserves_timeout() {
        let err = NostrError::from_async_error(AsyncError::Timeout { timeout_ms: 2_000 });
        assert_eq!(
            err.to_string(),
            "Async error: request deadline exceeded after 2000ms"
        );
        assert!(!err.is_retryable());
    }

    #[test]
    fn async_error_mapping_cancelled() {
        let err = NostrError::from_async_error(AsyncError::Cancelled);
        assert_eq!(err.to_string(), "Async error: operation cancelled");
    }

    #[test]
    fn display_formatting() {
        assert_eq!(
            NostrError::Crypto("bad key".into()).to_string(),
            "Crypto error: bad key"
        );
        assert_eq!(
            NostrError::Config("missing field".into()).to_string(),
            "Configuration error: missing field"
        );
        assert_eq!(
            NostrError::InvalidInput("empty".into()).to_string(),
            "Invalid input: empty"
        );
        assert_eq!(
            NostrError::Relay("closed".into()).to_string(),
            "Relay error: closed"
        );
        assert_eq!(
            NostrError::Stream("broken".into()).to_string(),
            "Stream error: broken"
        );
        assert_eq!(
            NostrError::Async("timeout".into()).to_string(),
            "Async error: timeout"
        );
    }
}
