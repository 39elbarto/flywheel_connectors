//! Vector database connector error types.

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_sdk::migration::ConnectorErrorMapping;
use thiserror::Error;

/// Vector database connector errors.
#[derive(Error, Debug)]
pub enum VectorDbError {
    /// Request configuration error.
    #[error("invalid request: {message}")]
    InvalidRequest {
        /// Error detail.
        message: String,
    },
    /// Provider communication error (retryable).
    #[error("provider error: {message}")]
    Provider {
        /// Error detail.
        message: String,
    },
    /// Internal error.
    #[error("internal: {message}")]
    Internal {
        /// Error detail.
        message: String,
    },
}

impl ConnectorErrorMapping for VectorDbError {
    fn from_async_error(error: AsyncError) -> Self {
        match error {
            AsyncError::Timeout { timeout_ms } => Self::Internal {
                message: format!("deadline exceeded after {timeout_ms}ms"),
            },
            AsyncError::Cancelled => Self::Internal {
                message: "request cancelled".into(),
            },
            other => Self::Internal {
                message: other.to_string(),
            },
        }
    }

    fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::InvalidRequest { message } => FcpError::InvalidRequest {
                code: 1003,
                message: message.clone(),
            },
            Self::Provider { message } => FcpError::External {
                service: "vectordb".into(),
                status_code: None,
                message: message.clone(),
                retryable: true,
                retry_after: None,
            },
            Self::Internal { message } => FcpError::Internal {
                message: message.clone(),
            },
        }
    }

    fn is_retryable(&self) -> bool {
        matches!(self, Self::Provider { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_timeout() {
        let err = VectorDbError::from_async_error(AsyncError::Timeout { timeout_ms: 5000 });
        assert!(matches!(err, VectorDbError::Internal { .. }));
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::Internal { .. }));
    }

    #[test]
    fn from_cancelled() {
        let err = VectorDbError::from_async_error(AsyncError::Cancelled);
        assert!(matches!(err, VectorDbError::Internal { .. }));
    }

    #[test]
    fn provider_is_retryable() {
        let err = VectorDbError::Provider {
            message: "timeout".into(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn invalid_request_not_retryable() {
        let err = VectorDbError::InvalidRequest {
            message: "bad input".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn internal_not_retryable() {
        let err = VectorDbError::Internal {
            message: "oops".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn display_formats() {
        assert_eq!(
            VectorDbError::Provider {
                message: "net".into()
            }
            .to_string(),
            "provider error: net"
        );
        assert_eq!(
            VectorDbError::InvalidRequest {
                message: "x".into()
            }
            .to_string(),
            "invalid request: x"
        );
    }

    #[test]
    fn to_fcp_error_provider() {
        let err = VectorDbError::Provider {
            message: "503".into(),
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::External { retryable, .. } => assert!(retryable),
            other => panic!("expected External, got {other:?}"),
        }
    }
}
