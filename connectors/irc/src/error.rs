//! IRC connector error types with `ConnectorErrorMapping` integration.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_sdk::migration::ConnectorErrorMapping;

/// Alias for IRC-specific results.
pub type IrcResult<T> = Result<T, IrcError>;

/// Unified error type for the IRC connector.
#[derive(Debug, thiserror::Error)]
pub enum IrcError {
    /// TCP / socket I/O failure.
    #[error("I/O error: {context} — {message}")]
    Io { context: String, message: String },

    /// IRC protocol-level failure (e.g. 433 nick in use, unexpected close).
    #[error("IRC protocol error: {0}")]
    Protocol(String),

    /// Timeout waiting for server response.
    #[error("IRC timeout: {0}")]
    Timeout(String),

    /// Async runtime error (cancelled, deadline exceeded, etc.).
    #[error("Async error: {0}")]
    Async(String),

    /// Configuration validation failure.
    #[error("Configuration error: {0}")]
    Config(String),

    /// Invalid input in an invoke request.
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// TLS handshake or setup failure.
    #[error("TLS error: {0}")]
    Tls(String),
}

impl IrcError {
    /// Create an I/O error from a `std::io::Error` with context.
    pub fn io(context: impl Into<String>, source: &std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            message: source.to_string(),
        }
    }

    /// Whether this error is retryable.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Io { .. } | Self::Timeout(_) | Self::Tls(_) => true,
            Self::Protocol(msg) => {
                // Connection closed before welcome is retryable; nick-in-use is not.
                !msg.contains("nickname already in use")
            }
            Self::Async(_) | Self::Config(_) | Self::InvalidInput(_) => false,
        }
    }

    /// Suggested retry-after delay.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::Timeout(_) => Some(Duration::from_secs(2)),
            _ => None,
        }
    }

    /// Convert to the canonical `FcpError`.
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Io { context, message } => FcpError::External {
                service: "irc".into(),
                message: format!("{context} failed: {message}"),
                status_code: None,
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Protocol(message) => FcpError::External {
                service: "irc".into(),
                message: message.clone(),
                status_code: None,
                retryable: self.is_retryable(),
                retry_after: None,
            },
            Self::Timeout(message) => FcpError::UpstreamTimeout {
                service: format!("irc: {message}"),
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
            Self::Tls(message) => FcpError::External {
                service: "irc".into(),
                message: format!("TLS error: {message}"),
                status_code: None,
                retryable: true,
                retry_after: None,
            },
        }
    }
}

impl ConnectorErrorMapping for IrcError {
    fn from_async_error(error: AsyncError) -> Self {
        match error {
            AsyncError::Timeout { timeout_ms } => {
                Self::Timeout(format!("request deadline exceeded after {timeout_ms}ms"))
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
    fn io_error_is_retryable() {
        let err = IrcError::Io {
            context: "connect".into(),
            message: "connection refused".into(),
        };
        assert!(err.is_retryable());
        assert!(err.retry_after().is_none());
    }

    #[test]
    fn timeout_is_retryable_with_delay() {
        let err = IrcError::Timeout("server did not respond".into());
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(Duration::from_secs(2)));
    }

    #[test]
    fn config_error_is_not_retryable() {
        let err = IrcError::Config("server must not be empty".into());
        assert!(!err.is_retryable());
        assert!(err.retry_after().is_none());
    }

    #[test]
    fn invalid_input_is_not_retryable() {
        let err = IrcError::InvalidInput("target is required".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn tls_error_is_retryable() {
        let err = IrcError::Tls("handshake failed".into());
        assert!(err.is_retryable());
    }

    #[test]
    fn nick_in_use_protocol_is_not_retryable() {
        let err = IrcError::Protocol("IRC nickname already in use".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn connection_closed_protocol_is_retryable() {
        let err = IrcError::Protocol("IRC server closed connection before welcome".into());
        assert!(err.is_retryable());
    }

    #[test]
    fn io_error_maps_to_external() {
        let source = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
        let err = IrcError::io("irc connect", &source);
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::External {
                service, retryable, ..
            } => {
                assert_eq!(service, "irc");
                assert!(retryable);
            }
            other => assert!(matches!(other, FcpError::External { .. })),
        }
    }

    #[test]
    fn timeout_maps_to_upstream_timeout() {
        let err = IrcError::Timeout("no response".into());
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::UpstreamTimeout { .. }));
    }

    #[test]
    fn config_maps_to_invalid_request() {
        let err = IrcError::Config("missing server".into());
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1001);
                assert!(message.contains("missing server"));
            }
            other => assert!(matches!(other, FcpError::InvalidRequest { .. })),
        }
    }

    #[test]
    fn invalid_input_maps_to_invalid_request_1005() {
        let err = IrcError::InvalidInput("target is required".into());
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::InvalidRequest { code, .. } => assert_eq!(code, 1005),
            other => assert!(matches!(other, FcpError::InvalidRequest { .. })),
        }
    }

    #[test]
    fn tls_maps_to_external() {
        let err = IrcError::Tls("certificate expired".into());
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::External {
                service,
                message,
                retryable,
                ..
            } => {
                assert_eq!(service, "irc");
                assert!(message.contains("TLS"));
                assert!(retryable);
            }
            other => assert!(matches!(other, FcpError::External { .. })),
        }
    }

    #[test]
    fn async_error_mapping_timeout() {
        let err = IrcError::from_async_error(AsyncError::Timeout { timeout_ms: 5000 });
        assert!(matches!(err, IrcError::Timeout(_)));
        assert!(err.to_string().contains("5000"));
    }

    #[test]
    fn async_error_mapping_cancelled() {
        let err = IrcError::from_async_error(AsyncError::Cancelled);
        assert!(matches!(err, IrcError::Async(_)));
        assert!(!err.is_retryable());
    }

    #[test]
    fn async_error_mapping_runtime() {
        let err = IrcError::from_async_error(AsyncError::Runtime {
            message: "runtime crash".into(),
        });
        assert!(matches!(err, IrcError::Async(_)));
        assert!(err.to_string().contains("runtime"));
    }

    #[test]
    fn display_formatting() {
        let io = IrcError::Io {
            context: "read".into(),
            message: "broken pipe".into(),
        };
        assert_eq!(io.to_string(), "I/O error: read \u{2014} broken pipe");

        let proto = IrcError::Protocol("nick in use".into());
        assert_eq!(proto.to_string(), "IRC protocol error: nick in use");

        let timeout = IrcError::Timeout("server unresponsive".into());
        assert_eq!(timeout.to_string(), "IRC timeout: server unresponsive");

        let config = IrcError::Config("missing server".into());
        assert_eq!(config.to_string(), "Configuration error: missing server");

        let input = IrcError::InvalidInput("target empty".into());
        assert_eq!(input.to_string(), "Invalid input: target empty");

        let tls = IrcError::Tls("cert invalid".into());
        assert_eq!(tls.to_string(), "TLS error: cert invalid");

        let async_err = IrcError::Async("cancelled".into());
        assert_eq!(async_err.to_string(), "Async error: cancelled");
    }
}
