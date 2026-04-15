//! Error types for the generic email connector.

use fcp_core::FcpError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EmailGenericError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("imap error: {0}")]
    Imap(String),

    #[error("smtp error: {0}")]
    Smtp(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("tls error: {0}")]
    Tls(#[from] native_tls::Error),

    #[error("address error: {0}")]
    Address(String),
}

pub type EmailGenericResult<T> = Result<T, EmailGenericError>;

impl EmailGenericError {
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Config(message) => FcpError::InvalidRequest {
                code: 1003,
                message: message.clone(),
            },
            Self::Imap(message) | Self::Smtp(message) => FcpError::External {
                service: "email_generic".into(),
                message: message.clone(),
                status_code: None,
                retryable: false,
                retry_after: None,
            },
            Self::Io(error) => FcpError::External {
                service: "email_generic".into(),
                message: error.to_string(),
                status_code: None,
                retryable: true,
                retry_after: None,
            },
            Self::Tls(error) => FcpError::Internal {
                message: error.to_string(),
            },
            Self::Address(error) => FcpError::InvalidRequest {
                code: 1005,
                message: format!("invalid email address: {error}"),
            },
        }
    }

    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(self, Self::Io(_))
    }
}

impl fcp_sdk::migration::ConnectorErrorMapping for EmailGenericError {
    fn from_async_error(error: fcp_async_core::AsyncError) -> Self {
        match error {
            fcp_async_core::AsyncError::Timeout { timeout_ms } => {
                Self::Imap(format!("deadline exceeded after {timeout_ms}ms"))
            }
            fcp_async_core::AsyncError::Cancelled => Self::Imap("request cancelled".into()),
            other => Self::Imap(other.to_string()),
        }
    }

    fn to_fcp_error(&self) -> FcpError {
        self.to_fcp_error()
    }

    fn is_retryable(&self) -> bool {
        self.is_retryable()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_error_maps_to_invalid_request() {
        let err = EmailGenericError::Config("bad config".into());
        match err.to_fcp_error() {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1003);
                assert!(message.contains("bad config"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn imap_error_maps_to_external() {
        let err = EmailGenericError::Imap("connection refused".into());
        match err.to_fcp_error() {
            FcpError::External {
                service,
                message,
                retryable,
                ..
            } => {
                assert_eq!(service, "email_generic");
                assert!(message.contains("connection refused"));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn smtp_error_maps_to_external() {
        let err = EmailGenericError::Smtp("auth failed".into());
        match err.to_fcp_error() {
            FcpError::External {
                service, retryable, ..
            } => {
                assert_eq!(service, "email_generic");
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn io_error_maps_to_retryable_external() {
        let err = EmailGenericError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "reset",
        ));
        match err.to_fcp_error() {
            FcpError::External { retryable, .. } => {
                assert!(retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn address_error_maps_to_invalid_request() {
        let err = EmailGenericError::Address("invalid email".into());
        match err.to_fcp_error() {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1005);
                assert!(message.contains("invalid email"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn io_error_is_retryable() {
        let err =
            EmailGenericError::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout"));
        assert!(err.is_retryable());
    }

    #[test]
    fn config_error_is_not_retryable() {
        let err = EmailGenericError::Config("bad".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn imap_error_is_not_retryable() {
        let err = EmailGenericError::Imap("failed".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn smtp_error_is_not_retryable() {
        let err = EmailGenericError::Smtp("relay denied".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn address_error_is_not_retryable() {
        let err = EmailGenericError::Address("bad@".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn error_display_config() {
        let err = EmailGenericError::Config("missing host".into());
        assert_eq!(err.to_string(), "configuration error: missing host");
    }

    #[test]
    fn error_display_imap() {
        let err = EmailGenericError::Imap("NO LOGIN failed".into());
        assert_eq!(err.to_string(), "imap error: NO LOGIN failed");
    }

    #[test]
    fn error_display_smtp() {
        let err = EmailGenericError::Smtp("relay denied".into());
        assert_eq!(err.to_string(), "smtp error: relay denied");
    }

    #[test]
    fn error_display_address() {
        let err = EmailGenericError::Address("invalid syntax".into());
        assert_eq!(err.to_string(), "address error: invalid syntax");
    }

    #[test]
    fn io_error_converts_via_from() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
        let err: EmailGenericError = io_err.into();
        assert!(matches!(err, EmailGenericError::Io(_)));
    }

    #[test]
    fn connector_error_mapping_from_timeout() {
        use fcp_sdk::migration::ConnectorErrorMapping;
        let err = EmailGenericError::from_async_error(fcp_async_core::AsyncError::Timeout {
            timeout_ms: 5000,
        });
        assert!(matches!(err, EmailGenericError::Imap(_)));
        let msg = err.to_string();
        assert!(msg.contains("5000"));
    }

    #[test]
    fn connector_error_mapping_from_cancelled() {
        use fcp_sdk::migration::ConnectorErrorMapping;
        let err = EmailGenericError::from_async_error(fcp_async_core::AsyncError::Cancelled);
        assert!(matches!(err, EmailGenericError::Imap(_)));
        assert!(err.to_string().contains("cancelled"));
    }
}
