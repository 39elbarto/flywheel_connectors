//! Error types for the `Apple Notes` connector.

use fcp_prelude::FcpError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppleNotesError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("unsupported platform: {0}")]
    UnsupportedPlatform(String),

    #[error("process error: {0}")]
    Process(String),

    #[error("parse error: {0}")]
    Parse(String),
}

pub type AppleNotesResult<T> = Result<T, AppleNotesError>;

impl AppleNotesError {
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Config(message) => FcpError::InvalidRequest {
                code: 1003,
                message: message.clone(),
            },
            Self::UnsupportedPlatform(message) => FcpError::ConnectorUnavailable {
                code: 5001,
                message: message.clone(),
            },
            Self::Process(message) | Self::Parse(message) => FcpError::Internal {
                message: message.clone(),
            },
        }
    }

    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        false // Local process errors are not retryable
    }
}

impl fcp_sdk::migration::ConnectorErrorMapping for AppleNotesError {
    fn from_async_error(error: fcp_async_core::AsyncError) -> Self {
        match error {
            fcp_async_core::AsyncError::Timeout { timeout_ms } => {
                Self::Process(format!("deadline exceeded after {timeout_ms}ms"))
            }
            fcp_async_core::AsyncError::Cancelled => Self::Process("cancelled".into()),
            other => Self::Process(other.to_string()),
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
        let err = AppleNotesError::Config("bad".into());
        assert!(matches!(
            err.to_fcp_error(),
            FcpError::InvalidRequest { .. }
        ));
    }

    #[test]
    fn unsupported_platform_maps_to_connector_unavailable() {
        let err = AppleNotesError::UnsupportedPlatform("Linux".into());
        assert!(matches!(
            err.to_fcp_error(),
            FcpError::ConnectorUnavailable { .. }
        ));
    }

    #[test]
    fn process_error_maps_to_internal() {
        let err = AppleNotesError::Process("osascript failed".into());
        assert!(matches!(err.to_fcp_error(), FcpError::Internal { .. }));
    }

    #[test]
    fn parse_error_maps_to_internal() {
        let err = AppleNotesError::Parse("bad output".into());
        assert!(matches!(err.to_fcp_error(), FcpError::Internal { .. }));
    }

    #[test]
    fn no_errors_are_retryable() {
        assert!(!AppleNotesError::Config("x".into()).is_retryable());
        assert!(!AppleNotesError::Process("x".into()).is_retryable());
        assert!(!AppleNotesError::Parse("x".into()).is_retryable());
        assert!(!AppleNotesError::UnsupportedPlatform("x".into()).is_retryable());
    }

    #[test]
    fn error_display_config() {
        assert_eq!(
            AppleNotesError::Config("missing".into()).to_string(),
            "configuration error: missing"
        );
    }

    #[test]
    fn error_display_unsupported() {
        assert_eq!(
            AppleNotesError::UnsupportedPlatform("Linux".into()).to_string(),
            "unsupported platform: Linux"
        );
    }

    #[test]
    fn error_display_process() {
        assert_eq!(
            AppleNotesError::Process("exit 1".into()).to_string(),
            "process error: exit 1"
        );
    }

    #[test]
    fn error_display_parse() {
        assert_eq!(
            AppleNotesError::Parse("bad".into()).to_string(),
            "parse error: bad"
        );
    }

    #[test]
    fn connector_error_mapping_from_timeout() {
        use fcp_sdk::migration::ConnectorErrorMapping;
        let err = AppleNotesError::from_async_error(fcp_async_core::AsyncError::Timeout {
            timeout_ms: 5000,
        });
        assert!(matches!(err, AppleNotesError::Process(_)));
        assert!(err.to_string().contains("5000"));
    }

    #[test]
    fn connector_error_mapping_from_cancelled() {
        use fcp_sdk::migration::ConnectorErrorMapping;
        let err = AppleNotesError::from_async_error(fcp_async_core::AsyncError::Cancelled);
        assert!(err.to_string().contains("cancelled"));
    }
}
