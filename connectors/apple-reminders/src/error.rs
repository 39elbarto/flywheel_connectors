//! Error types for the `Apple Reminders` connector.

use fcp_prelude::FcpError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppleRemindersError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("unsupported platform: {0}")]
    UnsupportedPlatform(String),

    #[error("process error: {0}")]
    Process(String),

    #[error("parse error: {0}")]
    Parse(String),
}

pub type AppleRemindersResult<T> = Result<T, AppleRemindersError>;

impl AppleRemindersError {
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
        false
    }
}

impl fcp_sdk::migration::ConnectorErrorMapping for AppleRemindersError {
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
        let err = AppleRemindersError::Config("bad".into());
        assert!(matches!(
            err.to_fcp_error(),
            FcpError::InvalidRequest { .. }
        ));
    }

    #[test]
    fn unsupported_maps_to_unavailable() {
        let err = AppleRemindersError::UnsupportedPlatform("Linux".into());
        assert!(matches!(
            err.to_fcp_error(),
            FcpError::ConnectorUnavailable { .. }
        ));
    }

    #[test]
    fn process_error_maps_to_internal() {
        let err = AppleRemindersError::Process("failed".into());
        assert!(matches!(err.to_fcp_error(), FcpError::Internal { .. }));
    }

    #[test]
    fn parse_error_maps_to_internal() {
        let err = AppleRemindersError::Parse("bad".into());
        assert!(matches!(err.to_fcp_error(), FcpError::Internal { .. }));
    }

    #[test]
    fn no_errors_are_retryable() {
        assert!(!AppleRemindersError::Config("x".into()).is_retryable());
        assert!(!AppleRemindersError::Process("x".into()).is_retryable());
        assert!(!AppleRemindersError::Parse("x".into()).is_retryable());
        assert!(!AppleRemindersError::UnsupportedPlatform("x".into()).is_retryable());
    }

    #[test]
    fn error_display_config() {
        assert_eq!(
            AppleRemindersError::Config("m".into()).to_string(),
            "configuration error: m"
        );
    }

    #[test]
    fn error_display_unsupported() {
        assert_eq!(
            AppleRemindersError::UnsupportedPlatform("L".into()).to_string(),
            "unsupported platform: L"
        );
    }

    #[test]
    fn error_display_process() {
        assert_eq!(
            AppleRemindersError::Process("p".into()).to_string(),
            "process error: p"
        );
    }

    #[test]
    fn error_display_parse() {
        assert_eq!(
            AppleRemindersError::Parse("q".into()).to_string(),
            "parse error: q"
        );
    }

    #[test]
    fn connector_error_mapping_from_timeout() {
        use fcp_sdk::migration::ConnectorErrorMapping;
        let err = AppleRemindersError::from_async_error(fcp_async_core::AsyncError::Timeout {
            timeout_ms: 5000,
        });
        assert!(err.to_string().contains("5000"));
    }

    #[test]
    fn connector_error_mapping_from_cancelled() {
        use fcp_sdk::migration::ConnectorErrorMapping;
        let err = AppleRemindersError::from_async_error(fcp_async_core::AsyncError::Cancelled);
        assert!(err.to_string().contains("cancelled"));
    }
}
