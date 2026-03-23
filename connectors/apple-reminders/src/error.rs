//! Error types for the Apple Reminders connector.

use fcp_core::FcpError;
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
}
