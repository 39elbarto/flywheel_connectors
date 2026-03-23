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
            Self::Tls(error) | Self::Address(error) => FcpError::Internal {
                message: error.to_string(),
            },
        }
    }
}

