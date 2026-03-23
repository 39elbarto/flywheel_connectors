//! Error types for the `Sonos` connector.

use fcp_core::FcpError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SonosError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("api error: status={status}, message={message}")]
    Api { status: u16, message: String },

    #[error("parse error: {0}")]
    Parse(String),
}

pub type SonosResult<T> = Result<T, SonosError>;

impl SonosError {
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Config(message) => FcpError::InvalidRequest {
                code: 1003,
                message: message.clone(),
            },
            Self::Http(error) if error.is_timeout() => FcpError::UpstreamTimeout {
                service: "sonos".into(),
            },
            Self::Http(error) => FcpError::External {
                service: "sonos".into(),
                message: error.to_string(),
                status_code: None,
                retryable: error.is_connect() || error.is_timeout(),
                retry_after: None,
            },
            Self::Api { status, message } => FcpError::External {
                service: "sonos".into(),
                message: message.clone(),
                status_code: Some(*status),
                retryable: matches!(status, 429 | 500 | 502 | 503 | 504),
                retry_after: None,
            },
            Self::Parse(message) => FcpError::Internal {
                message: message.clone(),
            },
        }
    }
}
