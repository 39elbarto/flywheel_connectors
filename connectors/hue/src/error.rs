//! Error types for the Hue connector.

use fcp_core::FcpError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HueError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("api error: status={status}, message={message}")]
    Api { status: u16, message: String },

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type HueResult<T> = Result<T, HueError>;

impl HueError {
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Config(message) => FcpError::InvalidRequest {
                code: 1003,
                message: message.clone(),
            },
            Self::Http(error) if error.is_timeout() => FcpError::UpstreamTimeout {
                service: "hue".into(),
            },
            Self::Http(error) => FcpError::External {
                service: "hue".into(),
                message: error.to_string(),
                status_code: None,
                retryable: error.is_connect() || error.is_timeout(),
                retry_after: None,
            },
            Self::Api { status, message } => FcpError::External {
                service: "hue".into(),
                message: message.clone(),
                status_code: Some(*status),
                retryable: matches!(status, 429 | 500 | 502 | 503 | 504),
                retry_after: None,
            },
            Self::Json(error) => FcpError::Internal {
                message: format!("Failed to decode Hue response: {error}"),
            },
        }
    }
}

