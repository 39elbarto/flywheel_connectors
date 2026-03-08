//! Whisper-specific error types.

use std::time::Duration;

use fcp_core::FcpError;
use thiserror::Error;

/// Result alias for Whisper operations.
pub type WhisperResult<T> = Result<T, WhisperError>;

/// Whisper-specific errors.
#[derive(Error, Debug)]
pub enum WhisperError {
    /// Whisper API connection error
    #[error("Whisper API connection error: {0}")]
    Connection(String),

    /// Whisper authentication error
    #[error("Whisper authentication error: {0}")]
    Auth(String),

    /// Whisper transcription error
    #[error("Whisper transcription error: {0}")]
    Transcription(String),

    /// Whisper unsupported format
    #[error("Whisper unsupported format: {0}")]
    UnsupportedFormat(String),

    /// Whisper file too large
    #[error("Whisper file too large: {size_bytes} bytes (max {max_bytes})")]
    FileTooLarge { size_bytes: u64, max_bytes: u64 },

    /// Whisper model not found
    #[error("Whisper model not found: {0}")]
    ModelNotFound(String),

    /// Whisper timeout
    #[error("Whisper timeout: {0}")]
    Timeout(String),

    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Whisper rate limited
    #[error("Whisper rate limited (retry after {retry_after_ms}ms)")]
    RateLimited { retry_after_ms: u64 },

    /// Whisper invalid audio
    #[error("Whisper invalid audio: {0}")]
    InvalidAudio(String),

    /// Whisper API returned an error
    #[error("Whisper API error ({status_code}): {message}")]
    Api { status_code: u16, message: String },
}

impl WhisperError {
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::RateLimited { .. } | Self::Connection(_) | Self::Timeout(_) => {
                true
            }
            Self::Api { status_code, .. } => matches!(status_code, 500..=599 | 429),
            _ => false,
        }
    }

    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after_ms } => Some(Duration::from_millis(*retry_after_ms)),
            _ => None,
        }
    }

    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Http(e) => FcpError::External {
                service: "whisper".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
            Self::Connection(msg) => FcpError::External {
                service: "whisper".into(),
                message: msg.clone(),
                status_code: None,
                retryable: true,
                retry_after: None,
            },
            Self::Auth(msg) => FcpError::External {
                service: "whisper".into(),
                message: msg.clone(),
                status_code: Some(401),
                retryable: false,
                retry_after: None,
            },
            Self::Transcription(msg) => FcpError::External {
                service: "whisper".into(),
                message: msg.clone(),
                status_code: None,
                retryable: false,
                retry_after: None,
            },
            Self::UnsupportedFormat(fmt) => FcpError::External {
                service: "whisper".into(),
                message: format!("Unsupported format: {fmt}"),
                status_code: Some(400),
                retryable: false,
                retry_after: None,
            },
            Self::FileTooLarge {
                size_bytes,
                max_bytes,
            } => FcpError::External {
                service: "whisper".into(),
                message: format!("File too large: {size_bytes} bytes (max {max_bytes})"),
                status_code: Some(413),
                retryable: false,
                retry_after: None,
            },
            Self::ModelNotFound(model) => FcpError::External {
                service: "whisper".into(),
                message: format!("Model not found: {model}"),
                status_code: Some(404),
                retryable: false,
                retry_after: None,
            },
            Self::Timeout(msg) => FcpError::External {
                service: "whisper".into(),
                message: msg.clone(),
                status_code: None,
                retryable: true,
                retry_after: None,
            },
            Self::RateLimited { retry_after_ms } => FcpError::External {
                service: "whisper".into(),
                message: format!("Rate limited (retry after {retry_after_ms}ms)"),
                status_code: Some(429),
                retryable: true,
                retry_after: self.retry_after(),
            },
            Self::InvalidAudio(msg) => FcpError::External {
                service: "whisper".into(),
                message: msg.clone(),
                status_code: Some(400),
                retryable: false,
                retry_after: None,
            },
            Self::Api {
                status_code,
                message,
            } => FcpError::External {
                service: "whisper".into(),
                message: message.clone(),
                status_code: Some(*status_code),
                retryable: self.is_retryable(),
                retry_after: None,
            },
        }
    }
}
