use std::time::Duration;

use fcp_prelude::FcpError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ComfyUiError {
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("provider returned HTTP {status}: {message}")]
    Provider { status: u16, message: String },
    #[error("provider rate limited request")]
    RateLimited { retry_after: Option<Duration> },
    #[error("provider resource not found: {0}")]
    NotFound(String),
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("provider JSON was invalid: {0}")]
    Json(#[from] serde_json::Error),
}

impl ComfyUiError {
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::InvalidInput(message) => FcpError::InvalidRequest {
                code: 1003,
                message: safe_provider_message(message),
            },
            Self::Provider { status, message } => FcpError::External {
                service: "comfyui".into(),
                message: safe_provider_message(message),
                status_code: Some(*status),
                retryable: *status >= 500,
                retry_after: None,
            },
            Self::RateLimited { retry_after } => FcpError::RateLimited {
                retry_after_ms: duration_millis(*retry_after),
                violation: None,
            },
            Self::NotFound(resource) => FcpError::ResourceNotFound {
                resource: safe_provider_message(resource),
            },
            Self::Http(error) if error.is_timeout() => FcpError::ConnectorUnavailable {
                code: 5000,
                message: "ComfyUI request timed out".into(),
            },
            Self::Http(error) => FcpError::External {
                service: "comfyui".into(),
                message: safe_provider_message(&error.to_string()),
                status_code: error.status().map(|status| status.as_u16()),
                retryable: true,
                retry_after: None,
            },
            Self::Json(error) => FcpError::External {
                service: "comfyui".into(),
                message: safe_provider_message(&error.to_string()),
                status_code: None,
                retryable: false,
                retry_after: None,
            },
        }
    }
}

pub fn safe_provider_message(message: &str) -> String {
    let mut sanitized = message.replace(['\r', '\n', '\0'], " ");
    let lower = sanitized.to_ascii_lowercase();
    if lower.contains("authorization")
        || lower.contains("bearer ")
        || lower.contains("api_key")
        || lower.contains("token")
        || lower.contains("workflow")
        || lower.contains("prompt")
    {
        return "provider message redacted".into();
    }
    if sanitized.len() > 512 {
        sanitized.truncate(512);
        sanitized.push_str("...");
    }
    sanitized
}

fn duration_millis(duration: Option<Duration>) -> u64 {
    duration.map_or(0, |duration| {
        u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
    })
}
