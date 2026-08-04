//! Google Apps Script connector errors.

use std::time::Duration;

use fcp_prelude::FcpError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ScriptError {
    #[error("HTTP request failed")]
    Http(#[from] reqwest::Error),
    #[error("invalid provider JSON")]
    Json(#[from] serde_json::Error),
    #[error("Apps Script API rejected the request ({status_code}): {message}")]
    Api { status_code: u16, message: String },
    #[error("Apps Script credentials are invalid or expired")]
    Unauthorized,
    #[error("Apps Script permission denied")]
    Forbidden,
    #[error("Apps Script resource was not found")]
    NotFound,
    #[error("Apps Script API rate limit; retry after {retry_after_ms} ms")]
    RateLimited { retry_after_ms: u64 },
    #[error("source replacement validation failed: {0}")]
    UnsafeSourceReplacement(String),
}

impl ScriptError {
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Http(_)
                | Self::RateLimited { .. }
                | Self::Api {
                    status_code: 500..=599,
                    ..
                }
        )
    }

    #[must_use]
    pub fn replay_is_safe(&self) -> bool {
        match self {
            Self::RateLimited { .. } => true,
            Self::Http(error) => !fcp_sdk::migration::transport_error_reached_service(error),
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
            Self::Unauthorized | Self::Forbidden => FcpError::Unauthorized {
                code: 2001,
                message: self.to_string(),
            },
            Self::NotFound => FcpError::ResourceNotFound {
                resource: "google-apps-script resource".into(),
            },
            Self::RateLimited { retry_after_ms } => FcpError::RateLimited {
                retry_after_ms: *retry_after_ms,
                violation: None,
            },
            Self::Json(error) => FcpError::Internal {
                message: format!("Apps Script response decode failed: {error}"),
            },
            Self::UnsafeSourceReplacement(message) => FcpError::InvalidRequest {
                code: 1003,
                message: message.clone(),
            },
            Self::Http(error) => FcpError::External {
                service: "google_apps_script".into(),
                message: "Apps Script transport failure".into(),
                status_code: error.status().map(|status| status.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Api {
                status_code,
                message,
            } => FcpError::External {
                service: "google_apps_script".into(),
                message: message.clone(),
                status_code: Some(*status_code),
                retryable: self.is_retryable(),
                retry_after: None,
            },
        }
    }
}

impl fcp_sdk::ConnectorErrorMapping for ScriptError {
    fn from_async_error(error: fcp_async_core::AsyncError) -> Self {
        match error {
            fcp_async_core::AsyncError::Timeout { timeout_ms } => Self::Api {
                status_code: 408,
                message: format!("deadline exceeded after {timeout_ms}ms"),
            },
            fcp_async_core::AsyncError::Cancelled => Self::Api {
                status_code: 0,
                message: "request cancelled".into(),
            },
            other => Self::Api {
                status_code: 0,
                message: other.to_string(),
            },
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

pub type ScriptResult<T> = Result<T, ScriptError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_refused_rate_limit_is_replay_safe_without_transport_evidence() {
        assert!(ScriptError::RateLimited { retry_after_ms: 1 }.replay_is_safe());
        assert!(
            !ScriptError::Api {
                status_code: 503,
                message: "unknown outcome".into()
            }
            .replay_is_safe()
        );
    }
}
