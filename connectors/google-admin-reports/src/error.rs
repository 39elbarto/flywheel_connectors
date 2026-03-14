//! Google Admin Reports-specific error types.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_core::FcpError;
use fcp_sdk::migration::ConnectorErrorMapping;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AdminReportsError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Admin Reports API error ({status_code}): {message}")]
    Api { status_code: u16, message: String },

    #[error("Rate limited, retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },

    #[error("Invalid or expired credentials")]
    Unauthorized,

    #[error("Insufficient admin permissions: {message}")]
    Forbidden { message: String },
}

impl AdminReportsError {
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::RateLimited { .. } => true,
            Self::Api { status_code, .. } => matches!(status_code, 500..=599 | 429),
            _ => false,
        }
    }

    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after_secs } => {
                Some(Duration::from_secs(*retry_after_secs))
            }
            _ => None,
        }
    }

    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Http(e) => FcpError::External {
                service: "google_admin_reports".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
            Self::Api {
                status_code: 401, ..
            }
            | Self::Api {
                status_code: 403, ..
            } => FcpError::Unauthorized {
                code: 2001,
                message: "Admin Reports auth/permission failure".into(),
            },
            Self::Api {
                status_code: 429, ..
            } => FcpError::RateLimited {
                retry_after_ms: 60_000,
                violation: None,
            },
            Self::Api {
                status_code,
                message,
            } => FcpError::External {
                service: "google_admin_reports".into(),
                message: message.clone(),
                status_code: Some(*status_code),
                retryable: self.is_retryable(),
                retry_after: None,
            },
            Self::RateLimited { retry_after_secs } => FcpError::RateLimited {
                retry_after_ms: retry_after_secs * 1000,
                violation: None,
            },
            Self::Unauthorized => FcpError::Unauthorized {
                code: 2001,
                message: "Invalid or expired admin credentials".into(),
            },
            Self::Forbidden { message } => FcpError::Unauthorized {
                code: 2001,
                message: format!("Admin permission denied: {message}"),
            },
        }
    }
}

impl ConnectorErrorMapping for AdminReportsError {
    fn from_async_error(error: AsyncError) -> Self {
        match error {
            AsyncError::Timeout { timeout_ms } => Self::Api {
                status_code: 408,
                message: format!("deadline exceeded after {timeout_ms}ms"),
            },
            AsyncError::Cancelled => Self::Api {
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

pub type AdminReportsResult<T> = Result<T, AdminReportsError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unauthorized_not_retryable() {
        assert!(!AdminReportsError::Unauthorized.is_retryable());
    }

    #[test]
    fn rate_limited_is_retryable() {
        assert!(AdminReportsError::RateLimited { retry_after_secs: 5 }.is_retryable());
    }

    #[test]
    fn api_500_is_retryable() {
        assert!(AdminReportsError::Api { status_code: 500, message: "err".into() }.is_retryable());
    }

    #[test]
    fn to_fcp_error_unauthorized() {
        match AdminReportsError::Unauthorized.to_fcp_error() {
            FcpError::Unauthorized { code, .. } => assert_eq!(code, 2001),
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_rate_limited() {
        match (AdminReportsError::RateLimited { retry_after_secs: 30 }).to_fcp_error() {
            FcpError::RateLimited { retry_after_ms, .. } => assert_eq!(retry_after_ms, 30_000),
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }
}
