//! Error mapping that never exposes provider payloads or credentials.

use std::time::Duration;

use fcp_prelude::FcpError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DriveActivityError {
    #[error("Google Drive Activity transport failed")]
    Http(#[from] reqwest::Error),
    #[error("Google Drive Activity response could not be decoded")]
    Json(#[from] serde_json::Error),
    #[error("Google Drive Activity API rejected the request ({status_code})")]
    Api { status_code: u16 },
    #[error("Google Drive Activity credentials are invalid or expired")]
    Unauthorized,
    #[error("Google Drive Activity permission denied")]
    Forbidden,
    #[error("Google Drive Activity rate limited the request")]
    RateLimited { retry_after_ms: u64 },
    #[error("Google Drive Activity response exceeds the 60000 byte caller boundary")]
    Oversize,
}

impl DriveActivityError {
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Http(_)
                | Self::RateLimited { .. }
                | Self::Api {
                    status_code: 500..=599
                }
        )
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
                message: "Google Drive Activity authorization failed".into(),
            },
            Self::RateLimited { retry_after_ms } => FcpError::RateLimited {
                retry_after_ms: *retry_after_ms,
                violation: None,
            },
            Self::Oversize => FcpError::InvalidRequest {
                code: 1001,
                message: "Drive Activity response is too large; request a smaller page".into(),
            },
            Self::Json(_) => FcpError::Internal {
                message: "Google Drive Activity response could not be decoded".into(),
            },
            Self::Http(error) => FcpError::External {
                service: "google_drive_activity".into(),
                message: "Google Drive Activity transport failed".into(),
                status_code: error.status().map(|status| status.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Api { status_code } => FcpError::External {
                service: "google_drive_activity".into(),
                message: "Google Drive Activity provider rejected the request".into(),
                status_code: Some(*status_code),
                retryable: self.is_retryable(),
                retry_after: None,
            },
        }
    }
}

impl fcp_sdk::ConnectorErrorMapping for DriveActivityError {
    fn from_async_error(error: fcp_async_core::AsyncError) -> Self {
        match error {
            fcp_async_core::AsyncError::Timeout { .. } => Self::Api { status_code: 408 },
            _ => Self::Api { status_code: 0 },
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

pub type DriveActivityResult<T> = Result<T, DriveActivityError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_classes_have_stable_safe_mapping() {
        for status_code in [400, 500, 503] {
            let error = DriveActivityError::Api { status_code };
            let mapped = error.to_fcp_error();
            assert!(!mapped.to_string().contains("provider payload"));
            assert_eq!(error.is_retryable(), status_code >= 500);
        }
        assert!(matches!(
            DriveActivityError::Unauthorized.to_fcp_error(),
            FcpError::Unauthorized { .. }
        ));
        assert!(matches!(
            DriveActivityError::Forbidden.to_fcp_error(),
            FcpError::Unauthorized { .. }
        ));
        assert!(matches!(
            DriveActivityError::RateLimited {
                retry_after_ms: 123
            }
            .to_fcp_error(),
            FcpError::RateLimited {
                retry_after_ms: 123,
                ..
            }
        ));
    }

    #[test]
    fn timeout_mapping_is_redacted_and_not_retryable_provider_status() {
        use fcp_sdk::ConnectorErrorMapping;
        let error = DriveActivityError::from_async_error(fcp_async_core::AsyncError::Timeout {
            timeout_ms: 30_000,
        });
        assert!(matches!(
            error,
            DriveActivityError::Api { status_code: 408 }
        ));
        assert!(!error.to_string().contains("30000"));
    }
}
