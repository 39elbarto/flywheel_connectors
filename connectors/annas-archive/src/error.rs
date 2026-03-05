use std::time::Duration;

use fcp_core::FcpError;

pub type AnnasArchiveResult<T> = Result<T, AnnasArchiveError>;

#[derive(Debug, thiserror::Error)]
pub enum AnnasArchiveError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("API error (status {status_code}): {message}")]
    Api { status_code: u16, message: String },

    #[error("Rate limited")]
    RateLimited { retry_after_ms: u64 },

    #[error("Not found: {resource}")]
    NotFound { resource: String },

    #[error("Service unavailable")]
    ServiceUnavailable,
}

impl AnnasArchiveError {
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::RateLimited { .. } | Self::ServiceUnavailable | Self::Http(_)
        )
    }

    #[must_use]
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after_ms } => Some(Duration::from_millis(*retry_after_ms)),
            Self::ServiceUnavailable => Some(Duration::from_secs(5)),
            _ => None,
        }
    }

    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Http(e) => FcpError::External {
                service: "annas-archive".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
            Self::Api {
                status_code,
                message,
            } => FcpError::External {
                service: "annas-archive".into(),
                message: message.clone(),
                status_code: Some(*status_code),
                retryable: self.is_retryable(),
                retry_after: None,
            },
            Self::RateLimited { retry_after_ms } => FcpError::External {
                service: "annas-archive".into(),
                message: format!("Rate limited, retry after {retry_after_ms}ms"),
                status_code: Some(429),
                retryable: true,
                retry_after: self.retry_after(),
            },
            Self::NotFound { resource } => FcpError::ResourceNotFound {
                resource: resource.clone(),
            },
            Self::ServiceUnavailable => FcpError::External {
                service: "annas-archive".into(),
                message: "Service unavailable".into(),
                status_code: Some(503),
                retryable: true,
                retry_after: self.retry_after(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limited_is_retryable() {
        let err = AnnasArchiveError::RateLimited {
            retry_after_ms: 60_000,
        };
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(Duration::from_millis(60_000)));
    }

    #[test]
    fn not_found_is_not_retryable() {
        let err = AnnasArchiveError::NotFound {
            resource: "md5:abc".into(),
        };
        assert!(!err.is_retryable());
        assert!(err.retry_after().is_none());
    }

    #[test]
    fn api_error_is_not_retryable() {
        let err = AnnasArchiveError::Api {
            status_code: 400,
            message: "Bad request".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn service_unavailable_is_retryable() {
        let err = AnnasArchiveError::ServiceUnavailable;
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn json_error_is_not_retryable() {
        let err: AnnasArchiveError =
            serde_json::from_str::<serde_json::Value>("invalid").unwrap_err().into();
        assert!(!err.is_retryable());
    }

    #[test]
    fn fcp_error_rate_limited() {
        let err = AnnasArchiveError::RateLimited {
            retry_after_ms: 1000,
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::External { retryable: true, .. }));
    }

    #[test]
    fn fcp_error_not_found() {
        let err = AnnasArchiveError::NotFound {
            resource: "isbn:123".into(),
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::ResourceNotFound { .. }));
    }

    #[test]
    fn fcp_error_api() {
        let err = AnnasArchiveError::Api {
            status_code: 500,
            message: "Internal".into(),
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::External { .. }));
    }

    #[test]
    fn fcp_error_unavailable() {
        let err = AnnasArchiveError::ServiceUnavailable;
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::External { retryable: true, .. }));
    }

    #[test]
    fn error_display_api() {
        let err = AnnasArchiveError::Api {
            status_code: 422,
            message: "Unprocessable".into(),
        };
        let s = err.to_string();
        assert!(s.contains("422"));
        assert!(s.contains("Unprocessable"));
    }

    #[test]
    fn error_display_not_found() {
        let err = AnnasArchiveError::NotFound {
            resource: "md5:abc123".into(),
        };
        assert!(err.to_string().contains("md5:abc123"));
    }

    #[test]
    fn error_display_rate_limited() {
        let err = AnnasArchiveError::RateLimited {
            retry_after_ms: 30_000,
        };
        assert!(err.to_string().contains("Rate limited"));
    }
}
