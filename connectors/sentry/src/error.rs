//! Sentry-specific error types.

use std::time::Duration;

use fcp_core::FcpError;
use thiserror::Error;

/// Result alias for Sentry operations.
pub type SentryResult<T> = Result<T, SentryError>;

/// Sentry-specific errors.
#[derive(Error, Debug)]
pub enum SentryError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Sentry API returned an error
    #[error("Sentry API error ({status_code}): {message}")]
    Api { status_code: u16, message: String },

    /// Rate limited (429)
    #[error("Rate limited, retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },

    /// Authentication failed (401)
    #[error("Authentication failed: invalid or expired auth token")]
    Unauthorized,

    /// Forbidden (403)
    #[error("Forbidden: insufficient permissions")]
    Forbidden,

    /// Resource not found (404)
    #[error("Not found: {resource}")]
    NotFound { resource: String },
}

impl SentryError {
    /// Check if this error is retryable.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) => true,
            Self::RateLimited { .. } => true,
            Self::Api { status_code, .. } => matches!(status_code, 500..=599 | 429),
            _ => false,
        }
    }

    /// Get the suggested retry delay.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after_ms } => Some(Duration::from_millis(*retry_after_ms)),
            _ => None,
        }
    }

    /// Convert to FCP error.
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Http(e) => FcpError::External {
                service: "sentry".into(),
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
                service: "sentry".into(),
                message: message.clone(),
                status_code: Some(*status_code),
                retryable: self.is_retryable(),
                retry_after: None,
            },
            Self::RateLimited { retry_after_ms } => FcpError::External {
                service: "sentry".into(),
                message: format!("Rate limited, retry after {retry_after_ms}ms"),
                status_code: Some(429),
                retryable: true,
                retry_after: self.retry_after(),
            },
            Self::Unauthorized => FcpError::External {
                service: "sentry".into(),
                message: "Authentication failed".into(),
                status_code: Some(401),
                retryable: false,
                retry_after: None,
            },
            Self::Forbidden => FcpError::External {
                service: "sentry".into(),
                message: "Insufficient permissions".into(),
                status_code: Some(403),
                retryable: false,
                retry_after: None,
            },
            Self::NotFound { resource } => FcpError::External {
                service: "sentry".into(),
                message: format!("Not found: {resource}"),
                status_code: Some(404),
                retryable: false,
                retry_after: None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── is_retryable ─────────────────────────────────────────────────

    #[test]
    fn rate_limited_is_retryable() {
        let err = SentryError::RateLimited {
            retry_after_ms: 5000,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_500_is_retryable() {
        let err = SentryError::Api {
            status_code: 500,
            message: "Internal Server Error".into(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_503_is_retryable() {
        let err = SentryError::Api {
            status_code: 503,
            message: "Service Unavailable".into(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_429_is_retryable() {
        let err = SentryError::Api {
            status_code: 429,
            message: "Too Many Requests".into(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn unauthorized_not_retryable() {
        assert!(!SentryError::Unauthorized.is_retryable());
    }

    #[test]
    fn forbidden_not_retryable() {
        assert!(!SentryError::Forbidden.is_retryable());
    }

    #[test]
    fn not_found_not_retryable() {
        let err = SentryError::NotFound {
            resource: "issue".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_400_not_retryable() {
        let err = SentryError::Api {
            status_code: 400,
            message: "Bad Request".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_403_not_retryable() {
        let err = SentryError::Api {
            status_code: 403,
            message: "Forbidden".into(),
        };
        assert!(!err.is_retryable());
    }

    // ── retry_after ──────────────────────────────────────────────────

    #[test]
    fn retry_after_for_rate_limited() {
        let err = SentryError::RateLimited {
            retry_after_ms: 30_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn retry_after_none_for_other_errors() {
        assert_eq!(SentryError::Unauthorized.retry_after(), None);
        assert_eq!(SentryError::Forbidden.retry_after(), None);
        let api = SentryError::Api {
            status_code: 500,
            message: "err".into(),
        };
        assert_eq!(api.retry_after(), None);
        let nf = SentryError::NotFound {
            resource: "x".into(),
        };
        assert_eq!(nf.retry_after(), None);
    }

    // ── to_fcp_error ─────────────────────────────────────────────────

    #[test]
    fn unauthorized_to_fcp_error() {
        let fcp = SentryError::Unauthorized.to_fcp_error();
        match &fcp {
            FcpError::External {
                service,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "sentry");
                assert_eq!(*status_code, Some(401));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn forbidden_to_fcp_error() {
        let fcp = SentryError::Forbidden.to_fcp_error();
        match &fcp {
            FcpError::External {
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(*status_code, Some(403));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn not_found_to_fcp_error() {
        let fcp = SentryError::NotFound {
            resource: "my-issue".into(),
        }
        .to_fcp_error();
        match &fcp {
            FcpError::External {
                message,
                status_code,
                retryable,
                ..
            } => {
                assert!(message.contains("my-issue"));
                assert_eq!(*status_code, Some(404));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_to_fcp_error() {
        let fcp = SentryError::RateLimited {
            retry_after_ms: 60_000,
        }
        .to_fcp_error();
        match &fcp {
            FcpError::External {
                status_code,
                retryable,
                retry_after,
                ..
            } => {
                assert_eq!(*status_code, Some(429));
                assert!(retryable);
                assert_eq!(*retry_after, Some(Duration::from_secs(60)));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn api_error_to_fcp_error() {
        let fcp = SentryError::Api {
            status_code: 502,
            message: "Bad Gateway".into(),
        }
        .to_fcp_error();
        match &fcp {
            FcpError::External {
                message,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(message, "Bad Gateway");
                assert_eq!(*status_code, Some(502));
                assert!(*retryable); // 5xx is retryable
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn json_error_to_fcp_internal() {
        let bad_json: Result<serde_json::Value, _> = serde_json::from_str("{invalid");
        let err = SentryError::Json(bad_json.unwrap_err());
        let fcp = err.to_fcp_error();
        match &fcp {
            FcpError::Internal { message } => {
                assert!(message.starts_with("JSON error:"));
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    // ── Display ──────────────────────────────────────────────────────

    #[test]
    fn error_display_messages() {
        assert_eq!(
            SentryError::Unauthorized.to_string(),
            "Authentication failed: invalid or expired auth token"
        );
        assert_eq!(
            SentryError::Forbidden.to_string(),
            "Forbidden: insufficient permissions"
        );
        let nf = SentryError::NotFound {
            resource: "project".into(),
        };
        assert_eq!(nf.to_string(), "Not found: project");

        let rl = SentryError::RateLimited {
            retry_after_ms: 1000,
        };
        assert_eq!(rl.to_string(), "Rate limited, retry after 1000ms");

        let api = SentryError::Api {
            status_code: 500,
            message: "Internal".into(),
        };
        assert_eq!(api.to_string(), "Sentry API error (500): Internal");
    }
}
