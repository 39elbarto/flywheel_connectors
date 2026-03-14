//! `PandaDoc`-specific error types.

use std::time::Duration;

use fcp_core::FcpError;
use fcp_async_core::AsyncError;
use fcp_sdk::migration::ConnectorErrorMapping;
use thiserror::Error;

/// Result alias for `PandaDoc` operations.
pub type PandaDocResult<T> = Result<T, PandaDocError>;

/// `PandaDoc`-specific errors.
#[derive(Error, Debug)]
pub enum PandaDocError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// `PandaDoc` API returned an error
    #[error("PandaDoc API error ({status_code}): {message}")]
    Api { status_code: u16, message: String },

    /// Rate limited (429)
    #[error("Rate limited, retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },

    /// Authentication failed (401)
    #[error("Authentication failed: invalid or expired API key")]
    Unauthorized,

    /// Forbidden (403)
    #[error("Forbidden: insufficient permissions")]
    Forbidden,

    /// Resource not found (404)
    #[error("Not found: {resource}")]
    NotFound { resource: String },
}

impl PandaDocError {
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
            Self::RateLimited { retry_after_ms } => Some(Duration::from_millis(*retry_after_ms)),
            _ => None,
        }
    }

    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Http(e) => FcpError::External {
                service: "pandadoc".into(),
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
                service: "pandadoc".into(),
                message: message.clone(),
                status_code: Some(*status_code),
                retryable: self.is_retryable(),
                retry_after: None,
            },
            Self::RateLimited { retry_after_ms } => FcpError::External {
                service: "pandadoc".into(),
                message: format!("Rate limited, retry after {retry_after_ms}ms"),
                status_code: Some(429),
                retryable: true,
                retry_after: self.retry_after(),
            },
            Self::Unauthorized => FcpError::External {
                service: "pandadoc".into(),
                message: "Authentication failed".into(),
                status_code: Some(401),
                retryable: false,
                retry_after: None,
            },
            Self::Forbidden => FcpError::External {
                service: "pandadoc".into(),
                message: "Insufficient permissions".into(),
                status_code: Some(403),
                retryable: false,
                retry_after: None,
            },
            Self::NotFound { resource } => FcpError::External {
                service: "pandadoc".into(),
                message: format!("Not found: {resource}"),
                status_code: Some(404),
                retryable: false,
                retry_after: None,
            },
        }
    }
}


impl ConnectorErrorMapping for PandaDocError {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limited_is_retryable() {
        assert!(
            PandaDocError::RateLimited {
                retry_after_ms: 5000
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_500_is_retryable() {
        assert!(
            PandaDocError::Api {
                status_code: 500,
                message: "err".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_503_is_retryable() {
        assert!(
            PandaDocError::Api {
                status_code: 503,
                message: "unavailable".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_429_is_retryable() {
        assert!(
            PandaDocError::Api {
                status_code: 429,
                message: "too many".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn unauthorized_not_retryable() {
        assert!(!PandaDocError::Unauthorized.is_retryable());
    }

    #[test]
    fn forbidden_not_retryable() {
        assert!(!PandaDocError::Forbidden.is_retryable());
    }

    #[test]
    fn not_found_not_retryable() {
        assert!(
            !PandaDocError::NotFound {
                resource: "document".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_400_not_retryable() {
        assert!(
            !PandaDocError::Api {
                status_code: 400,
                message: "bad request".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn retry_after_for_rate_limited() {
        let err = PandaDocError::RateLimited {
            retry_after_ms: 30_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn retry_after_none_for_unauthorized() {
        assert_eq!(PandaDocError::Unauthorized.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_forbidden() {
        assert_eq!(PandaDocError::Forbidden.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_api_error() {
        assert_eq!(
            PandaDocError::Api {
                status_code: 500,
                message: "err".into()
            }
            .retry_after(),
            None
        );
    }

    #[test]
    fn retry_after_none_for_not_found() {
        assert_eq!(
            PandaDocError::NotFound {
                resource: "x".into()
            }
            .retry_after(),
            None
        );
    }

    #[test]
    fn unauthorized_to_fcp_error() {
        match PandaDocError::Unauthorized.to_fcp_error() {
            FcpError::External {
                service,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "pandadoc");
                assert_eq!(status_code, Some(401));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn forbidden_to_fcp_error() {
        match PandaDocError::Forbidden.to_fcp_error() {
            FcpError::External {
                service,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "pandadoc");
                assert_eq!(status_code, Some(403));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn not_found_to_fcp_error() {
        match (PandaDocError::NotFound {
            resource: "doc_abc".into(),
        })
        .to_fcp_error()
        {
            FcpError::External {
                status_code,
                message,
                retryable,
                ..
            } => {
                assert_eq!(status_code, Some(404));
                assert!(message.contains("doc_abc"));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_to_fcp_error() {
        match (PandaDocError::RateLimited {
            retry_after_ms: 60_000,
        })
        .to_fcp_error()
        {
            FcpError::External {
                status_code,
                retryable,
                retry_after,
                ..
            } => {
                assert_eq!(status_code, Some(429));
                assert!(retryable);
                assert_eq!(retry_after, Some(Duration::from_secs(60)));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn api_error_to_fcp_error() {
        match (PandaDocError::Api {
            status_code: 503,
            message: "unavailable".into(),
        })
        .to_fcp_error()
        {
            FcpError::External {
                service,
                status_code,
                retryable,
                message,
                ..
            } => {
                assert_eq!(service, "pandadoc");
                assert_eq!(status_code, Some(503));
                assert!(retryable);
                assert_eq!(message, "unavailable");
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn json_error_to_fcp_internal() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{invalid");
        match PandaDocError::Json(bad.unwrap_err()).to_fcp_error() {
            FcpError::Internal { message } => assert!(message.starts_with("JSON error:")),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn api_error_non_retryable_to_fcp_error() {
        match (PandaDocError::Api {
            status_code: 400,
            message: "bad".into(),
        })
        .to_fcp_error()
        {
            FcpError::External {
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(status_code, Some(400));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn error_display_unauthorized() {
        assert_eq!(
            PandaDocError::Unauthorized.to_string(),
            "Authentication failed: invalid or expired API key"
        );
    }

    #[test]
    fn error_display_forbidden() {
        assert_eq!(
            PandaDocError::Forbidden.to_string(),
            "Forbidden: insufficient permissions"
        );
    }

    #[test]
    fn error_display_not_found() {
        assert_eq!(
            PandaDocError::NotFound {
                resource: "document".into()
            }
            .to_string(),
            "Not found: document"
        );
    }

    #[test]
    fn error_display_rate_limited() {
        assert_eq!(
            PandaDocError::RateLimited {
                retry_after_ms: 2000
            }
            .to_string(),
            "Rate limited, retry after 2000ms"
        );
    }

    #[test]
    fn error_display_api() {
        assert_eq!(
            PandaDocError::Api {
                status_code: 500,
                message: "Internal".into()
            }
            .to_string(),
            "PandaDoc API error (500): Internal"
        );
    }

    // ── Additional edge cases ───────────────────────────────────

    #[test]
    fn api_502_is_retryable() {
        assert!(
            PandaDocError::Api {
                status_code: 502,
                message: "bad gateway".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_599_is_retryable() {
        assert!(
            PandaDocError::Api {
                status_code: 599,
                message: "custom".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_499_not_retryable() {
        assert!(
            !PandaDocError::Api {
                status_code: 499,
                message: "client err".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_404_not_retryable() {
        assert!(
            !PandaDocError::Api {
                status_code: 404,
                message: "not found".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn json_error_not_retryable() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{bad");
        let err = PandaDocError::Json(bad.unwrap_err());
        assert!(!err.is_retryable());
    }

    #[test]
    fn retry_after_none_for_json_error() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{bad");
        let err = PandaDocError::Json(bad.unwrap_err());
        assert_eq!(err.retry_after(), None);
    }

    #[test]
    fn rate_limited_zero_ms() {
        let err = PandaDocError::RateLimited { retry_after_ms: 0 };
        assert_eq!(err.retry_after(), Some(Duration::from_millis(0)));
        assert!(err.is_retryable());
    }

    #[test]
    fn rate_limited_large_value() {
        let err = PandaDocError::RateLimited {
            retry_after_ms: 3_600_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(3600)));
    }

    #[test]
    fn not_found_empty_resource() {
        let err = PandaDocError::NotFound {
            resource: String::new(),
        };
        assert_eq!(err.to_string(), "Not found: ");
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_error_empty_message() {
        let err = PandaDocError::Api {
            status_code: 500,
            message: String::new(),
        };
        assert_eq!(err.to_string(), "PandaDoc API error (500): ");
        assert!(err.is_retryable());
    }

    #[test]
    fn error_debug_format() {
        let err = PandaDocError::Unauthorized;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Unauthorized"));
    }

    #[test]
    fn api_error_debug_shows_fields() {
        let err = PandaDocError::Api {
            status_code: 422,
            message: "unprocessable".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("422"));
        assert!(dbg.contains("unprocessable"));
    }

    #[test]
    fn not_found_to_fcp_error_message_content() {
        let err = PandaDocError::NotFound {
            resource: "doc_special_123".into(),
        };
        match err.to_fcp_error() {
            FcpError::External {
                message,
                retry_after,
                ..
            } => {
                assert!(message.contains("doc_special_123"));
                assert_eq!(retry_after, None);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_to_fcp_error_has_retry_after() {
        let err = PandaDocError::RateLimited {
            retry_after_ms: 5000,
        };
        match err.to_fcp_error() {
            FcpError::External { retry_after, .. } => {
                assert_eq!(retry_after, Some(Duration::from_secs(5)));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn api_error_to_fcp_error_no_retry_after() {
        let err = PandaDocError::Api {
            status_code: 500,
            message: "err".into(),
        };
        match err.to_fcp_error() {
            FcpError::External { retry_after, .. } => {
                assert_eq!(retry_after, None);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn unauthorized_fcp_error_message() {
        match PandaDocError::Unauthorized.to_fcp_error() {
            FcpError::External { message, .. } => {
                assert_eq!(message, "Authentication failed");
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn forbidden_fcp_error_message() {
        match PandaDocError::Forbidden.to_fcp_error() {
            FcpError::External { message, .. } => {
                assert_eq!(message, "Insufficient permissions");
            }
            other => panic!("expected External, got {other:?}"),
        }
    }
}
