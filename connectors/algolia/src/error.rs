//! `Algolia`-specific error types.

use std::time::Duration;

use fcp_core::FcpError;
use thiserror::Error;
use fcp_async_core::AsyncError;
use fcp_sdk::migration::ConnectorErrorMapping;

/// Result alias for `Algolia` operations.
pub type AlgoliaResult<T> = Result<T, AlgoliaError>;

/// `Algolia`-specific errors.
#[derive(Error, Debug)]
pub enum AlgoliaError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// `Algolia` API returned an error
    #[error("Algolia API error ({status_code}): {message}")]
    Api { status_code: u16, message: String },

    /// Rate limited (429)
    #[error("Rate limited, retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },

    /// Authentication failed (401)
    #[error("Authentication failed: invalid application ID or API key")]
    Unauthorized,

    /// Forbidden (403)
    #[error("Forbidden: insufficient permissions")]
    Forbidden,

    /// Resource not found (404)
    #[error("Not found: {resource}")]
    NotFound { resource: String },
}

impl AlgoliaError {
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
                service: "algolia".into(),
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
                service: "algolia".into(),
                message: message.clone(),
                status_code: Some(*status_code),
                retryable: self.is_retryable(),
                retry_after: None,
            },
            Self::RateLimited { retry_after_ms } => FcpError::External {
                service: "algolia".into(),
                message: format!("Rate limited, retry after {retry_after_ms}ms"),
                status_code: Some(429),
                retryable: true,
                retry_after: self.retry_after(),
            },
            Self::Unauthorized => FcpError::External {
                service: "algolia".into(),
                message: "Authentication failed".into(),
                status_code: Some(401),
                retryable: false,
                retry_after: None,
            },
            Self::Forbidden => FcpError::External {
                service: "algolia".into(),
                message: "Insufficient permissions".into(),
                status_code: Some(403),
                retryable: false,
                retry_after: None,
            },
            Self::NotFound { resource } => FcpError::External {
                service: "algolia".into(),
                message: format!("Not found: {resource}"),
                status_code: Some(404),
                retryable: false,
                retry_after: None,
            },
        }
    }
}

impl ConnectorErrorMapping for AlgoliaError {
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
            AlgoliaError::RateLimited {
                retry_after_ms: 5000
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_500_is_retryable() {
        assert!(
            AlgoliaError::Api {
                status_code: 500,
                message: "err".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_503_is_retryable() {
        assert!(
            AlgoliaError::Api {
                status_code: 503,
                message: "unavailable".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_429_is_retryable() {
        assert!(
            AlgoliaError::Api {
                status_code: 429,
                message: "too many".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn unauthorized_not_retryable() {
        assert!(!AlgoliaError::Unauthorized.is_retryable());
    }

    #[test]
    fn forbidden_not_retryable() {
        assert!(!AlgoliaError::Forbidden.is_retryable());
    }

    #[test]
    fn not_found_not_retryable() {
        assert!(
            !AlgoliaError::NotFound {
                resource: "index".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_400_not_retryable() {
        assert!(
            !AlgoliaError::Api {
                status_code: 400,
                message: "bad request".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_422_not_retryable() {
        assert!(
            !AlgoliaError::Api {
                status_code: 422,
                message: "unprocessable".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn retry_after_for_rate_limited() {
        let err = AlgoliaError::RateLimited {
            retry_after_ms: 30_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn retry_after_none_for_unauthorized() {
        assert_eq!(AlgoliaError::Unauthorized.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_forbidden() {
        assert_eq!(AlgoliaError::Forbidden.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_api_error() {
        assert_eq!(
            AlgoliaError::Api {
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
            AlgoliaError::NotFound {
                resource: "x".into()
            }
            .retry_after(),
            None
        );
    }

    #[test]
    fn unauthorized_to_fcp_error() {
        match AlgoliaError::Unauthorized.to_fcp_error() {
            FcpError::External {
                service,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "algolia");
                assert_eq!(status_code, Some(401));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn forbidden_to_fcp_error() {
        match AlgoliaError::Forbidden.to_fcp_error() {
            FcpError::External {
                service,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "algolia");
                assert_eq!(status_code, Some(403));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn not_found_to_fcp_error() {
        match (AlgoliaError::NotFound {
            resource: "products/abc123".into(),
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
                assert!(message.contains("products/abc123"));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_to_fcp_error() {
        match (AlgoliaError::RateLimited {
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
        match (AlgoliaError::Api {
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
                assert_eq!(service, "algolia");
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
        match AlgoliaError::Json(bad.unwrap_err()).to_fcp_error() {
            FcpError::Internal { message } => assert!(message.starts_with("JSON error:")),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn api_error_non_retryable_to_fcp_error() {
        match (AlgoliaError::Api {
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
            AlgoliaError::Unauthorized.to_string(),
            "Authentication failed: invalid application ID or API key"
        );
    }

    #[test]
    fn error_display_forbidden() {
        assert_eq!(
            AlgoliaError::Forbidden.to_string(),
            "Forbidden: insufficient permissions"
        );
    }

    #[test]
    fn error_display_not_found() {
        assert_eq!(
            AlgoliaError::NotFound {
                resource: "index".into()
            }
            .to_string(),
            "Not found: index"
        );
    }

    #[test]
    fn error_display_rate_limited() {
        assert_eq!(
            AlgoliaError::RateLimited {
                retry_after_ms: 2000
            }
            .to_string(),
            "Rate limited, retry after 2000ms"
        );
    }

    #[test]
    fn error_display_api() {
        assert_eq!(
            AlgoliaError::Api {
                status_code: 500,
                message: "Internal".into()
            }
            .to_string(),
            "Algolia API error (500): Internal"
        );
    }

    #[test]
    fn api_502_is_retryable() {
        assert!(
            AlgoliaError::Api {
                status_code: 502,
                message: "bad gateway".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_504_is_retryable() {
        assert!(
            AlgoliaError::Api {
                status_code: 504,
                message: "timeout".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn rate_limited_retry_after_zero() {
        let err = AlgoliaError::RateLimited { retry_after_ms: 0 };
        assert_eq!(err.retry_after(), Some(Duration::from_millis(0)));
    }

    #[test]
    fn not_found_to_fcp_error_service() {
        match (AlgoliaError::NotFound {
            resource: "rec".into(),
        })
        .to_fcp_error()
        {
            FcpError::External { service, .. } => assert_eq!(service, "algolia"),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_to_fcp_error_service() {
        match (AlgoliaError::RateLimited {
            retry_after_ms: 1000,
        })
        .to_fcp_error()
        {
            FcpError::External { service, .. } => assert_eq!(service, "algolia"),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn error_display_json() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("not json");
        let e = AlgoliaError::Json(bad.unwrap_err());
        let display = e.to_string();
        assert!(display.starts_with("JSON error:"));
    }

    #[test]
    fn json_error_is_not_retryable() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{bad");
        let e = AlgoliaError::Json(bad.unwrap_err());
        assert!(!e.is_retryable());
    }

    #[test]
    fn json_error_retry_after_is_none() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{bad");
        let e = AlgoliaError::Json(bad.unwrap_err());
        assert_eq!(e.retry_after(), None);
    }

    #[test]
    fn rate_limited_retry_after_large_value() {
        let err = AlgoliaError::RateLimited {
            retry_after_ms: 300_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(300)));
    }

    #[test]
    fn error_debug_unauthorized() {
        let err = AlgoliaError::Unauthorized;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Unauthorized"));
    }

    #[test]
    fn error_debug_api() {
        let err = AlgoliaError::Api {
            status_code: 418,
            message: "teapot".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("418"));
        assert!(dbg.contains("teapot"));
    }

    #[test]
    fn error_debug_not_found() {
        let err = AlgoliaError::NotFound {
            resource: "my-index".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("my-index"));
    }

    #[test]
    fn error_debug_rate_limited() {
        let err = AlgoliaError::RateLimited {
            retry_after_ms: 5000,
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("5000"));
    }

    #[test]
    fn api_error_retryable_boundary_499() {
        assert!(
            !AlgoliaError::Api {
                status_code: 499,
                message: "client error".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_error_retryable_boundary_599() {
        assert!(
            AlgoliaError::Api {
                status_code: 599,
                message: "server error".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_error_to_fcp_error_retry_after_is_none() {
        match (AlgoliaError::Api {
            status_code: 500,
            message: "err".into(),
        })
        .to_fcp_error()
        {
            FcpError::External { retry_after, .. } => assert!(retry_after.is_none()),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn unauthorized_to_fcp_error_retry_after_none() {
        match AlgoliaError::Unauthorized.to_fcp_error() {
            FcpError::External { retry_after, .. } => assert!(retry_after.is_none()),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn forbidden_to_fcp_error_retry_after_none() {
        match AlgoliaError::Forbidden.to_fcp_error() {
            FcpError::External { retry_after, .. } => assert!(retry_after.is_none()),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn not_found_to_fcp_error_retry_after_none() {
        match (AlgoliaError::NotFound {
            resource: "x".into(),
        })
        .to_fcp_error()
        {
            FcpError::External { retry_after, .. } => assert!(retry_after.is_none()),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn api_error_display_with_special_chars() {
        let err = AlgoliaError::Api {
            status_code: 400,
            message: "field \"name\" is required".into(),
        };
        let display = err.to_string();
        assert!(display.contains("field \"name\" is required"));
    }

    #[test]
    fn not_found_display_with_path() {
        let err = AlgoliaError::NotFound {
            resource: "/indexes/products/abc123".into(),
        };
        let display = err.to_string();
        assert!(display.contains("/indexes/products/abc123"));
    }
}
