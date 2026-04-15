//! `PostHog`-specific error types.

#![allow(clippy::doc_markdown)]

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_core::FcpError;
use fcp_sdk::migration::ConnectorErrorMapping;
use thiserror::Error;

/// Result alias for `PostHog` operations.
pub type PostHogResult<T> = Result<T, PostHogError>;

/// `PostHog`-specific errors.
#[derive(Error, Debug)]
pub enum PostHogError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// `PostHog` API returned an error
    #[error("PostHog API error ({status_code}): {message}")]
    Api { status_code: u16, message: String },

    /// Server error with retry-after hint (5xx with Retry-After header)
    #[error("PostHog API error ({status_code}): {message}")]
    RetryableApi {
        status_code: u16,
        message: String,
        retry_after_ms: u64,
    },

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

    /// Invalid input (client-side validation)
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

impl PostHogError {
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::RateLimited { .. } | Self::RetryableApi { .. } => true,
            Self::Api { status_code, .. } => matches!(status_code, 500..=599 | 429),
            _ => false,
        }
    }

    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after_ms, .. }
            | Self::RetryableApi {
                retry_after_ms, ..
            } => Some(Duration::from_millis(*retry_after_ms)),
            _ => None,
        }
    }

    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Http(e) => FcpError::External {
                service: "posthog".into(),
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
                service: "posthog".into(),
                message: message.clone(),
                status_code: Some(*status_code),
                retryable: self.is_retryable(),
                retry_after: None,
            },
            Self::RetryableApi {
                status_code,
                message,
                retry_after_ms,
            } => FcpError::External {
                service: "posthog".into(),
                message: message.clone(),
                status_code: Some(*status_code),
                retryable: true,
                retry_after: Some(Duration::from_millis(*retry_after_ms)),
            },
            Self::RateLimited { retry_after_ms } => FcpError::External {
                service: "posthog".into(),
                message: format!("Rate limited, retry after {retry_after_ms}ms"),
                status_code: Some(429),
                retryable: true,
                retry_after: self.retry_after(),
            },
            Self::Unauthorized => FcpError::External {
                service: "posthog".into(),
                message: "Authentication failed".into(),
                status_code: Some(401),
                retryable: false,
                retry_after: None,
            },
            Self::Forbidden => FcpError::External {
                service: "posthog".into(),
                message: "Insufficient permissions".into(),
                status_code: Some(403),
                retryable: false,
                retry_after: None,
            },
            Self::NotFound { resource } => FcpError::External {
                service: "posthog".into(),
                message: format!("Not found: {resource}"),
                status_code: Some(404),
                retryable: false,
                retry_after: None,
            },
            Self::InvalidInput(msg) => FcpError::Internal {
                message: format!("Invalid input: {msg}"),
            },
        }
    }
}

impl ConnectorErrorMapping for PostHogError {
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
            PostHogError::RateLimited {
                retry_after_ms: 5000
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_500_is_retryable() {
        assert!(
            PostHogError::Api {
                status_code: 500,
                message: "err".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_503_is_retryable() {
        assert!(
            PostHogError::Api {
                status_code: 503,
                message: "unavailable".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_429_is_retryable() {
        assert!(
            PostHogError::Api {
                status_code: 429,
                message: "too many".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn unauthorized_not_retryable() {
        assert!(!PostHogError::Unauthorized.is_retryable());
    }

    #[test]
    fn forbidden_not_retryable() {
        assert!(!PostHogError::Forbidden.is_retryable());
    }

    #[test]
    fn not_found_not_retryable() {
        assert!(
            !PostHogError::NotFound {
                resource: "insight".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_400_not_retryable() {
        assert!(
            !PostHogError::Api {
                status_code: 400,
                message: "bad request".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn retry_after_for_rate_limited() {
        let err = PostHogError::RateLimited {
            retry_after_ms: 30_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn retry_after_none_for_unauthorized() {
        assert_eq!(PostHogError::Unauthorized.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_forbidden() {
        assert_eq!(PostHogError::Forbidden.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_api_error() {
        assert_eq!(
            PostHogError::Api {
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
            PostHogError::NotFound {
                resource: "x".into()
            }
            .retry_after(),
            None
        );
    }

    #[test]
    fn unauthorized_to_fcp_error() {
        match PostHogError::Unauthorized.to_fcp_error() {
            FcpError::External {
                service,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "posthog");
                assert_eq!(status_code, Some(401));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn forbidden_to_fcp_error() {
        match PostHogError::Forbidden.to_fcp_error() {
            FcpError::External {
                service,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "posthog");
                assert_eq!(status_code, Some(403));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn not_found_to_fcp_error() {
        match (PostHogError::NotFound {
            resource: "insight_abc".into(),
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
                assert!(message.contains("insight_abc"));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_to_fcp_error() {
        match (PostHogError::RateLimited {
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
        match (PostHogError::Api {
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
                assert_eq!(service, "posthog");
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
        match PostHogError::Json(bad.unwrap_err()).to_fcp_error() {
            FcpError::Internal { message } => assert!(message.starts_with("JSON error:")),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn api_error_non_retryable_to_fcp_error() {
        match (PostHogError::Api {
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
            PostHogError::Unauthorized.to_string(),
            "Authentication failed: invalid or expired API key"
        );
    }

    #[test]
    fn error_display_forbidden() {
        assert_eq!(
            PostHogError::Forbidden.to_string(),
            "Forbidden: insufficient permissions"
        );
    }

    #[test]
    fn error_display_not_found() {
        assert_eq!(
            PostHogError::NotFound {
                resource: "insight".into()
            }
            .to_string(),
            "Not found: insight"
        );
    }

    #[test]
    fn error_display_rate_limited() {
        assert_eq!(
            PostHogError::RateLimited {
                retry_after_ms: 2000
            }
            .to_string(),
            "Rate limited, retry after 2000ms"
        );
    }

    #[test]
    fn error_display_api() {
        assert_eq!(
            PostHogError::Api {
                status_code: 500,
                message: "Internal".into()
            }
            .to_string(),
            "PostHog API error (500): Internal"
        );
    }

    // -- Additional error tests --

    #[test]
    fn api_599_is_retryable() {
        assert!(
            PostHogError::Api {
                status_code: 599,
                message: "err".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_501_is_retryable() {
        assert!(
            PostHogError::Api {
                status_code: 501,
                message: "not impl".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_499_not_retryable() {
        assert!(
            !PostHogError::Api {
                status_code: 499,
                message: "err".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_600_not_retryable() {
        assert!(
            !PostHogError::Api {
                status_code: 600,
                message: "err".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_422_not_retryable() {
        assert!(
            !PostHogError::Api {
                status_code: 422,
                message: "unprocessable".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn rate_limited_zero_ms() {
        let err = PostHogError::RateLimited { retry_after_ms: 0 };
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(Duration::from_millis(0)));
    }

    #[test]
    fn rate_limited_large_value() {
        let err = PostHogError::RateLimited {
            retry_after_ms: 3_600_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(3600)));
    }

    #[test]
    fn not_found_empty_resource() {
        let err = PostHogError::NotFound {
            resource: String::new(),
        };
        assert_eq!(err.to_string(), "Not found: ");
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_error_empty_message() {
        let err = PostHogError::Api {
            status_code: 400,
            message: String::new(),
        };
        assert_eq!(err.to_string(), "PostHog API error (400): ");
    }

    #[test]
    fn error_debug_unauthorized() {
        let err = PostHogError::Unauthorized;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Unauthorized"));
    }

    #[test]
    fn error_debug_not_found() {
        let err = PostHogError::NotFound {
            resource: "flag".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("NotFound"));
        assert!(dbg.contains("flag"));
    }

    #[test]
    fn error_debug_rate_limited() {
        let err = PostHogError::RateLimited {
            retry_after_ms: 2000,
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("RateLimited"));
        assert!(dbg.contains("2000"));
    }

    #[test]
    fn to_fcp_error_rate_limited_message_contains_ms() {
        match (PostHogError::RateLimited {
            retry_after_ms: 5000,
        })
        .to_fcp_error()
        {
            FcpError::External { message, .. } => assert!(message.contains("5000")),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_not_found_retry_after_is_none() {
        match (PostHogError::NotFound {
            resource: "x".into(),
        })
        .to_fcp_error()
        {
            FcpError::External { retry_after, .. } => assert!(retry_after.is_none()),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_retryable_has_no_retry_after() {
        match (PostHogError::Api {
            status_code: 502,
            message: "bad gw".into(),
        })
        .to_fcp_error()
        {
            FcpError::External {
                retryable,
                retry_after,
                ..
            } => {
                assert!(retryable);
                assert!(retry_after.is_none());
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_unauthorized_message() {
        match PostHogError::Unauthorized.to_fcp_error() {
            FcpError::External { message, .. } => assert_eq!(message, "Authentication failed"),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_forbidden_message() {
        match PostHogError::Forbidden.to_fcp_error() {
            FcpError::External { message, .. } => assert_eq!(message, "Insufficient permissions"),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn api_502_is_retryable() {
        assert!(
            PostHogError::Api {
                status_code: 502,
                message: "bad gateway".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_404_not_retryable() {
        assert!(
            !PostHogError::Api {
                status_code: 404,
                message: "not found".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_504_is_retryable() {
        assert!(
            PostHogError::Api {
                status_code: 504,
                message: "gateway timeout".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn error_debug_api() {
        let err = PostHogError::Api {
            status_code: 418,
            message: "teapot".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Api"));
        assert!(dbg.contains("418"));
        assert!(dbg.contains("teapot"));
    }

    #[test]
    fn error_debug_forbidden() {
        let err = PostHogError::Forbidden;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Forbidden"));
    }

    #[test]
    fn not_found_to_fcp_error_service_is_posthog() {
        match (PostHogError::NotFound {
            resource: "dashboard_42".into(),
        })
        .to_fcp_error()
        {
            FcpError::External { service, .. } => assert_eq!(service, "posthog"),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_display_large_ms() {
        let err = PostHogError::RateLimited {
            retry_after_ms: 120_000,
        };
        let display = err.to_string();
        assert!(display.contains("120000"));
        assert!(display.contains("retry after"));
    }

    #[test]
    fn invalid_input_display() {
        let err = PostHogError::InvalidInput("project_id must not be empty".into());
        assert_eq!(
            err.to_string(),
            "Invalid input: project_id must not be empty"
        );
    }

    #[test]
    fn invalid_input_not_retryable() {
        assert!(!PostHogError::InvalidInput("bad".into()).is_retryable());
    }

    #[test]
    fn invalid_input_retry_after_none() {
        assert_eq!(PostHogError::InvalidInput("bad".into()).retry_after(), None);
    }

    #[test]
    fn invalid_input_to_fcp_internal() {
        match PostHogError::InvalidInput("bad field".into()).to_fcp_error() {
            FcpError::Internal { message } => {
                assert!(message.contains("bad field"));
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }
}
