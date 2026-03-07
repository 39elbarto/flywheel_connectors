//! `ClickUp`-specific error types.

use std::time::Duration;

use fcp_core::FcpError;
use thiserror::Error;

/// Result alias for `ClickUp` operations.
pub type ClickUpResult<T> = Result<T, ClickUpError>;

/// `ClickUp`-specific errors.
#[derive(Error, Debug)]
pub enum ClickUpError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// `ClickUp` API returned an error
    #[error("ClickUp API error ({status_code}): {message}")]
    Api { status_code: u16, message: String },

    /// Rate limited (429)
    #[error("Rate limited, retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },

    /// Authentication failed (401)
    #[error("Authentication failed: invalid or expired API token")]
    Unauthorized,

    /// Forbidden (403)
    #[error("Forbidden: insufficient permissions")]
    Forbidden,

    /// Resource not found (404)
    #[error("Not found: {resource}")]
    NotFound { resource: String },
}

impl ClickUpError {
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
                service: "clickup".into(),
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
                service: "clickup".into(),
                message: message.clone(),
                status_code: Some(*status_code),
                retryable: self.is_retryable(),
                retry_after: None,
            },
            Self::RateLimited { retry_after_ms } => FcpError::External {
                service: "clickup".into(),
                message: format!("Rate limited, retry after {retry_after_ms}ms"),
                status_code: Some(429),
                retryable: true,
                retry_after: self.retry_after(),
            },
            Self::Unauthorized => FcpError::External {
                service: "clickup".into(),
                message: "Authentication failed".into(),
                status_code: Some(401),
                retryable: false,
                retry_after: None,
            },
            Self::Forbidden => FcpError::External {
                service: "clickup".into(),
                message: "Insufficient permissions".into(),
                status_code: Some(403),
                retryable: false,
                retry_after: None,
            },
            Self::NotFound { resource } => FcpError::External {
                service: "clickup".into(),
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

    #[test]
    fn rate_limited_is_retryable() {
        assert!(
            ClickUpError::RateLimited {
                retry_after_ms: 5000
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_500_is_retryable() {
        assert!(
            ClickUpError::Api {
                status_code: 500,
                message: "err".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_503_is_retryable() {
        assert!(
            ClickUpError::Api {
                status_code: 503,
                message: "unavailable".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_429_is_retryable() {
        assert!(
            ClickUpError::Api {
                status_code: 429,
                message: "too many".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn unauthorized_not_retryable() {
        assert!(!ClickUpError::Unauthorized.is_retryable());
    }

    #[test]
    fn forbidden_not_retryable() {
        assert!(!ClickUpError::Forbidden.is_retryable());
    }

    #[test]
    fn not_found_not_retryable() {
        assert!(
            !ClickUpError::NotFound {
                resource: "task".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_400_not_retryable() {
        assert!(
            !ClickUpError::Api {
                status_code: 400,
                message: "bad request".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn retry_after_for_rate_limited() {
        let err = ClickUpError::RateLimited {
            retry_after_ms: 30_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn retry_after_none_for_unauthorized() {
        assert_eq!(ClickUpError::Unauthorized.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_forbidden() {
        assert_eq!(ClickUpError::Forbidden.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_api_error() {
        assert_eq!(
            ClickUpError::Api {
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
            ClickUpError::NotFound {
                resource: "x".into()
            }
            .retry_after(),
            None
        );
    }

    #[test]
    fn unauthorized_to_fcp_error() {
        match ClickUpError::Unauthorized.to_fcp_error() {
            FcpError::External {
                service,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "clickup");
                assert_eq!(status_code, Some(401));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn forbidden_to_fcp_error() {
        match ClickUpError::Forbidden.to_fcp_error() {
            FcpError::External {
                service,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "clickup");
                assert_eq!(status_code, Some(403));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn not_found_to_fcp_error() {
        match (ClickUpError::NotFound {
            resource: "task_abc".into(),
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
                assert!(message.contains("task_abc"));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_to_fcp_error() {
        match (ClickUpError::RateLimited {
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
        match (ClickUpError::Api {
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
                assert_eq!(service, "clickup");
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
        match ClickUpError::Json(bad.unwrap_err()).to_fcp_error() {
            FcpError::Internal { message } => assert!(message.starts_with("JSON error:")),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn api_error_non_retryable_to_fcp_error() {
        match (ClickUpError::Api {
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
            ClickUpError::Unauthorized.to_string(),
            "Authentication failed: invalid or expired API token"
        );
    }

    #[test]
    fn error_display_forbidden() {
        assert_eq!(
            ClickUpError::Forbidden.to_string(),
            "Forbidden: insufficient permissions"
        );
    }

    #[test]
    fn error_display_not_found() {
        assert_eq!(
            ClickUpError::NotFound {
                resource: "task".into()
            }
            .to_string(),
            "Not found: task"
        );
    }

    #[test]
    fn error_display_rate_limited() {
        assert_eq!(
            ClickUpError::RateLimited {
                retry_after_ms: 2000
            }
            .to_string(),
            "Rate limited, retry after 2000ms"
        );
    }

    #[test]
    fn error_display_api() {
        assert_eq!(
            ClickUpError::Api {
                status_code: 500,
                message: "Internal".into()
            }
            .to_string(),
            "ClickUp API error (500): Internal"
        );
    }

    // ── Additional retryable boundary cases ───────────────────────

    #[test]
    fn api_599_is_retryable() {
        assert!(
            ClickUpError::Api {
                status_code: 599,
                message: "edge".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_499_not_retryable() {
        assert!(
            !ClickUpError::Api {
                status_code: 499,
                message: "not server".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn json_not_retryable() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{bad");
        assert!(!ClickUpError::Json(bad.unwrap_err()).is_retryable());
    }

    #[test]
    fn retry_after_none_for_json() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{bad");
        assert_eq!(ClickUpError::Json(bad.unwrap_err()).retry_after(), None);
    }

    #[test]
    fn rate_limited_zero_ms() {
        let err = ClickUpError::RateLimited { retry_after_ms: 0 };
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(Duration::from_millis(0)));
    }

    #[test]
    fn rate_limited_large_ms() {
        let err = ClickUpError::RateLimited {
            retry_after_ms: 3_600_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(3600)));
    }

    // ── Display edge cases ────────────────────────────────────────

    #[test]
    fn error_display_not_found_empty_resource() {
        assert_eq!(
            ClickUpError::NotFound {
                resource: String::new()
            }
            .to_string(),
            "Not found: "
        );
    }

    #[test]
    fn error_display_api_empty_message() {
        assert_eq!(
            ClickUpError::Api {
                status_code: 502,
                message: String::new()
            }
            .to_string(),
            "ClickUp API error (502): "
        );
    }

    // ── to_fcp_error service field ────────────────────────────────

    #[test]
    fn all_fcp_errors_have_clickup_service() {
        let errors: Vec<ClickUpError> = vec![
            ClickUpError::Unauthorized,
            ClickUpError::Forbidden,
            ClickUpError::NotFound {
                resource: "x".into(),
            },
            ClickUpError::RateLimited {
                retry_after_ms: 1000,
            },
            ClickUpError::Api {
                status_code: 500,
                message: "err".into(),
            },
        ];
        for err in &errors {
            let fcp = err.to_fcp_error();
            if let FcpError::External { service, .. } = fcp {
                assert_eq!(service, "clickup");
            }
        }
    }

    #[test]
    fn rate_limited_fcp_error_retry_after_matches() {
        match (ClickUpError::RateLimited {
            retry_after_ms: 45_000,
        })
        .to_fcp_error()
        {
            FcpError::External { retry_after, .. } => {
                assert_eq!(retry_after, Some(Duration::from_secs(45)));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    // ── Debug format ──────────────────────────────────────────────

    #[test]
    fn error_debug_format() {
        let err = ClickUpError::Api {
            status_code: 503,
            message: "retry".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Api"));
        assert!(dbg.contains("503"));
    }

    #[test]
    fn error_debug_unauthorized() {
        let dbg = format!("{:?}", ClickUpError::Unauthorized);
        assert!(dbg.contains("Unauthorized"));
    }

    #[test]
    fn error_debug_rate_limited() {
        let dbg = format!(
            "{:?}",
            ClickUpError::RateLimited {
                retry_after_ms: 100
            }
        );
        assert!(dbg.contains("RateLimited"));
        assert!(dbg.contains("100"));
    }

    #[test]
    fn api_501_is_retryable() {
        assert!(
            ClickUpError::Api {
                status_code: 501,
                message: "not impl".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_600_not_retryable() {
        assert!(
            !ClickUpError::Api {
                status_code: 600,
                message: "over".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn error_debug_not_found() {
        let dbg = format!(
            "{:?}",
            ClickUpError::NotFound {
                resource: "task/123".into()
            }
        );
        assert!(dbg.contains("NotFound"));
        assert!(dbg.contains("task/123"));
    }

    #[test]
    fn error_debug_forbidden() {
        let dbg = format!("{:?}", ClickUpError::Forbidden);
        assert!(dbg.contains("Forbidden"));
    }

    #[test]
    fn error_debug_json() {
        let inner = serde_json::from_str::<serde_json::Value>("bad").unwrap_err();
        let dbg = format!("{:?}", ClickUpError::Json(inner));
        assert!(dbg.contains("Json"));
    }

    #[test]
    fn from_serde_json_error() {
        let inner = serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err();
        let err: ClickUpError = inner.into();
        assert!(matches!(err, ClickUpError::Json(_)));
    }

    #[test]
    fn unauthorized_fcp_no_retry_after() {
        match ClickUpError::Unauthorized.to_fcp_error() {
            FcpError::External { retry_after, .. } => assert!(retry_after.is_none()),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn forbidden_fcp_no_retry_after() {
        match ClickUpError::Forbidden.to_fcp_error() {
            FcpError::External { retry_after, .. } => assert!(retry_after.is_none()),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn not_found_fcp_no_retry_after() {
        match (ClickUpError::NotFound {
            resource: "x".into(),
        })
        .to_fcp_error()
        {
            FcpError::External { retry_after, .. } => assert!(retry_after.is_none()),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn not_found_unicode_resource() {
        let err = ClickUpError::NotFound {
            resource: "task/\u{1F680}".into(),
        };
        assert!(err.to_string().contains('\u{1F680}'));
        match err.to_fcp_error() {
            FcpError::External { message, .. } => assert!(message.contains('\u{1F680}')),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn api_error_long_message() {
        let long = "x".repeat(10_000);
        let err = ClickUpError::Api {
            status_code: 500,
            message: long.clone(),
        };
        assert!(err.to_string().contains(&long));
    }
}
