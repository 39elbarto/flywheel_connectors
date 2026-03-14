//! `GitLab`-specific error types.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_core::FcpError;
use fcp_sdk::migration::ConnectorErrorMapping;
use thiserror::Error;

/// Result alias for `GitLab` operations.
pub type GitLabResult<T> = Result<T, GitLabError>;

/// `GitLab`-specific errors.
#[derive(Error, Debug)]
pub enum GitLabError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// `GitLab` API returned an error
    #[error("GitLab API error ({status_code}): {message}")]
    Api { status_code: u16, message: String },

    /// Rate limited (429)
    #[error("Rate limited, retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },

    /// Authentication failed (401)
    #[error("Authentication failed: invalid or expired token")]
    Unauthorized,

    /// Forbidden (403)
    #[error("Forbidden: insufficient permissions")]
    Forbidden,

    /// Resource not found (404)
    #[error("Not found: {resource}")]
    NotFound { resource: String },
}

impl GitLabError {
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
                service: "gitlab".into(),
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
                service: "gitlab".into(),
                message: message.clone(),
                status_code: Some(*status_code),
                retryable: self.is_retryable(),
                retry_after: None,
            },
            Self::RateLimited { retry_after_ms } => FcpError::External {
                service: "gitlab".into(),
                message: format!("Rate limited, retry after {retry_after_ms}ms"),
                status_code: Some(429),
                retryable: true,
                retry_after: self.retry_after(),
            },
            Self::Unauthorized => FcpError::External {
                service: "gitlab".into(),
                message: "Authentication failed".into(),
                status_code: Some(401),
                retryable: false,
                retry_after: None,
            },
            Self::Forbidden => FcpError::External {
                service: "gitlab".into(),
                message: "Insufficient permissions".into(),
                status_code: Some(403),
                retryable: false,
                retry_after: None,
            },
            Self::NotFound { resource } => FcpError::External {
                service: "gitlab".into(),
                message: format!("Not found: {resource}"),
                status_code: Some(404),
                retryable: false,
                retry_after: None,
            },
        }
    }
}

impl ConnectorErrorMapping for GitLabError {
    fn from_async_error(error: AsyncError) -> Self {
        match error {
            AsyncError::Timeout { timeout_ms } => Self::Api {
                status_code: 408,
                message: format!("deadline exceeded after {timeout_ms}ms"),
            },
            AsyncError::Cancelled => Self::Api {
                status_code: 499,
                message: "request cancelled".into(),
            },
            other => Self::Api {
                status_code: 500,
                message: other.to_string(),
            },
        }
    }

    fn to_fcp_error(&self) -> FcpError {
        GitLabError::to_fcp_error(self)
    }

    fn is_retryable(&self) -> bool {
        GitLabError::is_retryable(self)
    }

    fn retry_after(&self) -> Option<Duration> {
        GitLabError::retry_after(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── is_retryable ─────────────────────────────────────────────────

    #[test]
    fn rate_limited_is_retryable() {
        assert!(
            GitLabError::RateLimited {
                retry_after_ms: 5000
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_500_is_retryable() {
        assert!(
            GitLabError::Api {
                status_code: 500,
                message: "err".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_502_is_retryable() {
        assert!(
            GitLabError::Api {
                status_code: 502,
                message: "bad gateway".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_429_is_retryable() {
        assert!(
            GitLabError::Api {
                status_code: 429,
                message: "too many".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn unauthorized_not_retryable() {
        assert!(!GitLabError::Unauthorized.is_retryable());
    }

    #[test]
    fn forbidden_not_retryable() {
        assert!(!GitLabError::Forbidden.is_retryable());
    }

    #[test]
    fn not_found_not_retryable() {
        assert!(
            !GitLabError::NotFound {
                resource: "project".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_400_not_retryable() {
        assert!(
            !GitLabError::Api {
                status_code: 400,
                message: "bad".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_404_not_retryable() {
        assert!(
            !GitLabError::Api {
                status_code: 404,
                message: "not found".into()
            }
            .is_retryable()
        );
    }

    // ── retry_after ──────────────────────────────────────────────────

    #[test]
    fn retry_after_for_rate_limited() {
        let err = GitLabError::RateLimited {
            retry_after_ms: 30_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn retry_after_none_for_unauthorized() {
        assert_eq!(GitLabError::Unauthorized.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_forbidden() {
        assert_eq!(GitLabError::Forbidden.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_api_error() {
        assert_eq!(
            GitLabError::Api {
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
            GitLabError::NotFound {
                resource: "x".into()
            }
            .retry_after(),
            None
        );
    }

    // ── to_fcp_error ─────────────────────────────────────────────────

    #[test]
    fn unauthorized_to_fcp_error() {
        match GitLabError::Unauthorized.to_fcp_error() {
            FcpError::External {
                service,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "gitlab");
                assert_eq!(status_code, Some(401));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn forbidden_to_fcp_error() {
        match GitLabError::Forbidden.to_fcp_error() {
            FcpError::External {
                service,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "gitlab");
                assert_eq!(status_code, Some(403));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn not_found_to_fcp_error() {
        match (GitLabError::NotFound {
            resource: "issue".into(),
        })
        .to_fcp_error()
        {
            FcpError::External {
                service,
                status_code,
                message,
                retryable,
                ..
            } => {
                assert_eq!(service, "gitlab");
                assert_eq!(status_code, Some(404));
                assert!(message.contains("issue"));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_to_fcp_error() {
        match (GitLabError::RateLimited {
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
        match (GitLabError::Api {
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
                assert_eq!(service, "gitlab");
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
        match GitLabError::Json(bad.unwrap_err()).to_fcp_error() {
            FcpError::Internal { message } => assert!(message.starts_with("JSON error:")),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn api_error_non_retryable_to_fcp_error() {
        match (GitLabError::Api {
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

    // ── Display ──────────────────────────────────────────────────────

    #[test]
    fn error_display_unauthorized() {
        assert_eq!(
            GitLabError::Unauthorized.to_string(),
            "Authentication failed: invalid or expired token"
        );
    }

    #[test]
    fn error_display_forbidden() {
        assert_eq!(
            GitLabError::Forbidden.to_string(),
            "Forbidden: insufficient permissions"
        );
    }

    #[test]
    fn error_display_not_found() {
        assert_eq!(
            GitLabError::NotFound {
                resource: "project".into()
            }
            .to_string(),
            "Not found: project"
        );
    }

    #[test]
    fn error_display_rate_limited() {
        assert_eq!(
            GitLabError::RateLimited {
                retry_after_ms: 1000
            }
            .to_string(),
            "Rate limited, retry after 1000ms"
        );
    }

    #[test]
    fn error_display_api() {
        assert_eq!(
            GitLabError::Api {
                status_code: 500,
                message: "Internal".into()
            }
            .to_string(),
            "GitLab API error (500): Internal"
        );
    }

    // ── Display additional ──────────────────────────────────────────

    #[test]
    fn error_display_json() {
        let inner = serde_json::from_str::<serde_json::Value>("{bad").unwrap_err();
        let err = GitLabError::Json(inner);
        let s = err.to_string();
        assert!(s.starts_with("JSON error:"), "got: {s}");
    }

    #[test]
    fn error_display_api_empty_message() {
        let err = GitLabError::Api {
            status_code: 400,
            message: String::new(),
        };
        let s = err.to_string();
        assert!(s.contains("400"));
    }

    #[test]
    fn error_display_not_found_empty_resource() {
        let err = GitLabError::NotFound {
            resource: String::new(),
        };
        assert_eq!(err.to_string(), "Not found: ");
    }

    #[test]
    fn error_display_rate_limited_zero() {
        let err = GitLabError::RateLimited { retry_after_ms: 0 };
        assert_eq!(err.to_string(), "Rate limited, retry after 0ms");
    }

    // ── is_retryable extended ───────────────────────────────────────

    #[test]
    fn api_503_is_retryable() {
        assert!(
            GitLabError::Api {
                status_code: 503,
                message: "unavailable".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_504_is_retryable() {
        assert!(
            GitLabError::Api {
                status_code: 504,
                message: "timeout".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_599_is_retryable() {
        assert!(
            GitLabError::Api {
                status_code: 599,
                message: "unknown".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_422_not_retryable() {
        assert!(
            !GitLabError::Api {
                status_code: 422,
                message: "unprocessable".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_401_not_retryable() {
        assert!(
            !GitLabError::Api {
                status_code: 401,
                message: "unauth".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_403_not_retryable() {
        assert!(
            !GitLabError::Api {
                status_code: 403,
                message: "forbidden".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn json_error_not_retryable() {
        let inner = serde_json::from_str::<serde_json::Value>("nope").unwrap_err();
        assert!(!GitLabError::Json(inner).is_retryable());
    }

    // ── retry_after extended ────────────────────────────────────────

    #[test]
    fn retry_after_rate_limited_zero() {
        let err = GitLabError::RateLimited { retry_after_ms: 0 };
        assert_eq!(err.retry_after(), Some(Duration::from_millis(0)));
    }

    #[test]
    fn retry_after_rate_limited_large() {
        let err = GitLabError::RateLimited {
            retry_after_ms: 3_600_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(3600)));
    }

    #[test]
    fn retry_after_none_for_json() {
        let inner = serde_json::from_str::<serde_json::Value>("bad").unwrap_err();
        assert_eq!(GitLabError::Json(inner).retry_after(), None);
    }

    // ── to_fcp_error extended ───────────────────────────────────────

    #[test]
    fn fcp_error_rate_limited_retry_after_ms_in_message() {
        match (GitLabError::RateLimited {
            retry_after_ms: 5000,
        })
        .to_fcp_error()
        {
            FcpError::External {
                message,
                status_code,
                retryable,
                retry_after,
                ..
            } => {
                assert!(message.contains("5000"));
                assert_eq!(status_code, Some(429));
                assert!(retryable);
                assert_eq!(retry_after, Some(Duration::from_secs(5)));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn fcp_error_unauthorized_message() {
        match GitLabError::Unauthorized.to_fcp_error() {
            FcpError::External { message, .. } => assert_eq!(message, "Authentication failed"),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn fcp_error_forbidden_message() {
        match GitLabError::Forbidden.to_fcp_error() {
            FcpError::External { message, .. } => assert_eq!(message, "Insufficient permissions"),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn fcp_error_not_found_message_contains_resource() {
        match (GitLabError::NotFound {
            resource: "merge_request/42".into(),
        })
        .to_fcp_error()
        {
            FcpError::External { message, .. } => assert!(message.contains("merge_request/42")),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn fcp_error_api_retryable_500_range() {
        match (GitLabError::Api {
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
    fn fcp_error_api_non_retryable_400_range() {
        match (GitLabError::Api {
            status_code: 422,
            message: "unprocessable".into(),
        })
        .to_fcp_error()
        {
            FcpError::External { retryable, .. } => assert!(!retryable),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn fcp_error_all_variants_have_gitlab_service() {
        let variants: Vec<GitLabError> = vec![
            GitLabError::Api {
                status_code: 400,
                message: "bad".into(),
            },
            GitLabError::RateLimited {
                retry_after_ms: 1000,
            },
            GitLabError::Unauthorized,
            GitLabError::Forbidden,
            GitLabError::NotFound {
                resource: "x".into(),
            },
        ];
        for err in variants {
            match err.to_fcp_error() {
                FcpError::External { service, .. } => assert_eq!(service, "gitlab"),
                FcpError::Internal { .. } => {} // Json variant maps to Internal
                other => panic!("unexpected variant: {other:?}"),
            }
        }
    }

    // ── Debug trait ─────────────────────────────────────────────────

    #[test]
    fn error_debug_unauthorized() {
        let dbg = format!("{:?}", GitLabError::Unauthorized);
        assert!(dbg.contains("Unauthorized"));
    }

    #[test]
    fn error_debug_forbidden() {
        let dbg = format!("{:?}", GitLabError::Forbidden);
        assert!(dbg.contains("Forbidden"));
    }

    #[test]
    fn error_debug_api() {
        let dbg = format!(
            "{:?}",
            GitLabError::Api {
                status_code: 500,
                message: "err".into()
            }
        );
        assert!(dbg.contains("Api"));
        assert!(dbg.contains("500"));
    }

    #[test]
    fn error_debug_rate_limited() {
        let dbg = format!(
            "{:?}",
            GitLabError::RateLimited {
                retry_after_ms: 10_000
            }
        );
        assert!(dbg.contains("RateLimited"));
        assert!(dbg.contains("10000"));
    }

    #[test]
    fn error_debug_not_found() {
        let dbg = format!(
            "{:?}",
            GitLabError::NotFound {
                resource: "proj/1".into()
            }
        );
        assert!(dbg.contains("NotFound"));
        assert!(dbg.contains("proj/1"));
    }

    #[test]
    fn error_debug_json() {
        let inner = serde_json::from_str::<serde_json::Value>("!!!").unwrap_err();
        let dbg = format!("{:?}", GitLabError::Json(inner));
        assert!(dbg.contains("Json"));
    }

    // ── From impls ──────────────────────────────────────────────────

    #[test]
    fn from_serde_json_error() {
        let inner = serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err();
        let err: GitLabError = inner.into();
        assert!(matches!(err, GitLabError::Json(_)));
    }

    // ── Boundary values ─────────────────────────────────────────────

    #[test]
    fn rate_limited_max_u64() {
        let err = GitLabError::RateLimited {
            retry_after_ms: u64::MAX,
        };
        assert!(err.is_retryable());
        assert!(err.retry_after().is_some());
    }

    #[test]
    fn api_error_status_code_zero() {
        let err = GitLabError::Api {
            status_code: 0,
            message: "weird".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_error_status_code_max() {
        let err = GitLabError::Api {
            status_code: u16::MAX,
            message: "overflow".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn not_found_unicode_resource() {
        let err = GitLabError::NotFound {
            resource: "project/\u{1F680}".into(),
        };
        let s = err.to_string();
        assert!(s.contains('\u{1F680}'));
        match err.to_fcp_error() {
            FcpError::External { message, .. } => assert!(message.contains('\u{1F680}')),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn api_error_long_message() {
        let long = "x".repeat(10_000);
        let err = GitLabError::Api {
            status_code: 500,
            message: long.clone(),
        };
        assert!(err.to_string().contains(&long));
    }
}
