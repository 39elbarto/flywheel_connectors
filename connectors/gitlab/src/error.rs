//! `GitLab`-specific error types.

use std::time::Duration;

use fcp_core::FcpError;
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
            Self::Api { status_code, message } => FcpError::External {
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

#[cfg(test)]
mod tests {
    use super::*;

    // ── is_retryable ─────────────────────────────────────────────────

    #[test]
    fn rate_limited_is_retryable() {
        assert!(GitLabError::RateLimited { retry_after_ms: 5000 }.is_retryable());
    }

    #[test]
    fn api_500_is_retryable() {
        assert!(GitLabError::Api { status_code: 500, message: "err".into() }.is_retryable());
    }

    #[test]
    fn api_502_is_retryable() {
        assert!(GitLabError::Api { status_code: 502, message: "bad gateway".into() }.is_retryable());
    }

    #[test]
    fn api_429_is_retryable() {
        assert!(GitLabError::Api { status_code: 429, message: "too many".into() }.is_retryable());
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
        assert!(!GitLabError::NotFound { resource: "project".into() }.is_retryable());
    }

    #[test]
    fn api_400_not_retryable() {
        assert!(!GitLabError::Api { status_code: 400, message: "bad".into() }.is_retryable());
    }

    #[test]
    fn api_404_not_retryable() {
        assert!(!GitLabError::Api { status_code: 404, message: "not found".into() }.is_retryable());
    }

    // ── retry_after ──────────────────────────────────────────────────

    #[test]
    fn retry_after_for_rate_limited() {
        let err = GitLabError::RateLimited { retry_after_ms: 30_000 };
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
        assert_eq!(GitLabError::Api { status_code: 500, message: "err".into() }.retry_after(), None);
    }

    // ── to_fcp_error ─────────────────────────────────────────────────

    #[test]
    fn unauthorized_to_fcp_error() {
        match GitLabError::Unauthorized.to_fcp_error() {
            FcpError::External { service, status_code, retryable, .. } => {
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
            FcpError::External { service, status_code, retryable, .. } => {
                assert_eq!(service, "gitlab");
                assert_eq!(status_code, Some(403));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn not_found_to_fcp_error() {
        match (GitLabError::NotFound { resource: "issue".into() }).to_fcp_error() {
            FcpError::External { service, status_code, message, retryable, .. } => {
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
        match (GitLabError::RateLimited { retry_after_ms: 60_000 }).to_fcp_error() {
            FcpError::External { status_code, retryable, retry_after, .. } => {
                assert_eq!(status_code, Some(429));
                assert!(retryable);
                assert_eq!(retry_after, Some(Duration::from_secs(60)));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn api_error_to_fcp_error() {
        match (GitLabError::Api { status_code: 503, message: "unavailable".into() }).to_fcp_error() {
            FcpError::External { service, status_code, retryable, message, .. } => {
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

    // ── Display ──────────────────────────────────────────────────────

    #[test]
    fn error_display_unauthorized() {
        assert_eq!(GitLabError::Unauthorized.to_string(), "Authentication failed: invalid or expired token");
    }

    #[test]
    fn error_display_forbidden() {
        assert_eq!(GitLabError::Forbidden.to_string(), "Forbidden: insufficient permissions");
    }

    #[test]
    fn error_display_not_found() {
        assert_eq!(GitLabError::NotFound { resource: "project".into() }.to_string(), "Not found: project");
    }

    #[test]
    fn error_display_rate_limited() {
        assert_eq!(GitLabError::RateLimited { retry_after_ms: 1000 }.to_string(), "Rate limited, retry after 1000ms");
    }

    #[test]
    fn error_display_api() {
        assert_eq!(GitLabError::Api { status_code: 500, message: "Internal".into() }.to_string(), "GitLab API error (500): Internal");
    }
}
