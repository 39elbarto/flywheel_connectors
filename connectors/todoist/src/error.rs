//! `Todoist`-specific error types.

use std::time::Duration;

use fcp_core::FcpError;
use thiserror::Error;

/// Result alias for `Todoist` operations.
pub type TodoistResult<T> = Result<T, TodoistError>;

/// `Todoist`-specific errors.
#[derive(Error, Debug)]
pub enum TodoistError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// `Todoist` API returned an error
    #[error("Todoist API error ({status_code}): {message}")]
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

impl TodoistError {
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
                service: "todoist".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
            Self::Api { status_code, message } => FcpError::External {
                service: "todoist".into(),
                message: message.clone(),
                status_code: Some(*status_code),
                retryable: self.is_retryable(),
                retry_after: None,
            },
            Self::RateLimited { retry_after_ms } => FcpError::External {
                service: "todoist".into(),
                message: format!("Rate limited, retry after {retry_after_ms}ms"),
                status_code: Some(429),
                retryable: true,
                retry_after: self.retry_after(),
            },
            Self::Unauthorized => FcpError::External {
                service: "todoist".into(),
                message: "Authentication failed".into(),
                status_code: Some(401),
                retryable: false,
                retry_after: None,
            },
            Self::Forbidden => FcpError::External {
                service: "todoist".into(),
                message: "Insufficient permissions".into(),
                status_code: Some(403),
                retryable: false,
                retry_after: None,
            },
            Self::NotFound { resource } => FcpError::External {
                service: "todoist".into(),
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
        assert!(TodoistError::RateLimited { retry_after_ms: 5000 }.is_retryable());
    }

    #[test]
    fn api_500_is_retryable() {
        assert!(TodoistError::Api { status_code: 500, message: "err".into() }.is_retryable());
    }

    #[test]
    fn api_503_is_retryable() {
        assert!(TodoistError::Api { status_code: 503, message: "unavailable".into() }.is_retryable());
    }

    #[test]
    fn api_429_is_retryable() {
        assert!(TodoistError::Api { status_code: 429, message: "too many".into() }.is_retryable());
    }

    #[test]
    fn unauthorized_not_retryable() {
        assert!(!TodoistError::Unauthorized.is_retryable());
    }

    #[test]
    fn forbidden_not_retryable() {
        assert!(!TodoistError::Forbidden.is_retryable());
    }

    #[test]
    fn not_found_not_retryable() {
        assert!(!TodoistError::NotFound { resource: "task".into() }.is_retryable());
    }

    #[test]
    fn api_400_not_retryable() {
        assert!(!TodoistError::Api { status_code: 400, message: "bad request".into() }.is_retryable());
    }

    #[test]
    fn retry_after_for_rate_limited() {
        let err = TodoistError::RateLimited { retry_after_ms: 30_000 };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn retry_after_none_for_unauthorized() {
        assert_eq!(TodoistError::Unauthorized.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_forbidden() {
        assert_eq!(TodoistError::Forbidden.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_api_error() {
        assert_eq!(
            TodoistError::Api { status_code: 500, message: "err".into() }.retry_after(),
            None
        );
    }

    #[test]
    fn retry_after_none_for_not_found() {
        assert_eq!(TodoistError::NotFound { resource: "x".into() }.retry_after(), None);
    }

    #[test]
    fn unauthorized_to_fcp_error() {
        match TodoistError::Unauthorized.to_fcp_error() {
            FcpError::External { service, status_code, retryable, .. } => {
                assert_eq!(service, "todoist");
                assert_eq!(status_code, Some(401));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn forbidden_to_fcp_error() {
        match TodoistError::Forbidden.to_fcp_error() {
            FcpError::External { service, status_code, retryable, .. } => {
                assert_eq!(service, "todoist");
                assert_eq!(status_code, Some(403));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn not_found_to_fcp_error() {
        match (TodoistError::NotFound { resource: "task_abc".into() }).to_fcp_error() {
            FcpError::External { status_code, message, retryable, .. } => {
                assert_eq!(status_code, Some(404));
                assert!(message.contains("task_abc"));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_to_fcp_error() {
        match (TodoistError::RateLimited { retry_after_ms: 60_000 }).to_fcp_error() {
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
        match (TodoistError::Api { status_code: 503, message: "unavailable".into() }).to_fcp_error()
        {
            FcpError::External { service, status_code, retryable, message, .. } => {
                assert_eq!(service, "todoist");
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
        match TodoistError::Json(bad.unwrap_err()).to_fcp_error() {
            FcpError::Internal { message } => assert!(message.starts_with("JSON error:")),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn api_error_non_retryable_to_fcp_error() {
        match (TodoistError::Api { status_code: 400, message: "bad".into() }).to_fcp_error() {
            FcpError::External { status_code, retryable, .. } => {
                assert_eq!(status_code, Some(400));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn error_display_unauthorized() {
        assert_eq!(
            TodoistError::Unauthorized.to_string(),
            "Authentication failed: invalid or expired API token"
        );
    }

    #[test]
    fn error_display_forbidden() {
        assert_eq!(
            TodoistError::Forbidden.to_string(),
            "Forbidden: insufficient permissions"
        );
    }

    #[test]
    fn error_display_not_found() {
        assert_eq!(
            TodoistError::NotFound { resource: "task".into() }.to_string(),
            "Not found: task"
        );
    }

    #[test]
    fn error_display_rate_limited() {
        assert_eq!(
            TodoistError::RateLimited { retry_after_ms: 2000 }.to_string(),
            "Rate limited, retry after 2000ms"
        );
    }

    #[test]
    fn error_display_api() {
        assert_eq!(
            TodoistError::Api { status_code: 500, message: "Internal".into() }.to_string(),
            "Todoist API error (500): Internal"
        );
    }

    // ── Additional is_retryable ─────────────────────────────────────

    #[test]
    fn api_502_is_retryable() {
        assert!(TodoistError::Api { status_code: 502, message: "Bad Gateway".into() }.is_retryable());
    }

    #[test]
    fn api_599_is_retryable() {
        assert!(TodoistError::Api { status_code: 599, message: "custom".into() }.is_retryable());
    }

    #[test]
    fn api_499_not_retryable() {
        assert!(!TodoistError::Api { status_code: 499, message: "custom".into() }.is_retryable());
    }

    #[test]
    fn json_error_not_retryable() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{bad");
        assert!(!TodoistError::Json(bad.unwrap_err()).is_retryable());
    }

    // ── Additional retry_after ──────────────────────────────────────

    #[test]
    fn retry_after_none_for_json_error() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{bad");
        assert_eq!(TodoistError::Json(bad.unwrap_err()).retry_after(), None);
    }

    #[test]
    fn retry_after_zero_ms() {
        let err = TodoistError::RateLimited { retry_after_ms: 0 };
        assert_eq!(err.retry_after(), Some(Duration::from_millis(0)));
    }

    #[test]
    fn retry_after_large_value() {
        let err = TodoistError::RateLimited { retry_after_ms: 300_000 };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(300)));
    }

    // ── Additional to_fcp_error ─────────────────────────────────────

    #[test]
    fn rate_limited_fcp_error_service() {
        match (TodoistError::RateLimited { retry_after_ms: 1000 }).to_fcp_error() {
            FcpError::External { service, message, .. } => {
                assert_eq!(service, "todoist");
                assert!(message.contains("1000"));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn not_found_fcp_error_retry_after_none() {
        match (TodoistError::NotFound { resource: "project_xyz".into() }).to_fcp_error() {
            FcpError::External { message, retry_after, .. } => {
                assert!(message.contains("project_xyz"));
                assert!(retry_after.is_none());
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn forbidden_fcp_error_message() {
        match TodoistError::Forbidden.to_fcp_error() {
            FcpError::External { message, retry_after, .. } => {
                assert!(message.contains("permissions"));
                assert!(retry_after.is_none());
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn unauthorized_fcp_error_message() {
        match TodoistError::Unauthorized.to_fcp_error() {
            FcpError::External { message, .. } => {
                assert!(message.contains("Authentication"));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    // ── Display edge cases ──────────────────────────────────────────

    #[test]
    fn error_display_not_found_empty() {
        assert_eq!(TodoistError::NotFound { resource: String::new() }.to_string(), "Not found: ");
    }

    #[test]
    fn error_display_api_empty_message() {
        assert_eq!(TodoistError::Api { status_code: 422, message: String::new() }.to_string(), "Todoist API error (422): ");
    }

    #[test]
    fn error_display_rate_limited_zero() {
        assert_eq!(TodoistError::RateLimited { retry_after_ms: 0 }.to_string(), "Rate limited, retry after 0ms");
    }

    // ── Debug trait ─────────────────────────────────────────────────

    #[test]
    fn error_debug_unauthorized() {
        let dbg = format!("{:?}", TodoistError::Unauthorized);
        assert!(dbg.contains("Unauthorized"));
    }

    #[test]
    fn error_debug_rate_limited() {
        let dbg = format!("{:?}", TodoistError::RateLimited { retry_after_ms: 5000 });
        assert!(dbg.contains("5000"));
    }

    #[test]
    fn error_debug_api() {
        let dbg = format!("{:?}", TodoistError::Api { status_code: 503, message: "down".into() });
        assert!(dbg.contains("503"));
        assert!(dbg.contains("down"));
    }

    #[test]
    fn error_debug_not_found() {
        let dbg = format!("{:?}", TodoistError::NotFound { resource: "task_42".into() });
        assert!(dbg.contains("task_42"));
    }
}
