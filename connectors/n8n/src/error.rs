//! n8n-specific error types.

use std::time::Duration;

use fcp_core::FcpError;
use thiserror::Error;

/// Result alias for n8n operations.
pub type N8nResult<T> = Result<T, N8nError>;

/// n8n-specific errors.
#[derive(Error, Debug)]
pub enum N8nError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// n8n API returned an error
    #[error("n8n API error ({status_code}): {message}")]
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

impl N8nError {
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
                service: "n8n".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
            Self::Api { status_code, message } => FcpError::External {
                service: "n8n".into(),
                message: message.clone(),
                status_code: Some(*status_code),
                retryable: self.is_retryable(),
                retry_after: None,
            },
            Self::RateLimited { retry_after_ms } => FcpError::External {
                service: "n8n".into(),
                message: format!("Rate limited, retry after {retry_after_ms}ms"),
                status_code: Some(429),
                retryable: true,
                retry_after: self.retry_after(),
            },
            Self::Unauthorized => FcpError::External {
                service: "n8n".into(),
                message: "Authentication failed".into(),
                status_code: Some(401),
                retryable: false,
                retry_after: None,
            },
            Self::Forbidden => FcpError::External {
                service: "n8n".into(),
                message: "Insufficient permissions".into(),
                status_code: Some(403),
                retryable: false,
                retry_after: None,
            },
            Self::NotFound { resource } => FcpError::External {
                service: "n8n".into(),
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
        assert!(N8nError::RateLimited { retry_after_ms: 5000 }.is_retryable());
    }

    #[test]
    fn api_500_is_retryable() {
        assert!(N8nError::Api { status_code: 500, message: "err".into() }.is_retryable());
    }

    #[test]
    fn api_502_is_retryable() {
        assert!(N8nError::Api { status_code: 502, message: "bad gateway".into() }.is_retryable());
    }

    #[test]
    fn api_503_is_retryable() {
        assert!(N8nError::Api { status_code: 503, message: "unavailable".into() }.is_retryable());
    }

    #[test]
    fn api_429_is_retryable() {
        assert!(N8nError::Api { status_code: 429, message: "too many".into() }.is_retryable());
    }

    #[test]
    fn unauthorized_not_retryable() {
        assert!(!N8nError::Unauthorized.is_retryable());
    }

    #[test]
    fn forbidden_not_retryable() {
        assert!(!N8nError::Forbidden.is_retryable());
    }

    #[test]
    fn not_found_not_retryable() {
        assert!(!N8nError::NotFound { resource: "workflow".into() }.is_retryable());
    }

    #[test]
    fn api_400_not_retryable() {
        assert!(!N8nError::Api { status_code: 400, message: "bad request".into() }.is_retryable());
    }

    #[test]
    fn api_404_via_enum_not_retryable() {
        assert!(!N8nError::Api { status_code: 404, message: "not found".into() }.is_retryable());
    }

    #[test]
    fn api_409_not_retryable() {
        assert!(!N8nError::Api { status_code: 409, message: "conflict".into() }.is_retryable());
    }

    #[test]
    fn retry_after_for_rate_limited() {
        let err = N8nError::RateLimited { retry_after_ms: 30000 };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn retry_after_none_for_unauthorized() {
        assert_eq!(N8nError::Unauthorized.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_forbidden() {
        assert_eq!(N8nError::Forbidden.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_api_error() {
        assert_eq!(
            N8nError::Api { status_code: 500, message: "err".into() }.retry_after(),
            None
        );
    }

    #[test]
    fn retry_after_none_for_not_found() {
        assert_eq!(N8nError::NotFound { resource: "x".into() }.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_json_error() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{invalid");
        assert_eq!(N8nError::Json(bad.unwrap_err()).retry_after(), None);
    }

    #[test]
    fn unauthorized_to_fcp_error() {
        match N8nError::Unauthorized.to_fcp_error() {
            FcpError::External { service, status_code, retryable, .. } => {
                assert_eq!(service, "n8n");
                assert_eq!(status_code, Some(401));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn forbidden_to_fcp_error() {
        match N8nError::Forbidden.to_fcp_error() {
            FcpError::External { service, status_code, retryable, .. } => {
                assert_eq!(service, "n8n");
                assert_eq!(status_code, Some(403));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn not_found_to_fcp_error() {
        match (N8nError::NotFound { resource: "workflow_123".into() }).to_fcp_error() {
            FcpError::External { status_code, message, retryable, .. } => {
                assert_eq!(status_code, Some(404));
                assert!(message.contains("workflow_123"));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_to_fcp_error() {
        match (N8nError::RateLimited { retry_after_ms: 60000 }).to_fcp_error() {
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
        match (N8nError::Api { status_code: 503, message: "unavailable".into() }).to_fcp_error() {
            FcpError::External { service, status_code, retryable, message, .. } => {
                assert_eq!(service, "n8n");
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
        match N8nError::Json(bad.unwrap_err()).to_fcp_error() {
            FcpError::Internal { message } => assert!(message.starts_with("JSON error:")),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn api_error_non_retryable_to_fcp_error() {
        match (N8nError::Api { status_code: 400, message: "bad".into() }).to_fcp_error() {
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
            N8nError::Unauthorized.to_string(),
            "Authentication failed: invalid or expired API key"
        );
    }

    #[test]
    fn error_display_forbidden() {
        assert_eq!(
            N8nError::Forbidden.to_string(),
            "Forbidden: insufficient permissions"
        );
    }

    #[test]
    fn error_display_not_found() {
        assert_eq!(
            N8nError::NotFound { resource: "workflow".into() }.to_string(),
            "Not found: workflow"
        );
    }

    #[test]
    fn error_display_rate_limited() {
        assert_eq!(
            N8nError::RateLimited { retry_after_ms: 2000 }.to_string(),
            "Rate limited, retry after 2000ms"
        );
    }

    #[test]
    fn error_display_api() {
        assert_eq!(
            N8nError::Api { status_code: 500, message: "Internal".into() }.to_string(),
            "n8n API error (500): Internal"
        );
    }

    #[test]
    fn api_error_retryable_500_range() {
        for code in [500, 501, 502, 503, 504, 599] {
            assert!(
                N8nError::Api { status_code: code, message: "err".into() }.is_retryable(),
                "expected {code} to be retryable"
            );
        }
    }

    #[test]
    fn api_error_non_retryable_4xx() {
        for code in [400, 401, 403, 404, 405, 409, 422] {
            assert!(
                !N8nError::Api { status_code: code, message: "err".into() }.is_retryable(),
                "expected {code} to not be retryable"
            );
        }
    }

    #[test]
    fn rate_limited_zero_retry_after() {
        let err = N8nError::RateLimited { retry_after_ms: 0 };
        assert_eq!(err.retry_after(), Some(Duration::from_millis(0)));
        assert!(err.is_retryable());
    }

    #[test]
    fn api_error_service_name_in_fcp_error() {
        match (N8nError::Api { status_code: 422, message: "unprocessable".into() }).to_fcp_error() {
            FcpError::External { service, .. } => assert_eq!(service, "n8n"),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn error_debug_format_unauthorized() {
        let dbg = format!("{:?}", N8nError::Unauthorized);
        assert!(dbg.contains("Unauthorized"));
    }

    #[test]
    fn error_debug_format_forbidden() {
        let dbg = format!("{:?}", N8nError::Forbidden);
        assert!(dbg.contains("Forbidden"));
    }

    #[test]
    fn error_debug_format_not_found() {
        let dbg = format!("{:?}", N8nError::NotFound { resource: "wf".into() });
        assert!(dbg.contains("NotFound"));
        assert!(dbg.contains("wf"));
    }

    #[test]
    fn error_debug_format_rate_limited() {
        let dbg = format!("{:?}", N8nError::RateLimited { retry_after_ms: 100 });
        assert!(dbg.contains("RateLimited"));
        assert!(dbg.contains("100"));
    }

    #[test]
    fn error_debug_format_api() {
        let dbg = format!("{:?}", N8nError::Api { status_code: 418, message: "teapot".into() });
        assert!(dbg.contains("Api"));
        assert!(dbg.contains("418"));
    }

    #[test]
    fn api_error_599_is_retryable() {
        assert!(N8nError::Api { status_code: 599, message: "custom".into() }.is_retryable());
    }

    #[test]
    fn api_error_504_is_retryable() {
        assert!(N8nError::Api { status_code: 504, message: "timeout".into() }.is_retryable());
    }

    #[test]
    fn rate_limited_large_retry_after() {
        let err = N8nError::RateLimited { retry_after_ms: 3_600_000 };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(3600)));
    }

    #[test]
    fn unauthorized_fcp_error_retry_after_none() {
        match N8nError::Unauthorized.to_fcp_error() {
            FcpError::External { retry_after, .. } => assert!(retry_after.is_none()),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn forbidden_fcp_error_retry_after_none() {
        match N8nError::Forbidden.to_fcp_error() {
            FcpError::External { retry_after, .. } => assert!(retry_after.is_none()),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn json_error_not_retryable() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{invalid");
        assert!(!N8nError::Json(bad.unwrap_err()).is_retryable());
    }

    #[test]
    fn not_found_fcp_error_retry_after_none() {
        match (N8nError::NotFound { resource: "x".into() }).to_fcp_error() {
            FcpError::External { retry_after, .. } => assert!(retry_after.is_none()),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn api_error_fcp_retry_after_is_none() {
        match (N8nError::Api { status_code: 502, message: "gw".into() }).to_fcp_error() {
            FcpError::External { retry_after, .. } => assert!(retry_after.is_none()),
            other => panic!("expected External, got {other:?}"),
        }
    }
}
