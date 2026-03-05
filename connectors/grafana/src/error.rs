//! Grafana-specific error types.

use std::time::Duration;

use fcp_core::FcpError;
use thiserror::Error;

/// Result alias for Grafana operations.
pub type GrafanaResult<T> = Result<T, GrafanaError>;

/// Grafana-specific errors.
#[derive(Error, Debug)]
pub enum GrafanaError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Grafana API returned an error
    #[error("Grafana API error ({status_code}): {message}")]
    Api { status_code: u16, message: String },

    /// Rate limited (429)
    #[error("Rate limited, retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },

    /// Authentication failed (401)
    #[error("Authentication failed: invalid API key or token")]
    Unauthorized,

    /// Forbidden (403)
    #[error("Forbidden: insufficient permissions")]
    Forbidden,

    /// Resource not found (404)
    #[error("Not found: {resource}")]
    NotFound { resource: String },
}

impl GrafanaError {
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
                service: "grafana".into(),
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
                service: "grafana".into(),
                message: message.clone(),
                status_code: Some(*status_code),
                retryable: self.is_retryable(),
                retry_after: None,
            },
            Self::RateLimited { retry_after_ms } => FcpError::External {
                service: "grafana".into(),
                message: format!("Rate limited, retry after {retry_after_ms}ms"),
                status_code: Some(429),
                retryable: true,
                retry_after: self.retry_after(),
            },
            Self::Unauthorized => FcpError::External {
                service: "grafana".into(),
                message: "Authentication failed".into(),
                status_code: Some(401),
                retryable: false,
                retry_after: None,
            },
            Self::Forbidden => FcpError::External {
                service: "grafana".into(),
                message: "Insufficient permissions".into(),
                status_code: Some(403),
                retryable: false,
                retry_after: None,
            },
            Self::NotFound { resource } => FcpError::External {
                service: "grafana".into(),
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
        assert!(GrafanaError::RateLimited { retry_after_ms: 5000 }.is_retryable());
    }

    #[test]
    fn api_500_is_retryable() {
        assert!(GrafanaError::Api { status_code: 500, message: "err".into() }.is_retryable());
    }

    #[test]
    fn api_503_is_retryable() {
        assert!(GrafanaError::Api { status_code: 503, message: "unavailable".into() }.is_retryable());
    }

    #[test]
    fn api_429_is_retryable() {
        assert!(GrafanaError::Api { status_code: 429, message: "too many".into() }.is_retryable());
    }

    #[test]
    fn unauthorized_not_retryable() {
        assert!(!GrafanaError::Unauthorized.is_retryable());
    }

    #[test]
    fn forbidden_not_retryable() {
        assert!(!GrafanaError::Forbidden.is_retryable());
    }

    #[test]
    fn not_found_not_retryable() {
        assert!(!GrafanaError::NotFound { resource: "dash".into() }.is_retryable());
    }

    #[test]
    fn api_400_not_retryable() {
        assert!(!GrafanaError::Api { status_code: 400, message: "bad".into() }.is_retryable());
    }

    #[test]
    fn api_404_not_retryable() {
        assert!(!GrafanaError::Api { status_code: 404, message: "not found".into() }.is_retryable());
    }

    // ── retry_after ──────────────────────────────────────────────────

    #[test]
    fn retry_after_for_rate_limited() {
        let err = GrafanaError::RateLimited { retry_after_ms: 30_000 };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn retry_after_none_for_unauthorized() {
        assert_eq!(GrafanaError::Unauthorized.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_forbidden() {
        assert_eq!(GrafanaError::Forbidden.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_api_error() {
        assert_eq!(GrafanaError::Api { status_code: 500, message: "err".into() }.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_not_found() {
        assert_eq!(GrafanaError::NotFound { resource: "x".into() }.retry_after(), None);
    }

    // ── to_fcp_error ─────────────────────────────────────────────────

    #[test]
    fn unauthorized_to_fcp_error() {
        match GrafanaError::Unauthorized.to_fcp_error() {
            FcpError::External { service, status_code, retryable, .. } => {
                assert_eq!(service, "grafana");
                assert_eq!(status_code, Some(401));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn forbidden_to_fcp_error() {
        match GrafanaError::Forbidden.to_fcp_error() {
            FcpError::External { service, status_code, retryable, .. } => {
                assert_eq!(service, "grafana");
                assert_eq!(status_code, Some(403));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn not_found_to_fcp_error() {
        match (GrafanaError::NotFound { resource: "dashboard".into() }).to_fcp_error() {
            FcpError::External { status_code, message, retryable, .. } => {
                assert_eq!(status_code, Some(404));
                assert!(message.contains("dashboard"));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_to_fcp_error() {
        match (GrafanaError::RateLimited { retry_after_ms: 60_000 }).to_fcp_error() {
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
        match (GrafanaError::Api { status_code: 503, message: "unavailable".into() }).to_fcp_error() {
            FcpError::External { service, status_code, retryable, message, .. } => {
                assert_eq!(service, "grafana");
                assert_eq!(status_code, Some(503));
                assert!(retryable);
                assert_eq!(message, "unavailable");
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn api_error_non_retryable_to_fcp_error() {
        match (GrafanaError::Api { status_code: 400, message: "bad request".into() }).to_fcp_error() {
            FcpError::External { status_code, retryable, .. } => {
                assert_eq!(status_code, Some(400));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn json_error_to_fcp_internal() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{invalid");
        match GrafanaError::Json(bad.unwrap_err()).to_fcp_error() {
            FcpError::Internal { message } => assert!(message.starts_with("JSON error:")),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    // ── Display ──────────────────────────────────────────────────────

    #[test]
    fn error_display_unauthorized() {
        assert_eq!(GrafanaError::Unauthorized.to_string(), "Authentication failed: invalid API key or token");
    }

    #[test]
    fn error_display_forbidden() {
        assert_eq!(GrafanaError::Forbidden.to_string(), "Forbidden: insufficient permissions");
    }

    #[test]
    fn error_display_not_found() {
        assert_eq!(GrafanaError::NotFound { resource: "dashboard".into() }.to_string(), "Not found: dashboard");
    }

    #[test]
    fn error_display_rate_limited() {
        assert_eq!(GrafanaError::RateLimited { retry_after_ms: 1000 }.to_string(), "Rate limited, retry after 1000ms");
    }

    #[test]
    fn error_display_api() {
        assert_eq!(GrafanaError::Api { status_code: 500, message: "Internal".into() }.to_string(), "Grafana API error (500): Internal");
    }
}
