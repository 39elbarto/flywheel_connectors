//! `Metabase`-specific error types.

use std::time::Duration;

use fcp_core::FcpError;
use thiserror::Error;

/// Result alias for `Metabase` operations.
pub type MetabaseResult<T> = Result<T, MetabaseError>;

/// `Metabase`-specific errors.
#[derive(Error, Debug)]
pub enum MetabaseError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// `Metabase` API returned an error
    #[error("Metabase API error ({status_code}): {message}")]
    Api { status_code: u16, message: String },

    /// Rate limited (429)
    #[error("Rate limited, retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },

    /// Authentication failed (401)
    #[error("Authentication failed: invalid or expired session token")]
    Unauthorized,

    /// Forbidden (403)
    #[error("Forbidden: insufficient permissions")]
    Forbidden,

    /// Resource not found (404)
    #[error("Not found: {resource}")]
    NotFound { resource: String },
}

impl MetabaseError {
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
                service: "metabase".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
            Self::Api { status_code, message } => FcpError::External {
                service: "metabase".into(),
                message: message.clone(),
                status_code: Some(*status_code),
                retryable: self.is_retryable(),
                retry_after: None,
            },
            Self::RateLimited { retry_after_ms } => FcpError::External {
                service: "metabase".into(),
                message: format!("Rate limited, retry after {retry_after_ms}ms"),
                status_code: Some(429),
                retryable: true,
                retry_after: self.retry_after(),
            },
            Self::Unauthorized => FcpError::External {
                service: "metabase".into(),
                message: "Authentication failed".into(),
                status_code: Some(401),
                retryable: false,
                retry_after: None,
            },
            Self::Forbidden => FcpError::External {
                service: "metabase".into(),
                message: "Insufficient permissions".into(),
                status_code: Some(403),
                retryable: false,
                retry_after: None,
            },
            Self::NotFound { resource } => FcpError::External {
                service: "metabase".into(),
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
        assert!(MetabaseError::RateLimited { retry_after_ms: 5000 }.is_retryable());
    }

    #[test]
    fn api_500_is_retryable() {
        assert!(MetabaseError::Api { status_code: 500, message: "err".into() }.is_retryable());
    }

    #[test]
    fn api_503_is_retryable() {
        assert!(
            MetabaseError::Api { status_code: 503, message: "unavailable".into() }.is_retryable()
        );
    }

    #[test]
    fn api_429_is_retryable() {
        assert!(MetabaseError::Api { status_code: 429, message: "too many".into() }.is_retryable());
    }

    #[test]
    fn unauthorized_not_retryable() {
        assert!(!MetabaseError::Unauthorized.is_retryable());
    }

    #[test]
    fn forbidden_not_retryable() {
        assert!(!MetabaseError::Forbidden.is_retryable());
    }

    #[test]
    fn not_found_not_retryable() {
        assert!(!MetabaseError::NotFound { resource: "dashboard".into() }.is_retryable());
    }

    #[test]
    fn api_400_not_retryable() {
        assert!(
            !MetabaseError::Api { status_code: 400, message: "bad request".into() }.is_retryable()
        );
    }

    #[test]
    fn retry_after_for_rate_limited() {
        let err = MetabaseError::RateLimited { retry_after_ms: 30_000 };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn retry_after_none_for_unauthorized() {
        assert_eq!(MetabaseError::Unauthorized.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_forbidden() {
        assert_eq!(MetabaseError::Forbidden.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_api_error() {
        assert_eq!(
            MetabaseError::Api { status_code: 500, message: "err".into() }.retry_after(),
            None
        );
    }

    #[test]
    fn retry_after_none_for_not_found() {
        assert_eq!(MetabaseError::NotFound { resource: "x".into() }.retry_after(), None);
    }

    #[test]
    fn unauthorized_to_fcp_error() {
        match MetabaseError::Unauthorized.to_fcp_error() {
            FcpError::External { service, status_code, retryable, .. } => {
                assert_eq!(service, "metabase");
                assert_eq!(status_code, Some(401));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn forbidden_to_fcp_error() {
        match MetabaseError::Forbidden.to_fcp_error() {
            FcpError::External { service, status_code, retryable, .. } => {
                assert_eq!(service, "metabase");
                assert_eq!(status_code, Some(403));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn not_found_to_fcp_error() {
        match (MetabaseError::NotFound { resource: "card_42".into() }).to_fcp_error() {
            FcpError::External { status_code, message, retryable, .. } => {
                assert_eq!(status_code, Some(404));
                assert!(message.contains("card_42"));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_to_fcp_error() {
        match (MetabaseError::RateLimited { retry_after_ms: 60_000 }).to_fcp_error() {
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
        match (MetabaseError::Api { status_code: 503, message: "unavailable".into() }).to_fcp_error()
        {
            FcpError::External { service, status_code, retryable, message, .. } => {
                assert_eq!(service, "metabase");
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
        match MetabaseError::Json(bad.unwrap_err()).to_fcp_error() {
            FcpError::Internal { message } => assert!(message.starts_with("JSON error:")),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn api_error_non_retryable_to_fcp_error() {
        match (MetabaseError::Api { status_code: 400, message: "bad".into() }).to_fcp_error() {
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
            MetabaseError::Unauthorized.to_string(),
            "Authentication failed: invalid or expired session token"
        );
    }

    #[test]
    fn error_display_forbidden() {
        assert_eq!(
            MetabaseError::Forbidden.to_string(),
            "Forbidden: insufficient permissions"
        );
    }

    #[test]
    fn error_display_not_found() {
        assert_eq!(
            MetabaseError::NotFound { resource: "dashboard".into() }.to_string(),
            "Not found: dashboard"
        );
    }

    #[test]
    fn error_display_rate_limited() {
        assert_eq!(
            MetabaseError::RateLimited { retry_after_ms: 2000 }.to_string(),
            "Rate limited, retry after 2000ms"
        );
    }

    #[test]
    fn error_display_api() {
        assert_eq!(
            MetabaseError::Api { status_code: 500, message: "Internal".into() }.to_string(),
            "Metabase API error (500): Internal"
        );
    }

    #[test]
    fn error_display_http() {
        // Build an HTTP error from reqwest
        let client = reqwest::Client::new();
        let err = client
            .get("http://[::invalid::host]")
            .build()
            .unwrap_err();
        let me = MetabaseError::Http(err);
        let display = me.to_string();
        assert!(display.starts_with("HTTP error:"), "got: {display}");
    }

    #[test]
    fn error_display_json() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{bad");
        let me = MetabaseError::Json(bad.unwrap_err());
        let display = me.to_string();
        assert!(display.starts_with("JSON error:"), "got: {display}");
    }

    #[test]
    fn error_debug_unauthorized() {
        let dbg = format!("{:?}", MetabaseError::Unauthorized);
        assert!(dbg.contains("Unauthorized"));
    }

    #[test]
    fn error_debug_forbidden() {
        let dbg = format!("{:?}", MetabaseError::Forbidden);
        assert!(dbg.contains("Forbidden"));
    }

    #[test]
    fn error_debug_not_found() {
        let dbg = format!("{:?}", MetabaseError::NotFound { resource: "card".into() });
        assert!(dbg.contains("NotFound"));
        assert!(dbg.contains("card"));
    }

    #[test]
    fn error_debug_rate_limited() {
        let dbg = format!("{:?}", MetabaseError::RateLimited { retry_after_ms: 5000 });
        assert!(dbg.contains("RateLimited"));
        assert!(dbg.contains("5000"));
    }

    #[test]
    fn error_debug_api() {
        let dbg = format!("{:?}", MetabaseError::Api { status_code: 502, message: "bad gateway".into() });
        assert!(dbg.contains("Api"));
        assert!(dbg.contains("502"));
        assert!(dbg.contains("bad gateway"));
    }

    #[test]
    fn api_501_is_retryable() {
        assert!(MetabaseError::Api { status_code: 501, message: "not impl".into() }.is_retryable());
    }

    #[test]
    fn api_502_is_retryable() {
        assert!(
            MetabaseError::Api { status_code: 502, message: "bad gateway".into() }.is_retryable()
        );
    }

    #[test]
    fn api_504_is_retryable() {
        assert!(MetabaseError::Api { status_code: 504, message: "timeout".into() }.is_retryable());
    }

    #[test]
    fn api_599_is_retryable() {
        assert!(MetabaseError::Api { status_code: 599, message: "custom".into() }.is_retryable());
    }

    #[test]
    fn api_200_not_retryable() {
        assert!(!MetabaseError::Api { status_code: 200, message: "ok".into() }.is_retryable());
    }

    #[test]
    fn api_404_not_retryable() {
        assert!(!MetabaseError::Api { status_code: 404, message: "gone".into() }.is_retryable());
    }

    #[test]
    fn json_not_retryable() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{bad");
        assert!(!MetabaseError::Json(bad.unwrap_err()).is_retryable());
    }

    #[test]
    fn retry_after_none_for_json() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{bad");
        assert_eq!(MetabaseError::Json(bad.unwrap_err()).retry_after(), None);
    }

    #[test]
    fn retry_after_rate_limited_zero_ms() {
        let err = MetabaseError::RateLimited { retry_after_ms: 0 };
        assert_eq!(err.retry_after(), Some(Duration::from_millis(0)));
    }

    #[test]
    fn retry_after_rate_limited_large_value() {
        let err = MetabaseError::RateLimited { retry_after_ms: 300_000 };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(300)));
    }

    #[test]
    fn http_error_to_fcp_external() {
        let client = reqwest::Client::new();
        let err = client
            .get("http://[::invalid::host]")
            .build()
            .unwrap_err();
        let me = MetabaseError::Http(err);
        match me.to_fcp_error() {
            FcpError::External { service, retryable, .. } => {
                assert_eq!(service, "metabase");
                assert!(retryable); // HTTP errors are retryable
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn api_error_422_to_fcp_error() {
        match (MetabaseError::Api { status_code: 422, message: "unprocessable".into() })
            .to_fcp_error()
        {
            FcpError::External { status_code, retryable, message, .. } => {
                assert_eq!(status_code, Some(422));
                assert!(!retryable);
                assert_eq!(message, "unprocessable");
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn api_error_502_to_fcp_error() {
        match (MetabaseError::Api { status_code: 502, message: "bad gw".into() }).to_fcp_error() {
            FcpError::External { status_code, retryable, .. } => {
                assert_eq!(status_code, Some(502));
                assert!(retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_zero_to_fcp_error() {
        match (MetabaseError::RateLimited { retry_after_ms: 0 }).to_fcp_error() {
            FcpError::External { retry_after, retryable, .. } => {
                assert!(retryable);
                assert_eq!(retry_after, Some(Duration::from_millis(0)));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn not_found_fcp_error_has_service() {
        match (MetabaseError::NotFound { resource: "db_99".into() }).to_fcp_error() {
            FcpError::External { service, .. } => {
                assert_eq!(service, "metabase");
            }
            other => panic!("expected External, got {other:?}"),
        }
    }
}
