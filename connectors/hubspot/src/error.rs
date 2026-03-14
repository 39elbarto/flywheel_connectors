//! `HubSpot`-specific error types.

use std::time::Duration;

use fcp_core::FcpError;
use thiserror::Error;
use fcp_async_core::AsyncError;
use fcp_sdk::migration::ConnectorErrorMapping;

/// Result alias for `HubSpot` operations.
pub type HubSpotResult<T> = Result<T, HubSpotError>;

/// `HubSpot`-specific errors.
#[derive(Error, Debug)]
pub enum HubSpotError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// `HubSpot` API returned an error
    #[error("HubSpot API error ({status_code}): {message}")]
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

impl HubSpotError {
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
                service: "hubspot".into(),
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
                service: "hubspot".into(),
                message: message.clone(),
                status_code: Some(*status_code),
                retryable: self.is_retryable(),
                retry_after: None,
            },
            Self::RateLimited { retry_after_ms } => FcpError::External {
                service: "hubspot".into(),
                message: format!("Rate limited, retry after {retry_after_ms}ms"),
                status_code: Some(429),
                retryable: true,
                retry_after: self.retry_after(),
            },
            Self::Unauthorized => FcpError::External {
                service: "hubspot".into(),
                message: "Authentication failed".into(),
                status_code: Some(401),
                retryable: false,
                retry_after: None,
            },
            Self::Forbidden => FcpError::External {
                service: "hubspot".into(),
                message: "Insufficient permissions".into(),
                status_code: Some(403),
                retryable: false,
                retry_after: None,
            },
            Self::NotFound { resource } => FcpError::External {
                service: "hubspot".into(),
                message: format!("Not found: {resource}"),
                status_code: Some(404),
                retryable: false,
                retry_after: None,
            },
        }
    }
}

impl ConnectorErrorMapping for HubSpotError {
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

    // ── is_retryable ─────────────────────────────────────────────────

    #[test]
    fn rate_limited_is_retryable() {
        assert!(
            HubSpotError::RateLimited {
                retry_after_ms: 5000
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_500_is_retryable() {
        assert!(
            HubSpotError::Api {
                status_code: 500,
                message: "err".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_503_is_retryable() {
        assert!(
            HubSpotError::Api {
                status_code: 503,
                message: "unavailable".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_429_is_retryable() {
        assert!(
            HubSpotError::Api {
                status_code: 429,
                message: "too many".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn unauthorized_not_retryable() {
        assert!(!HubSpotError::Unauthorized.is_retryable());
    }

    #[test]
    fn forbidden_not_retryable() {
        assert!(!HubSpotError::Forbidden.is_retryable());
    }

    #[test]
    fn not_found_not_retryable() {
        assert!(
            !HubSpotError::NotFound {
                resource: "contact".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_400_not_retryable() {
        assert!(
            !HubSpotError::Api {
                status_code: 400,
                message: "bad request".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_404_not_retryable() {
        assert!(
            !HubSpotError::Api {
                status_code: 404,
                message: "not found".into()
            }
            .is_retryable()
        );
    }

    // ── retry_after ──────────────────────────────────────────────────

    #[test]
    fn retry_after_for_rate_limited() {
        let err = HubSpotError::RateLimited {
            retry_after_ms: 30_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn retry_after_none_for_unauthorized() {
        assert_eq!(HubSpotError::Unauthorized.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_forbidden() {
        assert_eq!(HubSpotError::Forbidden.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_api_error() {
        assert_eq!(
            HubSpotError::Api {
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
            HubSpotError::NotFound {
                resource: "x".into()
            }
            .retry_after(),
            None
        );
    }

    // ── to_fcp_error ─────────────────────────────────────────────────

    #[test]
    fn unauthorized_to_fcp_error() {
        match HubSpotError::Unauthorized.to_fcp_error() {
            FcpError::External {
                service,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "hubspot");
                assert_eq!(status_code, Some(401));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn forbidden_to_fcp_error() {
        match HubSpotError::Forbidden.to_fcp_error() {
            FcpError::External {
                service,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "hubspot");
                assert_eq!(status_code, Some(403));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn not_found_to_fcp_error() {
        match (HubSpotError::NotFound {
            resource: "deal".into(),
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
                assert!(message.contains("deal"));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_to_fcp_error() {
        match (HubSpotError::RateLimited {
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
        match (HubSpotError::Api {
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
                assert_eq!(service, "hubspot");
                assert_eq!(status_code, Some(503));
                assert!(retryable);
                assert_eq!(message, "unavailable");
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn api_error_non_retryable_to_fcp_error() {
        match (HubSpotError::Api {
            status_code: 400,
            message: "bad request".into(),
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
    fn json_error_to_fcp_internal() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{invalid");
        match HubSpotError::Json(bad.unwrap_err()).to_fcp_error() {
            FcpError::Internal { message } => assert!(message.starts_with("JSON error:")),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    // ── Display ──────────────────────────────────────────────────────

    #[test]
    fn error_display_unauthorized() {
        assert_eq!(
            HubSpotError::Unauthorized.to_string(),
            "Authentication failed: invalid or expired token"
        );
    }

    #[test]
    fn error_display_forbidden() {
        assert_eq!(
            HubSpotError::Forbidden.to_string(),
            "Forbidden: insufficient permissions"
        );
    }

    #[test]
    fn error_display_not_found() {
        assert_eq!(
            HubSpotError::NotFound {
                resource: "contact".into()
            }
            .to_string(),
            "Not found: contact"
        );
    }

    #[test]
    fn error_display_rate_limited() {
        assert_eq!(
            HubSpotError::RateLimited {
                retry_after_ms: 2000
            }
            .to_string(),
            "Rate limited, retry after 2000ms"
        );
    }

    #[test]
    fn error_display_api() {
        assert_eq!(
            HubSpotError::Api {
                status_code: 500,
                message: "Internal".into()
            }
            .to_string(),
            "HubSpot API error (500): Internal"
        );
    }

    // ── Additional is_retryable ─────────────────────────────────────

    #[test]
    fn api_502_is_retryable() {
        assert!(
            HubSpotError::Api {
                status_code: 502,
                message: "Bad Gateway".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_599_is_retryable() {
        assert!(
            HubSpotError::Api {
                status_code: 599,
                message: "custom".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_499_not_retryable() {
        assert!(
            !HubSpotError::Api {
                status_code: 499,
                message: "custom".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn json_error_not_retryable() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{bad");
        assert!(!HubSpotError::Json(bad.unwrap_err()).is_retryable());
    }

    // ── Additional retry_after ──────────────────────────────────────

    #[test]
    fn retry_after_none_for_json_error() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{bad");
        assert_eq!(HubSpotError::Json(bad.unwrap_err()).retry_after(), None);
    }

    #[test]
    fn retry_after_zero_ms() {
        let err = HubSpotError::RateLimited { retry_after_ms: 0 };
        assert_eq!(err.retry_after(), Some(Duration::from_millis(0)));
    }

    #[test]
    fn retry_after_large_value() {
        let err = HubSpotError::RateLimited {
            retry_after_ms: 300_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(300)));
    }

    // ── Additional to_fcp_error ─────────────────────────────────────

    #[test]
    fn rate_limited_fcp_error_service() {
        match (HubSpotError::RateLimited {
            retry_after_ms: 1000,
        })
        .to_fcp_error()
        {
            FcpError::External {
                service, message, ..
            } => {
                assert_eq!(service, "hubspot");
                assert!(message.contains("1000"));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn not_found_fcp_error_retry_after_none() {
        match (HubSpotError::NotFound {
            resource: "deal_x".into(),
        })
        .to_fcp_error()
        {
            FcpError::External {
                message,
                retry_after,
                ..
            } => {
                assert!(message.contains("deal_x"));
                assert!(retry_after.is_none());
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn forbidden_fcp_error_message() {
        match HubSpotError::Forbidden.to_fcp_error() {
            FcpError::External {
                message,
                retry_after,
                ..
            } => {
                assert!(message.contains("permissions"));
                assert!(retry_after.is_none());
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    // ── Display edge cases ──────────────────────────────────────────

    #[test]
    fn error_display_not_found_empty() {
        assert_eq!(
            HubSpotError::NotFound {
                resource: String::new()
            }
            .to_string(),
            "Not found: "
        );
    }

    #[test]
    fn error_display_api_empty_message() {
        assert_eq!(
            HubSpotError::Api {
                status_code: 422,
                message: String::new()
            }
            .to_string(),
            "HubSpot API error (422): "
        );
    }

    #[test]
    fn error_display_rate_limited_zero() {
        assert_eq!(
            HubSpotError::RateLimited { retry_after_ms: 0 }.to_string(),
            "Rate limited, retry after 0ms"
        );
    }

    // ── Debug trait ─────────────────────────────────────────────────

    #[test]
    fn error_debug_unauthorized() {
        let dbg = format!("{:?}", HubSpotError::Unauthorized);
        assert!(dbg.contains("Unauthorized"));
    }

    #[test]
    fn error_debug_rate_limited() {
        let dbg = format!(
            "{:?}",
            HubSpotError::RateLimited {
                retry_after_ms: 5000
            }
        );
        assert!(dbg.contains("5000"));
    }

    #[test]
    fn error_debug_api() {
        let dbg = format!(
            "{:?}",
            HubSpotError::Api {
                status_code: 503,
                message: "down".into()
            }
        );
        assert!(dbg.contains("503"));
        assert!(dbg.contains("down"));
    }

    #[test]
    fn error_debug_not_found() {
        let dbg = format!(
            "{:?}",
            HubSpotError::NotFound {
                resource: "contact_42".into()
            }
        );
        assert!(dbg.contains("contact_42"));
    }

    // ── Additional error edge cases ──────────────────────────────

    #[test]
    fn api_501_is_retryable() {
        assert!(
            HubSpotError::Api {
                status_code: 501,
                message: "not implemented".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_504_is_retryable() {
        assert!(
            HubSpotError::Api {
                status_code: 504,
                message: "gateway timeout".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_error_long_message() {
        let long_msg = "e".repeat(5000);
        let err = HubSpotError::Api {
            status_code: 500,
            message: long_msg.clone(),
        };
        assert!(err.to_string().contains(&long_msg));
    }

    #[test]
    fn not_found_fcp_error_service_is_hubspot() {
        match (HubSpotError::NotFound {
            resource: "company".into(),
        })
        .to_fcp_error()
        {
            FcpError::External { service, .. } => {
                assert_eq!(service, "hubspot");
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_display_large_ms() {
        let err = HubSpotError::RateLimited {
            retry_after_ms: 600_000,
        };
        assert_eq!(err.to_string(), "Rate limited, retry after 600000ms");
    }
}
