//! `Pulumi`-specific error types.

use std::time::Duration;

use fcp_core::FcpError;
use fcp_async_core::AsyncError;
use fcp_sdk::migration::ConnectorErrorMapping;
use thiserror::Error;

/// Result alias for `Pulumi` operations.
pub type PulumiResult<T> = Result<T, PulumiError>;

/// `Pulumi`-specific errors.
#[derive(Error, Debug)]
pub enum PulumiError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// `Pulumi` API returned an error
    #[error("Pulumi API error ({status_code}): {message}")]
    Api { status_code: u16, message: String },

    /// Rate limited (429)
    #[error("Rate limited, retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },

    /// Authentication failed (401)
    #[error("Authentication failed: invalid or expired access token")]
    Unauthorized,

    /// Forbidden (403)
    #[error("Forbidden: insufficient permissions")]
    Forbidden,

    /// Resource not found (404)
    #[error("Not found: {resource}")]
    NotFound { resource: String },
}

impl PulumiError {
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
                service: "pulumi".into(),
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
                service: "pulumi".into(),
                message: message.clone(),
                status_code: Some(*status_code),
                retryable: self.is_retryable(),
                retry_after: None,
            },
            Self::RateLimited { retry_after_ms } => FcpError::External {
                service: "pulumi".into(),
                message: format!("Rate limited, retry after {retry_after_ms}ms"),
                status_code: Some(429),
                retryable: true,
                retry_after: self.retry_after(),
            },
            Self::Unauthorized => FcpError::External {
                service: "pulumi".into(),
                message: "Authentication failed".into(),
                status_code: Some(401),
                retryable: false,
                retry_after: None,
            },
            Self::Forbidden => FcpError::External {
                service: "pulumi".into(),
                message: "Insufficient permissions".into(),
                status_code: Some(403),
                retryable: false,
                retry_after: None,
            },
            Self::NotFound { resource } => FcpError::External {
                service: "pulumi".into(),
                message: format!("Not found: {resource}"),
                status_code: Some(404),
                retryable: false,
                retry_after: None,
            },
        }
    }
}


impl ConnectorErrorMapping for PulumiError {
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
            PulumiError::RateLimited {
                retry_after_ms: 5000
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_500_is_retryable() {
        assert!(
            PulumiError::Api {
                status_code: 500,
                message: "err".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_503_is_retryable() {
        assert!(
            PulumiError::Api {
                status_code: 503,
                message: "unavailable".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_429_is_retryable() {
        assert!(
            PulumiError::Api {
                status_code: 429,
                message: "too many".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn unauthorized_not_retryable() {
        assert!(!PulumiError::Unauthorized.is_retryable());
    }

    #[test]
    fn forbidden_not_retryable() {
        assert!(!PulumiError::Forbidden.is_retryable());
    }

    #[test]
    fn not_found_not_retryable() {
        assert!(
            !PulumiError::NotFound {
                resource: "stack".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_400_not_retryable() {
        assert!(
            !PulumiError::Api {
                status_code: 400,
                message: "bad request".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn retry_after_for_rate_limited() {
        let err = PulumiError::RateLimited {
            retry_after_ms: 30_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn retry_after_none_for_unauthorized() {
        assert_eq!(PulumiError::Unauthorized.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_forbidden() {
        assert_eq!(PulumiError::Forbidden.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_api_error() {
        assert_eq!(
            PulumiError::Api {
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
            PulumiError::NotFound {
                resource: "x".into()
            }
            .retry_after(),
            None
        );
    }

    #[test]
    fn unauthorized_to_fcp_error() {
        match PulumiError::Unauthorized.to_fcp_error() {
            FcpError::External {
                service,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "pulumi");
                assert_eq!(status_code, Some(401));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn forbidden_to_fcp_error() {
        match PulumiError::Forbidden.to_fcp_error() {
            FcpError::External {
                service,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "pulumi");
                assert_eq!(status_code, Some(403));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn not_found_to_fcp_error() {
        match (PulumiError::NotFound {
            resource: "myorg/myproj/dev".into(),
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
                assert!(message.contains("myorg/myproj/dev"));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_to_fcp_error() {
        match (PulumiError::RateLimited {
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
        match (PulumiError::Api {
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
                assert_eq!(service, "pulumi");
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
        match PulumiError::Json(bad.unwrap_err()).to_fcp_error() {
            FcpError::Internal { message } => assert!(message.starts_with("JSON error:")),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn api_error_non_retryable_to_fcp_error() {
        match (PulumiError::Api {
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
            PulumiError::Unauthorized.to_string(),
            "Authentication failed: invalid or expired access token"
        );
    }

    #[test]
    fn error_display_forbidden() {
        assert_eq!(
            PulumiError::Forbidden.to_string(),
            "Forbidden: insufficient permissions"
        );
    }

    #[test]
    fn error_display_not_found() {
        assert_eq!(
            PulumiError::NotFound {
                resource: "stack".into()
            }
            .to_string(),
            "Not found: stack"
        );
    }

    #[test]
    fn error_display_rate_limited() {
        assert_eq!(
            PulumiError::RateLimited {
                retry_after_ms: 2000
            }
            .to_string(),
            "Rate limited, retry after 2000ms"
        );
    }

    #[test]
    fn error_display_api() {
        assert_eq!(
            PulumiError::Api {
                status_code: 500,
                message: "Internal".into()
            }
            .to_string(),
            "Pulumi API error (500): Internal"
        );
    }

    // ── Additional edge cases ───────────────────────────────────

    #[test]
    fn api_502_is_retryable() {
        assert!(
            PulumiError::Api {
                status_code: 502,
                message: "bad gateway".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_599_is_retryable() {
        assert!(
            PulumiError::Api {
                status_code: 599,
                message: "custom".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_499_not_retryable() {
        assert!(
            !PulumiError::Api {
                status_code: 499,
                message: "client err".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_404_not_retryable() {
        assert!(
            !PulumiError::Api {
                status_code: 404,
                message: "not found".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn json_error_not_retryable() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{bad");
        let err = PulumiError::Json(bad.unwrap_err());
        assert!(!err.is_retryable());
    }

    #[test]
    fn retry_after_none_for_json_error() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{bad");
        let err = PulumiError::Json(bad.unwrap_err());
        assert_eq!(err.retry_after(), None);
    }

    #[test]
    fn rate_limited_zero_ms() {
        let err = PulumiError::RateLimited { retry_after_ms: 0 };
        assert_eq!(err.retry_after(), Some(Duration::from_millis(0)));
        assert!(err.is_retryable());
    }

    #[test]
    fn rate_limited_large_value() {
        let err = PulumiError::RateLimited {
            retry_after_ms: 3_600_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(3600)));
    }

    #[test]
    fn not_found_empty_resource() {
        let err = PulumiError::NotFound {
            resource: String::new(),
        };
        assert_eq!(err.to_string(), "Not found: ");
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_error_empty_message() {
        let err = PulumiError::Api {
            status_code: 500,
            message: String::new(),
        };
        assert_eq!(err.to_string(), "Pulumi API error (500): ");
        assert!(err.is_retryable());
    }

    #[test]
    fn error_debug_format() {
        let err = PulumiError::Unauthorized;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Unauthorized"));
    }

    #[test]
    fn api_error_debug_shows_fields() {
        let err = PulumiError::Api {
            status_code: 422,
            message: "unprocessable".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("422"));
        assert!(dbg.contains("unprocessable"));
    }

    #[test]
    fn not_found_to_fcp_error_message_content() {
        let err = PulumiError::NotFound {
            resource: "myorg/myproj/staging".into(),
        };
        match err.to_fcp_error() {
            FcpError::External {
                message,
                retry_after,
                ..
            } => {
                assert!(message.contains("myorg/myproj/staging"));
                assert_eq!(retry_after, None);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_to_fcp_error_has_retry_after() {
        let err = PulumiError::RateLimited {
            retry_after_ms: 5000,
        };
        match err.to_fcp_error() {
            FcpError::External { retry_after, .. } => {
                assert_eq!(retry_after, Some(Duration::from_secs(5)));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn api_error_to_fcp_error_no_retry_after() {
        let err = PulumiError::Api {
            status_code: 500,
            message: "err".into(),
        };
        match err.to_fcp_error() {
            FcpError::External { retry_after, .. } => {
                assert_eq!(retry_after, None);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn unauthorized_fcp_error_message() {
        match PulumiError::Unauthorized.to_fcp_error() {
            FcpError::External { message, .. } => {
                assert_eq!(message, "Authentication failed");
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn forbidden_fcp_error_message() {
        match PulumiError::Forbidden.to_fcp_error() {
            FcpError::External { message, .. } => {
                assert_eq!(message, "Insufficient permissions");
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    // ── Additional edge-case tests ────────────────────────────────

    #[test]
    fn api_501_is_retryable() {
        assert!(
            PulumiError::Api {
                status_code: 501,
                message: "not implemented".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_504_is_retryable() {
        assert!(
            PulumiError::Api {
                status_code: 504,
                message: "gateway timeout".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_error_long_message() {
        let long_msg = "x".repeat(10_000);
        let err = PulumiError::Api {
            status_code: 500,
            message: long_msg.clone(),
        };
        let display = err.to_string();
        assert!(display.contains(&long_msg));
    }

    #[test]
    fn not_found_fcp_error_service_is_pulumi() {
        match (PulumiError::NotFound {
            resource: "stack".into(),
        })
        .to_fcp_error()
        {
            FcpError::External { service, .. } => {
                assert_eq!(service, "pulumi");
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_display_large_ms() {
        let err = PulumiError::RateLimited {
            retry_after_ms: 999_999,
        };
        assert_eq!(err.to_string(), "Rate limited, retry after 999999ms");
    }
}
