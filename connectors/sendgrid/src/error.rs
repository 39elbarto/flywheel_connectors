//! `SendGrid`-specific error types.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_core::FcpError;
use fcp_sdk::migration::ConnectorErrorMapping;
use thiserror::Error;

/// Result alias for `SendGrid` operations.
pub type SendGridResult<T> = Result<T, SendGridError>;

/// `SendGrid`-specific errors.
#[derive(Error, Debug)]
pub enum SendGridError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// `SendGrid` API returned an error
    #[error("SendGrid API error ({status_code}): {message}")]
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

    /// Invalid input (missing field, path traversal, etc.).
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

impl SendGridError {
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
                service: "sendgrid".into(),
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
                service: "sendgrid".into(),
                message: message.clone(),
                status_code: Some(*status_code),
                retryable: self.is_retryable(),
                retry_after: None,
            },
            Self::RateLimited { retry_after_ms } => FcpError::External {
                service: "sendgrid".into(),
                message: format!("Rate limited, retry after {retry_after_ms}ms"),
                status_code: Some(429),
                retryable: true,
                retry_after: self.retry_after(),
            },
            Self::Unauthorized => FcpError::External {
                service: "sendgrid".into(),
                message: "Authentication failed".into(),
                status_code: Some(401),
                retryable: false,
                retry_after: None,
            },
            Self::Forbidden => FcpError::External {
                service: "sendgrid".into(),
                message: "Insufficient permissions".into(),
                status_code: Some(403),
                retryable: false,
                retry_after: None,
            },
            Self::NotFound { resource } => FcpError::External {
                service: "sendgrid".into(),
                message: format!("Not found: {resource}"),
                status_code: Some(404),
                retryable: false,
                retry_after: None,
            },
            Self::InvalidInput(msg) => FcpError::InvalidRequest {
                code: 1005,
                message: format!("Invalid input: {msg}"),
            },
        }
    }
}

impl ConnectorErrorMapping for SendGridError {
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
            SendGridError::RateLimited {
                retry_after_ms: 5000
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_500_is_retryable() {
        assert!(
            SendGridError::Api {
                status_code: 500,
                message: "err".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_503_is_retryable() {
        assert!(
            SendGridError::Api {
                status_code: 503,
                message: "unavailable".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_429_is_retryable() {
        assert!(
            SendGridError::Api {
                status_code: 429,
                message: "too many".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn unauthorized_not_retryable() {
        assert!(!SendGridError::Unauthorized.is_retryable());
    }

    #[test]
    fn forbidden_not_retryable() {
        assert!(!SendGridError::Forbidden.is_retryable());
    }

    #[test]
    fn not_found_not_retryable() {
        assert!(
            !SendGridError::NotFound {
                resource: "contact".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_400_not_retryable() {
        assert!(
            !SendGridError::Api {
                status_code: 400,
                message: "bad request".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn retry_after_for_rate_limited() {
        let err = SendGridError::RateLimited {
            retry_after_ms: 30_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn retry_after_none_for_unauthorized() {
        assert_eq!(SendGridError::Unauthorized.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_forbidden() {
        assert_eq!(SendGridError::Forbidden.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_api_error() {
        assert_eq!(
            SendGridError::Api {
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
            SendGridError::NotFound {
                resource: "x".into()
            }
            .retry_after(),
            None
        );
    }

    #[test]
    fn unauthorized_to_fcp_error() {
        match SendGridError::Unauthorized.to_fcp_error() {
            FcpError::External {
                service,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "sendgrid");
                assert_eq!(status_code, Some(401));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn forbidden_to_fcp_error() {
        match SendGridError::Forbidden.to_fcp_error() {
            FcpError::External {
                service,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "sendgrid");
                assert_eq!(status_code, Some(403));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn not_found_to_fcp_error() {
        match (SendGridError::NotFound {
            resource: "contact_abc".into(),
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
                assert!(message.contains("contact_abc"));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_to_fcp_error() {
        match (SendGridError::RateLimited {
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
        match (SendGridError::Api {
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
                assert_eq!(service, "sendgrid");
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
        match SendGridError::Json(bad.unwrap_err()).to_fcp_error() {
            FcpError::Internal { message } => assert!(message.starts_with("JSON error:")),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn api_error_non_retryable_to_fcp_error() {
        match (SendGridError::Api {
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
            SendGridError::Unauthorized.to_string(),
            "Authentication failed: invalid or expired API key"
        );
    }

    #[test]
    fn error_display_forbidden() {
        assert_eq!(
            SendGridError::Forbidden.to_string(),
            "Forbidden: insufficient permissions"
        );
    }

    #[test]
    fn error_display_not_found() {
        assert_eq!(
            SendGridError::NotFound {
                resource: "contact".into()
            }
            .to_string(),
            "Not found: contact"
        );
    }

    #[test]
    fn error_display_rate_limited() {
        assert_eq!(
            SendGridError::RateLimited {
                retry_after_ms: 2000
            }
            .to_string(),
            "Rate limited, retry after 2000ms"
        );
    }

    #[test]
    fn error_display_api() {
        assert_eq!(
            SendGridError::Api {
                status_code: 500,
                message: "Internal".into()
            }
            .to_string(),
            "SendGrid API error (500): Internal"
        );
    }

    #[test]
    fn api_502_is_retryable() {
        assert!(
            SendGridError::Api {
                status_code: 502,
                message: "bad gateway".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_422_not_retryable() {
        assert!(
            !SendGridError::Api {
                status_code: 422,
                message: "unprocessable".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_504_is_retryable() {
        assert!(
            SendGridError::Api {
                status_code: 504,
                message: "gateway timeout".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn rate_limited_retry_after_small() {
        let err = SendGridError::RateLimited {
            retry_after_ms: 100,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_millis(100)));
    }

    #[test]
    fn error_display_http() {
        let client = reqwest::Client::new();
        let err = client.get("://bad").build().unwrap_err();
        let sg_err = SendGridError::Http(err);
        assert!(sg_err.to_string().starts_with("HTTP error:"));
    }

    #[test]
    fn error_display_json() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{{bad");
        let err = SendGridError::Json(bad.unwrap_err());
        assert!(err.to_string().starts_with("JSON error:"));
    }

    #[test]
    fn json_error_not_retryable() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{bad");
        let err = SendGridError::Json(bad.unwrap_err());
        assert!(!err.is_retryable());
    }

    #[test]
    fn retry_after_none_for_json_error() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{bad");
        let err = SendGridError::Json(bad.unwrap_err());
        assert_eq!(err.retry_after(), None);
    }

    #[test]
    fn rate_limited_zero_retry() {
        let err = SendGridError::RateLimited { retry_after_ms: 0 };
        assert_eq!(err.retry_after(), Some(Duration::from_millis(0)));
        assert!(err.is_retryable());
    }

    #[test]
    fn rate_limited_large_retry() {
        let err = SendGridError::RateLimited {
            retry_after_ms: 3_600_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(3600)));
    }

    #[test]
    fn api_501_is_retryable() {
        assert!(
            SendGridError::Api {
                status_code: 501,
                message: "not implemented".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_599_is_retryable() {
        assert!(
            SendGridError::Api {
                status_code: 599,
                message: "unknown".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_600_not_retryable() {
        assert!(
            !SendGridError::Api {
                status_code: 600,
                message: "invalid".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn http_error_to_fcp_external() {
        let client = reqwest::Client::new();
        let err = client.get("://bad").build().unwrap_err();
        let sg_err = SendGridError::Http(err);
        match sg_err.to_fcp_error() {
            FcpError::External {
                service, retryable, ..
            } => {
                assert_eq!(service, "sendgrid");
                assert!(retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn unauthorized_fcp_message_contains_auth() {
        match SendGridError::Unauthorized.to_fcp_error() {
            FcpError::External { message, .. } => {
                assert!(message.contains("Authentication"));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn forbidden_fcp_message_contains_permissions() {
        match SendGridError::Forbidden.to_fcp_error() {
            FcpError::External { message, .. } => {
                assert!(message.contains("permissions"));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_fcp_message_contains_ms() {
        match (SendGridError::RateLimited {
            retry_after_ms: 5000,
        })
        .to_fcp_error()
        {
            FcpError::External { message, .. } => {
                assert!(message.contains("5000ms"));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn error_debug_variant_names() {
        let err = SendGridError::Unauthorized;
        assert!(format!("{err:?}").contains("Unauthorized"));
        let err2 = SendGridError::Forbidden;
        assert!(format!("{err2:?}").contains("Forbidden"));
    }

    #[test]
    fn not_found_display_with_special_chars() {
        let err = SendGridError::NotFound {
            resource: "contact/abc+123".into(),
        };
        assert!(err.to_string().contains("contact/abc+123"));
    }

    #[test]
    fn api_error_display_empty_message() {
        let err = SendGridError::Api {
            status_code: 500,
            message: String::new(),
        };
        assert_eq!(err.to_string(), "SendGrid API error (500): ");
    }

    #[test]
    fn api_error_retryable_no_retry_after() {
        match (SendGridError::Api {
            status_code: 500,
            message: "err".into(),
        })
        .to_fcp_error()
        {
            FcpError::External { retry_after, .. } => {
                assert!(retry_after.is_none());
            }
            other => panic!("expected External, got {other:?}"),
        }
    }
}
