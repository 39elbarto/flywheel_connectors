//! `Salesforce`-specific error types.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_sdk::migration::ConnectorErrorMapping;
use thiserror::Error;

/// Result alias for `Salesforce` operations.
pub type SalesforceResult<T> = Result<T, SalesforceError>;

/// `Salesforce`-specific errors.
#[derive(Error, Debug)]
pub enum SalesforceError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// `Salesforce` API returned an error
    #[error("Salesforce API error ({status_code}): {message}")]
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

    /// Invalid input (path traversal, injection attempt, etc.)
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

impl SalesforceError {
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
                service: "salesforce".into(),
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
                service: "salesforce".into(),
                message: message.clone(),
                status_code: Some(*status_code),
                retryable: self.is_retryable(),
                retry_after: None,
            },
            Self::RateLimited { retry_after_ms } => FcpError::External {
                service: "salesforce".into(),
                message: format!("Rate limited, retry after {retry_after_ms}ms"),
                status_code: Some(429),
                retryable: true,
                retry_after: self.retry_after(),
            },
            Self::Unauthorized => FcpError::External {
                service: "salesforce".into(),
                message: "Authentication failed".into(),
                status_code: Some(401),
                retryable: false,
                retry_after: None,
            },
            Self::Forbidden => FcpError::External {
                service: "salesforce".into(),
                message: "Insufficient permissions".into(),
                status_code: Some(403),
                retryable: false,
                retry_after: None,
            },
            Self::NotFound { resource } => FcpError::External {
                service: "salesforce".into(),
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

impl ConnectorErrorMapping for SalesforceError {
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

    // -- is_retryable --

    #[test]
    fn rate_limited_is_retryable() {
        assert!(
            SalesforceError::RateLimited {
                retry_after_ms: 5000
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_500_is_retryable() {
        assert!(
            SalesforceError::Api {
                status_code: 500,
                message: "err".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_502_is_retryable() {
        assert!(
            SalesforceError::Api {
                status_code: 502,
                message: "bad gateway".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_429_is_retryable() {
        assert!(
            SalesforceError::Api {
                status_code: 429,
                message: "too many".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn unauthorized_not_retryable() {
        assert!(!SalesforceError::Unauthorized.is_retryable());
    }

    #[test]
    fn forbidden_not_retryable() {
        assert!(!SalesforceError::Forbidden.is_retryable());
    }

    #[test]
    fn not_found_not_retryable() {
        assert!(
            !SalesforceError::NotFound {
                resource: "account".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_400_not_retryable() {
        assert!(
            !SalesforceError::Api {
                status_code: 400,
                message: "bad".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_404_not_retryable() {
        assert!(
            !SalesforceError::Api {
                status_code: 404,
                message: "not found".into()
            }
            .is_retryable()
        );
    }

    // -- retry_after --

    #[test]
    fn retry_after_for_rate_limited() {
        let err = SalesforceError::RateLimited {
            retry_after_ms: 30_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn retry_after_none_for_unauthorized() {
        assert_eq!(SalesforceError::Unauthorized.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_forbidden() {
        assert_eq!(SalesforceError::Forbidden.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_api_error() {
        assert_eq!(
            SalesforceError::Api {
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
            SalesforceError::NotFound {
                resource: "x".into()
            }
            .retry_after(),
            None
        );
    }

    // -- to_fcp_error --

    #[test]
    fn unauthorized_to_fcp_error() {
        match SalesforceError::Unauthorized.to_fcp_error() {
            FcpError::External {
                service,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "salesforce");
                assert_eq!(status_code, Some(401));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn forbidden_to_fcp_error() {
        match SalesforceError::Forbidden.to_fcp_error() {
            FcpError::External {
                service,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "salesforce");
                assert_eq!(status_code, Some(403));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn not_found_to_fcp_error() {
        match (SalesforceError::NotFound {
            resource: "account".into(),
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
                assert_eq!(service, "salesforce");
                assert_eq!(status_code, Some(404));
                assert!(message.contains("account"));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_to_fcp_error() {
        match (SalesforceError::RateLimited {
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
        match (SalesforceError::Api {
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
                assert_eq!(service, "salesforce");
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
        match SalesforceError::Json(bad.unwrap_err()).to_fcp_error() {
            FcpError::Internal { message } => assert!(message.starts_with("JSON error:")),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn api_error_non_retryable_to_fcp_error() {
        match (SalesforceError::Api {
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

    // -- Display --

    #[test]
    fn error_display_unauthorized() {
        assert_eq!(
            SalesforceError::Unauthorized.to_string(),
            "Authentication failed: invalid or expired token"
        );
    }

    #[test]
    fn error_display_forbidden() {
        assert_eq!(
            SalesforceError::Forbidden.to_string(),
            "Forbidden: insufficient permissions"
        );
    }

    #[test]
    fn error_display_not_found() {
        assert_eq!(
            SalesforceError::NotFound {
                resource: "contact".into()
            }
            .to_string(),
            "Not found: contact"
        );
    }

    #[test]
    fn error_display_rate_limited() {
        assert_eq!(
            SalesforceError::RateLimited {
                retry_after_ms: 1000
            }
            .to_string(),
            "Rate limited, retry after 1000ms"
        );
    }

    #[test]
    fn error_display_api() {
        assert_eq!(
            SalesforceError::Api {
                status_code: 500,
                message: "Internal".into()
            }
            .to_string(),
            "Salesforce API error (500): Internal"
        );
    }

    // -- Additional error tests --

    #[test]
    fn api_599_is_retryable() {
        assert!(
            SalesforceError::Api {
                status_code: 599,
                message: "err".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_501_is_retryable() {
        assert!(
            SalesforceError::Api {
                status_code: 501,
                message: "not implemented".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_499_not_retryable() {
        assert!(
            !SalesforceError::Api {
                status_code: 499,
                message: "err".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_600_not_retryable() {
        assert!(
            !SalesforceError::Api {
                status_code: 600,
                message: "err".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_422_not_retryable() {
        assert!(
            !SalesforceError::Api {
                status_code: 422,
                message: "unprocessable".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn rate_limited_zero_ms() {
        let err = SalesforceError::RateLimited { retry_after_ms: 0 };
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(Duration::from_millis(0)));
    }

    #[test]
    fn rate_limited_large_value() {
        let err = SalesforceError::RateLimited {
            retry_after_ms: 3_600_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(3600)));
    }

    #[test]
    fn not_found_empty_resource() {
        let err = SalesforceError::NotFound {
            resource: String::new(),
        };
        assert_eq!(err.to_string(), "Not found: ");
        assert!(!err.is_retryable());
        assert_eq!(err.retry_after(), None);
    }

    #[test]
    fn api_error_empty_message() {
        let err = SalesforceError::Api {
            status_code: 400,
            message: String::new(),
        };
        assert_eq!(err.to_string(), "Salesforce API error (400): ");
    }

    #[test]
    fn error_debug_format() {
        let err = SalesforceError::Unauthorized;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Unauthorized"));
    }

    #[test]
    fn error_debug_not_found() {
        let err = SalesforceError::NotFound {
            resource: "lead".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("NotFound"));
        assert!(dbg.contains("lead"));
    }

    #[test]
    fn error_debug_rate_limited() {
        let err = SalesforceError::RateLimited {
            retry_after_ms: 1000,
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("RateLimited"));
        assert!(dbg.contains("1000"));
    }

    #[test]
    fn to_fcp_error_rate_limited_message_contains_ms() {
        match (SalesforceError::RateLimited {
            retry_after_ms: 5000,
        })
        .to_fcp_error()
        {
            FcpError::External { message, .. } => {
                assert!(message.contains("5000"));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_not_found_retry_after_is_none() {
        match (SalesforceError::NotFound {
            resource: "x".into(),
        })
        .to_fcp_error()
        {
            FcpError::External { retry_after, .. } => {
                assert!(retry_after.is_none());
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_retryable_has_no_retry_after() {
        match (SalesforceError::Api {
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
    fn to_fcp_error_unauthorized_message() {
        match SalesforceError::Unauthorized.to_fcp_error() {
            FcpError::External { message, .. } => {
                assert_eq!(message, "Authentication failed");
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_forbidden_message() {
        match SalesforceError::Forbidden.to_fcp_error() {
            FcpError::External { message, .. } => {
                assert_eq!(message, "Insufficient permissions");
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    // -- InvalidInput --

    #[test]
    fn invalid_input_not_retryable() {
        assert!(!SalesforceError::InvalidInput("bad".into()).is_retryable());
    }

    #[test]
    fn invalid_input_retry_after_none() {
        assert_eq!(
            SalesforceError::InvalidInput("bad".into()).retry_after(),
            None
        );
    }

    #[test]
    fn invalid_input_to_fcp_invalid_request() {
        match SalesforceError::InvalidInput("path traversal".into()).to_fcp_error() {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1005);
                assert!(message.contains("Invalid input"));
                assert!(message.contains("path traversal"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn invalid_input_display() {
        assert_eq!(
            SalesforceError::InvalidInput("bad id".into()).to_string(),
            "Invalid input: bad id"
        );
    }
}
