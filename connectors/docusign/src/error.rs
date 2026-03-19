//! `DocuSign`-specific error types.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_core::FcpError;
use fcp_sdk::migration::ConnectorErrorMapping;
use thiserror::Error;

/// Result alias for `DocuSign` operations.
pub type DocuSignResult<T> = Result<T, DocuSignError>;

/// `DocuSign`-specific errors.
#[derive(Error, Debug)]
pub enum DocuSignError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// `DocuSign` API returned an error
    #[error("DocuSign API error ({status_code}): {message}")]
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

    /// Envelope cannot be modified (already sent/completed/voided)
    #[error("Envelope not modifiable: {reason}")]
    EnvelopeNotModifiable { reason: String },
}

impl DocuSignError {
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
                service: "docusign".into(),
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
                service: "docusign".into(),
                message: message.clone(),
                status_code: Some(*status_code),
                retryable: self.is_retryable(),
                retry_after: None,
            },
            Self::RateLimited { retry_after_ms } => FcpError::External {
                service: "docusign".into(),
                message: format!("Rate limited, retry after {retry_after_ms}ms"),
                status_code: Some(429),
                retryable: true,
                retry_after: self.retry_after(),
            },
            Self::Unauthorized => FcpError::External {
                service: "docusign".into(),
                message: "Authentication failed".into(),
                status_code: Some(401),
                retryable: false,
                retry_after: None,
            },
            Self::Forbidden => FcpError::External {
                service: "docusign".into(),
                message: "Insufficient permissions".into(),
                status_code: Some(403),
                retryable: false,
                retry_after: None,
            },
            Self::NotFound { resource } => FcpError::External {
                service: "docusign".into(),
                message: format!("Not found: {resource}"),
                status_code: Some(404),
                retryable: false,
                retry_after: None,
            },
            Self::EnvelopeNotModifiable { reason } => FcpError::External {
                service: "docusign".into(),
                message: format!("Envelope not modifiable: {reason}"),
                status_code: Some(400),
                retryable: false,
                retry_after: None,
            },
        }
    }
}

impl ConnectorErrorMapping for DocuSignError {
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
            DocuSignError::RateLimited {
                retry_after_ms: 5000
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_500_is_retryable() {
        assert!(
            DocuSignError::Api {
                status_code: 500,
                message: "err".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_503_is_retryable() {
        assert!(
            DocuSignError::Api {
                status_code: 503,
                message: "unavailable".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_429_is_retryable() {
        assert!(
            DocuSignError::Api {
                status_code: 429,
                message: "too many".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn unauthorized_not_retryable() {
        assert!(!DocuSignError::Unauthorized.is_retryable());
    }

    #[test]
    fn forbidden_not_retryable() {
        assert!(!DocuSignError::Forbidden.is_retryable());
    }

    #[test]
    fn not_found_not_retryable() {
        assert!(
            !DocuSignError::NotFound {
                resource: "envelope".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn envelope_not_modifiable_not_retryable() {
        assert!(
            !DocuSignError::EnvelopeNotModifiable {
                reason: "already sent".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_400_not_retryable() {
        assert!(
            !DocuSignError::Api {
                status_code: 400,
                message: "bad request".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn retry_after_for_rate_limited() {
        let err = DocuSignError::RateLimited {
            retry_after_ms: 30_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn retry_after_none_for_unauthorized() {
        assert_eq!(DocuSignError::Unauthorized.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_forbidden() {
        assert_eq!(DocuSignError::Forbidden.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_api_error() {
        assert_eq!(
            DocuSignError::Api {
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
            DocuSignError::NotFound {
                resource: "x".into()
            }
            .retry_after(),
            None
        );
    }

    #[test]
    fn retry_after_none_for_envelope_not_modifiable() {
        assert_eq!(
            DocuSignError::EnvelopeNotModifiable {
                reason: "completed".into()
            }
            .retry_after(),
            None
        );
    }

    #[test]
    fn unauthorized_to_fcp_error() {
        match DocuSignError::Unauthorized.to_fcp_error() {
            FcpError::External {
                service,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "docusign");
                assert_eq!(status_code, Some(401));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn forbidden_to_fcp_error() {
        match DocuSignError::Forbidden.to_fcp_error() {
            FcpError::External {
                service,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "docusign");
                assert_eq!(status_code, Some(403));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn not_found_to_fcp_error() {
        match (DocuSignError::NotFound {
            resource: "env_abc".into(),
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
                assert!(message.contains("env_abc"));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_to_fcp_error() {
        match (DocuSignError::RateLimited {
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
        match (DocuSignError::Api {
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
                assert_eq!(service, "docusign");
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
        match DocuSignError::Json(bad.unwrap_err()).to_fcp_error() {
            FcpError::Internal { message } => assert!(message.starts_with("JSON error:")),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn api_error_non_retryable_to_fcp_error() {
        match (DocuSignError::Api {
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
    fn envelope_not_modifiable_to_fcp_error() {
        match (DocuSignError::EnvelopeNotModifiable {
            reason: "already completed".into(),
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
                assert_eq!(service, "docusign");
                assert_eq!(status_code, Some(400));
                assert!(message.contains("already completed"));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn error_display_unauthorized() {
        assert_eq!(
            DocuSignError::Unauthorized.to_string(),
            "Authentication failed: invalid or expired access token"
        );
    }

    #[test]
    fn error_display_forbidden() {
        assert_eq!(
            DocuSignError::Forbidden.to_string(),
            "Forbidden: insufficient permissions"
        );
    }

    #[test]
    fn error_display_not_found() {
        assert_eq!(
            DocuSignError::NotFound {
                resource: "envelope".into()
            }
            .to_string(),
            "Not found: envelope"
        );
    }

    #[test]
    fn error_display_rate_limited() {
        assert_eq!(
            DocuSignError::RateLimited {
                retry_after_ms: 2000
            }
            .to_string(),
            "Rate limited, retry after 2000ms"
        );
    }

    #[test]
    fn error_display_api() {
        assert_eq!(
            DocuSignError::Api {
                status_code: 500,
                message: "Internal".into()
            }
            .to_string(),
            "DocuSign API error (500): Internal"
        );
    }

    #[test]
    fn error_display_envelope_not_modifiable() {
        assert_eq!(
            DocuSignError::EnvelopeNotModifiable {
                reason: "already sent".into()
            }
            .to_string(),
            "Envelope not modifiable: already sent"
        );
    }

    #[test]
    fn api_501_is_retryable() {
        assert!(
            DocuSignError::Api {
                status_code: 501,
                message: "not implemented".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_599_is_retryable() {
        assert!(
            DocuSignError::Api {
                status_code: 599,
                message: "edge".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_499_not_retryable() {
        assert!(
            !DocuSignError::Api {
                status_code: 499,
                message: "client".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn json_not_retryable() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{bad");
        assert!(!DocuSignError::Json(bad.unwrap_err()).is_retryable());
    }

    #[test]
    fn error_debug_format_api() {
        let err = DocuSignError::Api {
            status_code: 503,
            message: "unavailable".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Api"));
        assert!(dbg.contains("503"));
    }

    #[test]
    fn error_debug_format_unauthorized() {
        let dbg = format!("{:?}", DocuSignError::Unauthorized);
        assert!(dbg.contains("Unauthorized"));
    }

    #[test]
    fn error_debug_format_forbidden() {
        let dbg = format!("{:?}", DocuSignError::Forbidden);
        assert!(dbg.contains("Forbidden"));
    }

    #[test]
    fn error_debug_format_envelope_not_modifiable() {
        let err = DocuSignError::EnvelopeNotModifiable {
            reason: "completed".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("EnvelopeNotModifiable"));
    }

    #[test]
    fn retry_after_zero_ms() {
        let err = DocuSignError::RateLimited { retry_after_ms: 0 };
        assert_eq!(err.retry_after(), Some(Duration::from_millis(0)));
    }

    #[test]
    fn retry_after_large_value() {
        let err = DocuSignError::RateLimited {
            retry_after_ms: 3_600_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(3600)));
    }

    #[test]
    fn api_error_retryable_has_no_retry_after() {
        match (DocuSignError::Api {
            status_code: 500,
            message: "err".into(),
        })
        .to_fcp_error()
        {
            FcpError::External { retry_after, .. } => assert!(retry_after.is_none()),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn error_display_json() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{{");
        let err = DocuSignError::Json(bad.unwrap_err());
        let display = err.to_string();
        assert!(display.starts_with("JSON error:"));
    }

    #[test]
    fn api_502_is_retryable() {
        assert!(
            DocuSignError::Api {
                status_code: 502,
                message: "bad gateway".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_504_is_retryable() {
        assert!(
            DocuSignError::Api {
                status_code: 504,
                message: "gateway timeout".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_422_not_retryable() {
        assert!(
            !DocuSignError::Api {
                status_code: 422,
                message: "unprocessable".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn retry_after_none_for_json_error() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{bad");
        assert_eq!(DocuSignError::Json(bad.unwrap_err()).retry_after(), None);
    }

    #[test]
    fn envelope_not_modifiable_to_fcp_error_message_format() {
        match (DocuSignError::EnvelopeNotModifiable {
            reason: "voided".into(),
        })
        .to_fcp_error()
        {
            FcpError::External { message, .. } => {
                assert!(message.contains("Envelope not modifiable"));
                assert!(message.contains("voided"));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }
}
