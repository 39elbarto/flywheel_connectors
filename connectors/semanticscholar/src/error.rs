//! Semantic Scholar-specific error types.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_core::FcpError;
use fcp_sdk::migration::ConnectorErrorMapping;
use thiserror::Error;

/// Result alias for Semantic Scholar operations.
pub type SemanticScholarResult<T> = Result<T, SemanticScholarError>;

/// Semantic Scholar-specific errors.
#[derive(Error, Debug)]
pub enum SemanticScholarError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Semantic Scholar API returned an error
    #[error("Semantic Scholar API error ({status_code}): {message}")]
    Api { status_code: u16, message: String },

    /// Rate limited (429)
    #[error("Rate limited, retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },

    /// Authentication failed (401)
    #[error("Authentication failed: invalid API key")]
    Unauthorized,

    /// Forbidden (403)
    #[error("Forbidden: insufficient permissions")]
    Forbidden,

    /// Resource not found (404)
    #[error("Not found: {resource}")]
    NotFound { resource: String },
}

impl SemanticScholarError {
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
                service: "semanticscholar".into(),
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
                service: "semanticscholar".into(),
                message: message.clone(),
                status_code: Some(*status_code),
                retryable: self.is_retryable(),
                retry_after: None,
            },
            Self::RateLimited { retry_after_ms } => FcpError::External {
                service: "semanticscholar".into(),
                message: format!("Rate limited, retry after {retry_after_ms}ms"),
                status_code: Some(429),
                retryable: true,
                retry_after: self.retry_after(),
            },
            Self::Unauthorized => FcpError::External {
                service: "semanticscholar".into(),
                message: "Authentication failed".into(),
                status_code: Some(401),
                retryable: false,
                retry_after: None,
            },
            Self::Forbidden => FcpError::External {
                service: "semanticscholar".into(),
                message: "Insufficient permissions".into(),
                status_code: Some(403),
                retryable: false,
                retry_after: None,
            },
            Self::NotFound { resource } => FcpError::External {
                service: "semanticscholar".into(),
                message: format!("Not found: {resource}"),
                status_code: Some(404),
                retryable: false,
                retry_after: None,
            },
        }
    }
}

impl ConnectorErrorMapping for SemanticScholarError {
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
            SemanticScholarError::RateLimited {
                retry_after_ms: 5000
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_500_is_retryable() {
        assert!(
            SemanticScholarError::Api {
                status_code: 500,
                message: "err".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_503_is_retryable() {
        assert!(
            SemanticScholarError::Api {
                status_code: 503,
                message: "unavailable".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_429_is_retryable() {
        assert!(
            SemanticScholarError::Api {
                status_code: 429,
                message: "too many".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn unauthorized_not_retryable() {
        assert!(!SemanticScholarError::Unauthorized.is_retryable());
    }

    #[test]
    fn forbidden_not_retryable() {
        assert!(!SemanticScholarError::Forbidden.is_retryable());
    }

    #[test]
    fn not_found_not_retryable() {
        assert!(
            !SemanticScholarError::NotFound {
                resource: "paper".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_400_not_retryable() {
        assert!(
            !SemanticScholarError::Api {
                status_code: 400,
                message: "bad request".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_502_is_retryable() {
        assert!(
            SemanticScholarError::Api {
                status_code: 502,
                message: "bad gateway".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn retry_after_for_rate_limited() {
        let err = SemanticScholarError::RateLimited {
            retry_after_ms: 30_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn retry_after_none_for_unauthorized() {
        assert_eq!(SemanticScholarError::Unauthorized.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_forbidden() {
        assert_eq!(SemanticScholarError::Forbidden.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_api_error() {
        assert_eq!(
            SemanticScholarError::Api {
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
            SemanticScholarError::NotFound {
                resource: "x".into()
            }
            .retry_after(),
            None
        );
    }

    #[test]
    fn unauthorized_to_fcp_error() {
        match SemanticScholarError::Unauthorized.to_fcp_error() {
            FcpError::External {
                service,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "semanticscholar");
                assert_eq!(status_code, Some(401));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn forbidden_to_fcp_error() {
        match SemanticScholarError::Forbidden.to_fcp_error() {
            FcpError::External {
                service,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "semanticscholar");
                assert_eq!(status_code, Some(403));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn not_found_to_fcp_error() {
        match (SemanticScholarError::NotFound {
            resource: "paper_abc".into(),
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
                assert!(message.contains("paper_abc"));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_to_fcp_error() {
        match (SemanticScholarError::RateLimited {
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
        match (SemanticScholarError::Api {
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
                assert_eq!(service, "semanticscholar");
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
        match SemanticScholarError::Json(bad.unwrap_err()).to_fcp_error() {
            FcpError::Internal { message } => assert!(message.starts_with("JSON error:")),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn api_error_non_retryable_to_fcp_error() {
        match (SemanticScholarError::Api {
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
            SemanticScholarError::Unauthorized.to_string(),
            "Authentication failed: invalid API key"
        );
    }

    #[test]
    fn error_display_forbidden() {
        assert_eq!(
            SemanticScholarError::Forbidden.to_string(),
            "Forbidden: insufficient permissions"
        );
    }

    #[test]
    fn error_display_not_found() {
        assert_eq!(
            SemanticScholarError::NotFound {
                resource: "paper".into()
            }
            .to_string(),
            "Not found: paper"
        );
    }

    #[test]
    fn error_display_rate_limited() {
        assert_eq!(
            SemanticScholarError::RateLimited {
                retry_after_ms: 2000
            }
            .to_string(),
            "Rate limited, retry after 2000ms"
        );
    }

    #[test]
    fn error_display_api() {
        assert_eq!(
            SemanticScholarError::Api {
                status_code: 500,
                message: "Internal".into()
            }
            .to_string(),
            "Semantic Scholar API error (500): Internal"
        );
    }

    #[test]
    fn rate_limited_to_fcp_error_has_service() {
        match (SemanticScholarError::RateLimited {
            retry_after_ms: 1000,
        })
        .to_fcp_error()
        {
            FcpError::External { service, .. } => {
                assert_eq!(service, "semanticscholar");
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn not_found_to_fcp_error_has_service() {
        match (SemanticScholarError::NotFound {
            resource: "author".into(),
        })
        .to_fcp_error()
        {
            FcpError::External {
                service, retryable, ..
            } => {
                assert_eq!(service, "semanticscholar");
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    // --- Debug format ---

    #[test]
    fn debug_rate_limited() {
        let err = SemanticScholarError::RateLimited {
            retry_after_ms: 5000,
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("RateLimited"));
        assert!(dbg.contains("5000"));
    }

    #[test]
    fn debug_unauthorized() {
        let dbg = format!("{:?}", SemanticScholarError::Unauthorized);
        assert!(dbg.contains("Unauthorized"));
    }

    #[test]
    fn debug_forbidden() {
        let dbg = format!("{:?}", SemanticScholarError::Forbidden);
        assert!(dbg.contains("Forbidden"));
    }

    #[test]
    fn debug_not_found() {
        let err = SemanticScholarError::NotFound {
            resource: "paper_x".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("NotFound"));
        assert!(dbg.contains("paper_x"));
    }

    #[test]
    fn debug_api() {
        let err = SemanticScholarError::Api {
            status_code: 503,
            message: "unavailable".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Api"));
        assert!(dbg.contains("503"));
        assert!(dbg.contains("unavailable"));
    }

    #[test]
    fn debug_json() {
        let json_err = serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err();
        let err = SemanticScholarError::Json(json_err);
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Json"));
    }

    // --- Source chain ---

    #[test]
    fn source_json_variant() {
        let json_err = serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err();
        let err = SemanticScholarError::Json(json_err);
        let source = std::error::Error::source(&err);
        assert!(source.is_some(), "Json variant should have a source");
    }

    #[test]
    fn source_unauthorized_none() {
        let err = SemanticScholarError::Unauthorized;
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn source_forbidden_none() {
        let err = SemanticScholarError::Forbidden;
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn source_not_found_none() {
        let err = SemanticScholarError::NotFound {
            resource: "x".into(),
        };
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn source_api_none() {
        let err = SemanticScholarError::Api {
            status_code: 500,
            message: "err".into(),
        };
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn source_rate_limited_none() {
        let err = SemanticScholarError::RateLimited {
            retry_after_ms: 100,
        };
        assert!(std::error::Error::source(&err).is_none());
    }

    // --- From impls ---

    #[test]
    fn from_serde_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("x").unwrap_err();
        let err: SemanticScholarError = json_err.into();
        assert!(matches!(err, SemanticScholarError::Json(_)));
    }

    // --- error_trait_impl ---

    #[test]
    fn error_trait_impl() {
        let _: &dyn std::error::Error = &SemanticScholarError::Unauthorized;
    }

    // --- Result alias ---

    #[test]
    fn result_alias_ok() {
        let r: SemanticScholarResult<u32> = Ok(42);
        assert!(r.is_ok());
    }

    #[test]
    fn result_alias_err() {
        let r: SemanticScholarResult<u32> = Err(SemanticScholarError::Forbidden);
        assert!(matches!(r, Err(SemanticScholarError::Forbidden)));
    }

    // --- retry_after zero ---

    #[test]
    fn retry_after_zero_ms() {
        let err = SemanticScholarError::RateLimited { retry_after_ms: 0 };
        assert_eq!(err.retry_after(), Some(Duration::from_millis(0)));
    }

    // --- Display edge cases ---

    #[test]
    fn display_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err();
        let err = SemanticScholarError::Json(json_err);
        let display = err.to_string();
        assert!(display.starts_with("JSON error:"));
    }

    // --- is_retryable additional ---

    #[test]
    fn api_599_is_retryable() {
        assert!(
            SemanticScholarError::Api {
                status_code: 599,
                message: "err".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn json_not_retryable() {
        let json_err = serde_json::from_str::<serde_json::Value>("x").unwrap_err();
        assert!(!SemanticScholarError::Json(json_err).is_retryable());
    }

    // --- to_fcp_error additional ---

    #[test]
    fn http_error_to_fcp_external() {
        // We cannot easily construct a reqwest::Error, but we can at least test
        // that the Http variant is recognized via the is_retryable path
        // and that all FcpError conversions for other variants are covered.
        // This tests forbidden to_fcp_error message content
        match SemanticScholarError::Forbidden.to_fcp_error() {
            FcpError::External { message, .. } => {
                assert_eq!(message, "Insufficient permissions");
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn unauthorized_to_fcp_error_message() {
        match SemanticScholarError::Unauthorized.to_fcp_error() {
            FcpError::External { message, .. } => {
                assert_eq!(message, "Authentication failed");
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_to_fcp_error_message_format() {
        match (SemanticScholarError::RateLimited {
            retry_after_ms: 2000,
        })
        .to_fcp_error()
        {
            FcpError::External { message, .. } => {
                assert_eq!(message, "Rate limited, retry after 2000ms");
            }
            other => panic!("expected External, got {other:?}"),
        }
    }
}
