//! `1Password`-specific error types.

use std::time::Duration;

use fcp_core::FcpError;
use thiserror::Error;

/// Result alias for `1Password` operations.
pub type OnePasswordResult<T> = Result<T, OnePasswordError>;

/// `1Password`-specific errors.
#[derive(Error, Debug)]
pub enum OnePasswordError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// `1Password` API returned an error
    #[error("1Password API error ({status_code}): {message}")]
    Api { status_code: u16, message: String },

    /// Rate limited (429)
    #[error("Rate limited, retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },

    /// Authentication failed (401)
    #[error("Authentication failed: invalid or expired service account token")]
    Unauthorized,

    /// Forbidden (403)
    #[error("Forbidden: insufficient permissions for this vault or item")]
    Forbidden,

    /// Resource not found (404)
    #[error("Not found: {resource}")]
    NotFound { resource: String },
}

impl OnePasswordError {
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
                service: "1password".into(),
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
                service: "1password".into(),
                message: message.clone(),
                status_code: Some(*status_code),
                retryable: self.is_retryable(),
                retry_after: None,
            },
            Self::RateLimited { retry_after_ms } => FcpError::External {
                service: "1password".into(),
                message: format!("Rate limited, retry after {retry_after_ms}ms"),
                status_code: Some(429),
                retryable: true,
                retry_after: self.retry_after(),
            },
            Self::Unauthorized => FcpError::External {
                service: "1password".into(),
                message: "Authentication failed".into(),
                status_code: Some(401),
                retryable: false,
                retry_after: None,
            },
            Self::Forbidden => FcpError::External {
                service: "1password".into(),
                message: "Insufficient permissions".into(),
                status_code: Some(403),
                retryable: false,
                retry_after: None,
            },
            Self::NotFound { resource } => FcpError::External {
                service: "1password".into(),
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
        assert!(
            OnePasswordError::RateLimited {
                retry_after_ms: 5000
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_500_is_retryable() {
        assert!(
            OnePasswordError::Api {
                status_code: 500,
                message: "err".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_503_is_retryable() {
        assert!(
            OnePasswordError::Api {
                status_code: 503,
                message: "unavailable".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_429_is_retryable() {
        assert!(
            OnePasswordError::Api {
                status_code: 429,
                message: "too many".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn unauthorized_not_retryable() {
        assert!(!OnePasswordError::Unauthorized.is_retryable());
    }

    #[test]
    fn forbidden_not_retryable() {
        assert!(!OnePasswordError::Forbidden.is_retryable());
    }

    #[test]
    fn not_found_not_retryable() {
        assert!(
            !OnePasswordError::NotFound {
                resource: "vault".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_400_not_retryable() {
        assert!(
            !OnePasswordError::Api {
                status_code: 400,
                message: "bad request".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn retry_after_for_rate_limited() {
        let err = OnePasswordError::RateLimited {
            retry_after_ms: 30_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn retry_after_none_for_unauthorized() {
        assert_eq!(OnePasswordError::Unauthorized.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_forbidden() {
        assert_eq!(OnePasswordError::Forbidden.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_api_error() {
        assert_eq!(
            OnePasswordError::Api {
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
            OnePasswordError::NotFound {
                resource: "x".into()
            }
            .retry_after(),
            None
        );
    }

    #[test]
    fn unauthorized_to_fcp_error() {
        match OnePasswordError::Unauthorized.to_fcp_error() {
            FcpError::External {
                service,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "1password");
                assert_eq!(status_code, Some(401));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn forbidden_to_fcp_error() {
        match OnePasswordError::Forbidden.to_fcp_error() {
            FcpError::External {
                service,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "1password");
                assert_eq!(status_code, Some(403));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn not_found_to_fcp_error() {
        match (OnePasswordError::NotFound {
            resource: "vault_abc".into(),
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
                assert!(message.contains("vault_abc"));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_to_fcp_error() {
        match (OnePasswordError::RateLimited {
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
        match (OnePasswordError::Api {
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
                assert_eq!(service, "1password");
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
        match OnePasswordError::Json(bad.unwrap_err()).to_fcp_error() {
            FcpError::Internal { message } => assert!(message.starts_with("JSON error:")),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn api_error_non_retryable_to_fcp_error() {
        match (OnePasswordError::Api {
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
            OnePasswordError::Unauthorized.to_string(),
            "Authentication failed: invalid or expired service account token"
        );
    }

    #[test]
    fn error_display_forbidden() {
        assert_eq!(
            OnePasswordError::Forbidden.to_string(),
            "Forbidden: insufficient permissions for this vault or item"
        );
    }

    #[test]
    fn error_display_not_found() {
        assert_eq!(
            OnePasswordError::NotFound {
                resource: "item".into()
            }
            .to_string(),
            "Not found: item"
        );
    }

    #[test]
    fn error_display_rate_limited() {
        assert_eq!(
            OnePasswordError::RateLimited {
                retry_after_ms: 2000
            }
            .to_string(),
            "Rate limited, retry after 2000ms"
        );
    }

    #[test]
    fn error_display_api() {
        assert_eq!(
            OnePasswordError::Api {
                status_code: 500,
                message: "Internal".into()
            }
            .to_string(),
            "1Password API error (500): Internal"
        );
    }

    #[test]
    fn error_display_http() {
        let err = reqwest::Client::new().get("://bad").build().unwrap_err();
        let op_err = OnePasswordError::Http(err);
        assert!(op_err.to_string().starts_with("HTTP error:"));
    }

    #[test]
    fn error_display_json() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{invalid");
        let err = OnePasswordError::Json(bad.unwrap_err());
        assert!(err.to_string().starts_with("JSON error:"));
    }

    #[test]
    fn error_debug_contains_variant_name() {
        let err = OnePasswordError::Unauthorized;
        assert!(format!("{err:?}").contains("Unauthorized"));
    }

    #[test]
    fn error_debug_api_contains_fields() {
        let err = OnePasswordError::Api {
            status_code: 422,
            message: "Unprocessable".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("422"));
        assert!(dbg.contains("Unprocessable"));
    }

    #[test]
    fn api_502_is_retryable() {
        assert!(
            OnePasswordError::Api {
                status_code: 502,
                message: "bad gateway".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_504_is_retryable() {
        assert!(
            OnePasswordError::Api {
                status_code: 504,
                message: "timeout".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_422_not_retryable() {
        assert!(
            !OnePasswordError::Api {
                status_code: 422,
                message: "unprocessable".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn json_not_retryable() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{bad");
        assert!(!OnePasswordError::Json(bad.unwrap_err()).is_retryable());
    }

    #[test]
    fn retry_after_none_for_json_error() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{bad");
        assert_eq!(OnePasswordError::Json(bad.unwrap_err()).retry_after(), None);
    }

    #[test]
    fn rate_limited_retry_after_zero() {
        let err = OnePasswordError::RateLimited { retry_after_ms: 0 };
        assert_eq!(err.retry_after(), Some(Duration::from_millis(0)));
    }

    #[test]
    fn rate_limited_retry_after_large_value() {
        let err = OnePasswordError::RateLimited {
            retry_after_ms: 300_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(300)));
    }

    #[test]
    fn api_error_to_fcp_has_no_retry_after() {
        match (OnePasswordError::Api {
            status_code: 500,
            message: "err".into(),
        })
        .to_fcp_error()
        {
            FcpError::External { retry_after, .. } => {
                assert_eq!(retry_after, None);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_to_fcp_error_message_contains_ms() {
        match (OnePasswordError::RateLimited {
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
    fn not_found_to_fcp_error_has_no_retry_after() {
        match (OnePasswordError::NotFound {
            resource: "x".into(),
        })
        .to_fcp_error()
        {
            FcpError::External { retry_after, .. } => {
                assert_eq!(retry_after, None);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn unauthorized_to_fcp_error_has_no_retry_after() {
        match OnePasswordError::Unauthorized.to_fcp_error() {
            FcpError::External { retry_after, .. } => {
                assert_eq!(retry_after, None);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn forbidden_to_fcp_error_has_no_retry_after() {
        match OnePasswordError::Forbidden.to_fcp_error() {
            FcpError::External { retry_after, .. } => {
                assert_eq!(retry_after, None);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }
}
