//! Asana-specific error types.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_core::FcpError;
use fcp_sdk::migration::ConnectorErrorMapping;
use thiserror::Error;

/// Result alias for Asana operations.
pub type AsanaResult<T> = Result<T, AsanaError>;

/// Asana-specific errors.
#[derive(Error, Debug)]
pub enum AsanaError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Asana API returned an error
    #[error("Asana API error ({status_code}): {message}")]
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

    /// Invalid input (missing field, path traversal, etc.).
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

impl AsanaError {
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
                service: "asana".into(),
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
                service: "asana".into(),
                message: message.clone(),
                status_code: Some(*status_code),
                retryable: self.is_retryable(),
                retry_after: None,
            },
            Self::RateLimited { retry_after_ms } => FcpError::RateLimited {
                retry_after_ms: *retry_after_ms,
                violation: None,
            },
            Self::Unauthorized => FcpError::Unauthorized {
                code: 2001,
                message: "Authentication failed: invalid or expired access token".into(),
            },
            Self::Forbidden => FcpError::External {
                service: "asana".into(),
                message: "Insufficient permissions".into(),
                status_code: Some(403),
                retryable: false,
                retry_after: None,
            },
            Self::NotFound { resource } => FcpError::ResourceNotFound {
                resource: resource.clone(),
            },
            Self::InvalidInput(msg) => FcpError::InvalidRequest {
                code: 1005,
                message: format!("Invalid input: {msg}"),
            },
        }
    }
}

impl ConnectorErrorMapping for AsanaError {
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
            AsanaError::RateLimited {
                retry_after_ms: 5000
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_500_is_retryable() {
        assert!(
            AsanaError::Api {
                status_code: 500,
                message: "err".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_503_is_retryable() {
        assert!(
            AsanaError::Api {
                status_code: 503,
                message: "unavailable".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_429_is_retryable() {
        assert!(
            AsanaError::Api {
                status_code: 429,
                message: "too many".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn unauthorized_not_retryable() {
        assert!(!AsanaError::Unauthorized.is_retryable());
    }

    #[test]
    fn forbidden_not_retryable() {
        assert!(!AsanaError::Forbidden.is_retryable());
    }

    #[test]
    fn not_found_not_retryable() {
        assert!(
            !AsanaError::NotFound {
                resource: "task".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_400_not_retryable() {
        assert!(
            !AsanaError::Api {
                status_code: 400,
                message: "bad request".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn retry_after_for_rate_limited() {
        let err = AsanaError::RateLimited {
            retry_after_ms: 30_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn retry_after_none_for_unauthorized() {
        assert_eq!(AsanaError::Unauthorized.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_forbidden() {
        assert_eq!(AsanaError::Forbidden.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_api_error() {
        assert_eq!(
            AsanaError::Api {
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
            AsanaError::NotFound {
                resource: "x".into()
            }
            .retry_after(),
            None
        );
    }

    #[test]
    fn unauthorized_to_fcp_error() {
        match AsanaError::Unauthorized.to_fcp_error() {
            FcpError::Unauthorized { code, message } => {
                assert_eq!(code, 2001);
                assert!(message.contains("Authentication failed"));
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn forbidden_to_fcp_error() {
        match AsanaError::Forbidden.to_fcp_error() {
            FcpError::External {
                service,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "asana");
                assert_eq!(status_code, Some(403));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn not_found_to_fcp_error() {
        match (AsanaError::NotFound {
            resource: "task_abc".into(),
        })
        .to_fcp_error()
        {
            FcpError::ResourceNotFound { resource } => {
                assert_eq!(resource, "task_abc");
            }
            other => panic!("expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_to_fcp_error() {
        match (AsanaError::RateLimited {
            retry_after_ms: 60_000,
        })
        .to_fcp_error()
        {
            FcpError::RateLimited {
                retry_after_ms,
                violation,
            } => {
                assert_eq!(retry_after_ms, 60_000);
                assert!(violation.is_none());
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn api_error_to_fcp_error() {
        match (AsanaError::Api {
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
                assert_eq!(service, "asana");
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
        match AsanaError::Json(bad.unwrap_err()).to_fcp_error() {
            FcpError::Internal { message } => assert!(message.starts_with("JSON error:")),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn api_error_non_retryable_to_fcp_error() {
        match (AsanaError::Api {
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
            AsanaError::Unauthorized.to_string(),
            "Authentication failed: invalid or expired access token"
        );
    }

    #[test]
    fn error_display_forbidden() {
        assert_eq!(
            AsanaError::Forbidden.to_string(),
            "Forbidden: insufficient permissions"
        );
    }

    #[test]
    fn error_display_not_found() {
        assert_eq!(
            AsanaError::NotFound {
                resource: "task".into()
            }
            .to_string(),
            "Not found: task"
        );
    }

    #[test]
    fn error_display_rate_limited() {
        assert_eq!(
            AsanaError::RateLimited {
                retry_after_ms: 2000
            }
            .to_string(),
            "Rate limited, retry after 2000ms"
        );
    }

    #[test]
    fn error_display_api() {
        assert_eq!(
            AsanaError::Api {
                status_code: 500,
                message: "Internal".into()
            }
            .to_string(),
            "Asana API error (500): Internal"
        );
    }

    // ── Additional error coverage ────────────────────────────────

    #[test]
    fn api_502_is_retryable() {
        assert!(
            AsanaError::Api {
                status_code: 502,
                message: "bad gateway".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_504_is_retryable() {
        assert!(
            AsanaError::Api {
                status_code: 504,
                message: "gateway timeout".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_599_is_retryable() {
        assert!(
            AsanaError::Api {
                status_code: 599,
                message: "server error".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_404_not_retryable() {
        assert!(
            !AsanaError::Api {
                status_code: 404,
                message: "not found".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_401_not_retryable() {
        assert!(
            !AsanaError::Api {
                status_code: 401,
                message: "unauthorized".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_403_not_retryable() {
        assert!(
            !AsanaError::Api {
                status_code: 403,
                message: "forbidden".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn json_error_not_retryable() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("bad");
        assert!(!AsanaError::Json(bad.unwrap_err()).is_retryable());
    }

    #[test]
    fn retry_after_zero_ms() {
        let err = AsanaError::RateLimited { retry_after_ms: 0 };
        assert_eq!(err.retry_after(), Some(Duration::from_millis(0)));
    }

    #[test]
    fn retry_after_large_value() {
        let err = AsanaError::RateLimited {
            retry_after_ms: 120_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(120)));
    }

    #[test]
    fn retry_after_none_for_json_error() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("bad");
        assert_eq!(AsanaError::Json(bad.unwrap_err()).retry_after(), None);
    }

    #[test]
    fn rate_limited_to_fcp_error_has_retry_after() {
        match (AsanaError::RateLimited {
            retry_after_ms: 5000,
        })
        .to_fcp_error()
        {
            FcpError::RateLimited {
                retry_after_ms,
                violation,
            } => {
                assert_eq!(retry_after_ms, 5000);
                assert!(violation.is_none());
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn api_error_to_fcp_error_no_retry_after() {
        match (AsanaError::Api {
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

    #[test]
    fn unauthorized_fcp_error_message() {
        match AsanaError::Unauthorized.to_fcp_error() {
            FcpError::Unauthorized { code, message } => {
                assert_eq!(code, 2001);
                assert!(message.contains("Authentication failed"));
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn forbidden_fcp_error_message() {
        match AsanaError::Forbidden.to_fcp_error() {
            FcpError::External { message, .. } => {
                assert_eq!(message, "Insufficient permissions");
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn not_found_fcp_error_is_resource_not_found() {
        match (AsanaError::NotFound {
            resource: "project_xyz".into(),
        })
        .to_fcp_error()
        {
            FcpError::ResourceNotFound { resource } => {
                assert_eq!(resource, "project_xyz");
            }
            other => panic!("expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn debug_format_all_variants() {
        let variants: Vec<AsanaError> = vec![
            AsanaError::Unauthorized,
            AsanaError::Forbidden,
            AsanaError::NotFound {
                resource: "x".into(),
            },
            AsanaError::RateLimited {
                retry_after_ms: 1000,
            },
            AsanaError::Api {
                status_code: 500,
                message: "err".into(),
            },
        ];
        for v in &variants {
            let dbg = format!("{v:?}");
            assert!(!dbg.is_empty());
        }
    }

    #[test]
    fn error_implements_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(AsanaError::Unauthorized);
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn json_error_source_chain() {
        let json_err = serde_json::from_str::<i32>("bad").unwrap_err();
        let err = AsanaError::Json(json_err);
        let dyn_err: &dyn std::error::Error = &err;
        assert!(dyn_err.source().is_some());
    }

    #[test]
    fn result_type_alias_ok() {
        let ok: AsanaResult<i32> = Ok(42);
        assert!(matches!(ok, Ok(42)));
    }

    #[test]
    fn result_type_alias_err() {
        let err: AsanaResult<i32> = Err(AsanaError::Unauthorized);
        assert!(err.is_err());
    }

    #[test]
    fn error_display_http() {
        let req_err = reqwest::Client::builder()
            .build()
            .unwrap()
            .get("://invalid")
            .build();
        if let Err(e) = req_err {
            let ae = AsanaError::Http(e);
            assert!(ae.to_string().starts_with("HTTP error:"));
        }
    }

    #[test]
    fn error_display_json() {
        let json_err = serde_json::from_str::<i32>("bad").unwrap_err();
        let ae = AsanaError::Json(json_err);
        assert!(ae.to_string().starts_with("JSON error:"));
    }

    #[test]
    fn http_error_is_retryable() {
        let req_err = reqwest::Client::builder()
            .build()
            .unwrap()
            .get("://invalid")
            .build();
        if let Err(e) = req_err {
            let ae = AsanaError::Http(e);
            assert!(ae.is_retryable());
        }
    }
}
