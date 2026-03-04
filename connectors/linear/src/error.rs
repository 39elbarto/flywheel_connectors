//! Linear-specific error types.

use std::time::Duration;

use fcp_core::FcpError;
use thiserror::Error;

/// Linear-specific errors.
#[derive(Error, Debug)]
pub enum LinearError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Linear GraphQL API returned errors
    #[error("Linear API error: {message}")]
    Api {
        message: String,
        status_code: Option<u16>,
    },

    /// Rate limited
    #[error("Rate limited, retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },

    /// Invalid or expired token
    #[error("Invalid or expired Linear API key")]
    Unauthorized,

    /// Resource not found
    #[error("Resource not found: {resource}")]
    NotFound { resource: String },
}

impl LinearError {
    /// Check if this error is retryable.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) => true,
            Self::RateLimited { .. } => true,
            Self::Api { status_code, .. } => matches!(status_code, Some(500..=599 | 429)),
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
                service: "linear".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Api {
                message,
                status_code,
            } => {
                if *status_code == Some(401) || *status_code == Some(403) {
                    FcpError::Unauthorized {
                        code: 2001,
                        message: "Invalid or insufficient Linear API key".into(),
                    }
                } else if *status_code == Some(429) {
                    FcpError::RateLimited {
                        retry_after_ms: 60_000,
                        violation: None,
                    }
                } else {
                    FcpError::External {
                        service: "linear".into(),
                        message: message.clone(),
                        status_code: *status_code,
                        retryable: self.is_retryable(),
                        retry_after: self.retry_after(),
                    }
                }
            }
            Self::RateLimited { retry_after_ms } => FcpError::RateLimited {
                retry_after_ms: *retry_after_ms,
                violation: None,
            },
            Self::Unauthorized => FcpError::Unauthorized {
                code: 2001,
                message: "Invalid or expired Linear API key".into(),
            },
            Self::NotFound { resource } => FcpError::ResourceNotFound {
                resource: resource.clone(),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
        }
    }
}

/// Result type for Linear operations.
pub type LinearResult<T> = Result<T, LinearError>;

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Display ----

    #[test]
    fn display_api_error() {
        let err = LinearError::Api {
            message: "Entity not found".into(),
            status_code: Some(404),
        };
        assert!(err.to_string().contains("Entity not found"));
    }

    #[test]
    fn display_rate_limited() {
        let err = LinearError::RateLimited {
            retry_after_ms: 5000,
        };
        assert!(err.to_string().contains("5000ms"));
    }

    #[test]
    fn display_unauthorized() {
        assert!(LinearError::Unauthorized
            .to_string()
            .contains("Linear API key"));
    }

    #[test]
    fn display_not_found() {
        let err = LinearError::NotFound {
            resource: "issue:abc".into(),
        };
        assert!(err.to_string().contains("issue:abc"));
    }

    // ---- is_retryable ----

    #[test]
    fn is_retryable_rate_limited() {
        assert!(LinearError::RateLimited {
            retry_after_ms: 1000
        }
        .is_retryable());
    }

    #[test]
    fn is_retryable_api_500() {
        assert!(LinearError::Api {
            message: "internal".into(),
            status_code: Some(500),
        }
        .is_retryable());
    }

    #[test]
    fn not_retryable_api_400() {
        assert!(!LinearError::Api {
            message: "bad".into(),
            status_code: Some(400),
        }
        .is_retryable());
    }

    #[test]
    fn not_retryable_unauthorized() {
        assert!(!LinearError::Unauthorized.is_retryable());
    }

    #[test]
    fn not_retryable_not_found() {
        assert!(!LinearError::NotFound {
            resource: "x".into()
        }
        .is_retryable());
    }

    #[test]
    fn not_retryable_json() {
        let json_err = serde_json::from_str::<serde_json::Value>("x").unwrap_err();
        assert!(!LinearError::Json(json_err).is_retryable());
    }

    // ---- retry_after ----

    #[test]
    fn retry_after_rate_limited() {
        let err = LinearError::RateLimited {
            retry_after_ms: 5000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn retry_after_other_none() {
        assert_eq!(LinearError::Unauthorized.retry_after(), None);
    }

    // ---- to_fcp_error ----

    #[test]
    fn to_fcp_error_api_401() {
        let err = LinearError::Api {
            message: "unauthorized".into(),
            status_code: Some(401),
        };
        assert!(matches!(err.to_fcp_error(), FcpError::Unauthorized { .. }));
    }

    #[test]
    fn to_fcp_error_api_403() {
        let err = LinearError::Api {
            message: "forbidden".into(),
            status_code: Some(403),
        };
        assert!(matches!(err.to_fcp_error(), FcpError::Unauthorized { .. }));
    }

    #[test]
    fn to_fcp_error_api_429() {
        let err = LinearError::Api {
            message: "rate limited".into(),
            status_code: Some(429),
        };
        match err.to_fcp_error() {
            FcpError::RateLimited {
                retry_after_ms, ..
            } => assert_eq!(retry_after_ms, 60_000),
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_500_external() {
        let err = LinearError::Api {
            message: "server error".into(),
            status_code: Some(500),
        };
        match err.to_fcp_error() {
            FcpError::External {
                service, retryable, ..
            } => {
                assert_eq!(service, "linear");
                assert!(retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_rate_limited() {
        let err = LinearError::RateLimited {
            retry_after_ms: 2000,
        };
        match err.to_fcp_error() {
            FcpError::RateLimited {
                retry_after_ms, ..
            } => assert_eq!(retry_after_ms, 2000),
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_unauthorized() {
        match LinearError::Unauthorized.to_fcp_error() {
            FcpError::Unauthorized { code, .. } => assert_eq!(code, 2001),
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_not_found() {
        let err = LinearError::NotFound {
            resource: "issue:abc".into(),
        };
        match err.to_fcp_error() {
            FcpError::ResourceNotFound { resource } => assert_eq!(resource, "issue:abc"),
            other => panic!("expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_json_internal() {
        let json_err = serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err();
        let err = LinearError::Json(json_err);
        assert!(matches!(err.to_fcp_error(), FcpError::Internal { .. }));
    }

    // ---- From / Result / trait ----

    #[test]
    fn from_serde_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("nope").unwrap_err();
        let err: LinearError = json_err.into();
        assert!(matches!(err, LinearError::Json(_)));
    }

    #[test]
    fn linear_result_ok() {
        let r: LinearResult<u32> = Ok(42);
        assert!(r.is_ok());
    }

    #[test]
    fn error_trait_impl() {
        let _: &dyn std::error::Error = &LinearError::Unauthorized;
    }
}
