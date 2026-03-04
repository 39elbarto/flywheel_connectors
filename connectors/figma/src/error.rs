//! Figma-specific error types.

use std::time::Duration;

use fcp_core::FcpError;
use thiserror::Error;

/// Figma-specific errors.
#[derive(Error, Debug)]
pub enum FigmaError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Figma API returned an error
    #[error("Figma API error: {status} - {message}")]
    Api { status: u16, message: String },

    /// Rate limited
    #[error("Rate limited, retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },

    /// Invalid or expired token
    #[error("Invalid or expired Figma token")]
    Unauthorized,

    /// File not found
    #[error("File not found: {file_key}")]
    FileNotFound { file_key: String },

    /// Comment not found
    #[error("Comment not found: {comment_id}")]
    CommentNotFound { comment_id: String },

    /// Webhook not found
    #[error("Webhook not found: {webhook_id}")]
    WebhookNotFound { webhook_id: String },
}

impl FigmaError {
    /// Check if this error is retryable.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::RateLimited { .. } => true,
            Self::Api { status, message } => {
                // Figma transient errors
                *status == 429
                    || *status >= 500
                    || message.contains("timeout")
                    || message.contains("temporarily unavailable")
            }
            _ => false,
        }
    }

    /// Get the suggested retry delay.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after_secs } => Some(Duration::from_secs(*retry_after_secs)),
            _ => None,
        }
    }

    /// Convert to FCP error.
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Http(e) => FcpError::External {
                service: "figma".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Api { status, message } => {
                if *status == 403 || *status == 401 {
                    FcpError::Unauthorized {
                        code: 2001,
                        message: "Invalid or insufficient Figma token".into(),
                    }
                } else if *status == 429 {
                    FcpError::RateLimited {
                        retry_after_ms: 60_000,
                        violation: None,
                    }
                } else if *status == 404 {
                    FcpError::ResourceNotFound {
                        resource: message.clone(),
                    }
                } else {
                    FcpError::External {
                        service: "figma".into(),
                        message: message.clone(),
                        status_code: Some(*status),
                        retryable: self.is_retryable(),
                        retry_after: self.retry_after(),
                    }
                }
            }
            Self::RateLimited { retry_after_secs } => FcpError::RateLimited {
                retry_after_ms: retry_after_secs * 1000,
                violation: None,
            },
            Self::Unauthorized => FcpError::Unauthorized {
                code: 2001,
                message: "Invalid or expired Figma token".into(),
            },
            Self::FileNotFound { file_key } => FcpError::ResourceNotFound {
                resource: format!("file:{file_key}"),
            },
            Self::CommentNotFound { comment_id } => FcpError::ResourceNotFound {
                resource: format!("comment:{comment_id}"),
            },
            Self::WebhookNotFound { webhook_id } => FcpError::ResourceNotFound {
                resource: format!("webhook:{webhook_id}"),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
        }
    }
}

/// Result type for Figma operations.
pub type FigmaResult<T> = Result<T, FigmaError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_api() {
        let err = FigmaError::Api {
            status: 403,
            message: "forbidden".into(),
        };
        let s = err.to_string();
        assert!(s.contains("403"));
        assert!(s.contains("forbidden"));
    }

    #[test]
    fn display_rate_limited() {
        let err = FigmaError::RateLimited {
            retry_after_secs: 30,
        };
        assert!(err.to_string().contains("30s"));
    }

    #[test]
    fn display_file_not_found() {
        let err = FigmaError::FileNotFound {
            file_key: "abc123".into(),
        };
        assert!(err.to_string().contains("abc123"));
    }

    #[test]
    fn display_comment_not_found() {
        let err = FigmaError::CommentNotFound {
            comment_id: "c_1".into(),
        };
        assert!(err.to_string().contains("c_1"));
    }

    #[test]
    fn display_webhook_not_found() {
        let err = FigmaError::WebhookNotFound {
            webhook_id: "wh_1".into(),
        };
        assert!(err.to_string().contains("wh_1"));
    }

    // ---- is_retryable ----

    #[test]
    fn is_retryable_rate_limited() {
        assert!(FigmaError::RateLimited {
            retry_after_secs: 1
        }
        .is_retryable());
    }

    #[test]
    fn is_retryable_api_500() {
        assert!(FigmaError::Api {
            status: 500,
            message: "internal".into(),
        }
        .is_retryable());
    }

    #[test]
    fn is_retryable_api_429() {
        assert!(FigmaError::Api {
            status: 429,
            message: "rate limited".into(),
        }
        .is_retryable());
    }

    #[test]
    fn is_retryable_api_timeout_message() {
        assert!(FigmaError::Api {
            status: 200,
            message: "timeout occurred".into(),
        }
        .is_retryable());
    }

    #[test]
    fn is_retryable_api_temporarily_unavailable() {
        assert!(FigmaError::Api {
            status: 200,
            message: "service temporarily unavailable".into(),
        }
        .is_retryable());
    }

    #[test]
    fn not_retryable_api_400() {
        assert!(!FigmaError::Api {
            status: 400,
            message: "bad request".into(),
        }
        .is_retryable());
    }

    #[test]
    fn not_retryable_unauthorized() {
        assert!(!FigmaError::Unauthorized.is_retryable());
    }

    #[test]
    fn not_retryable_file_not_found() {
        assert!(!FigmaError::FileNotFound {
            file_key: "x".into()
        }
        .is_retryable());
    }

    // ---- retry_after ----

    #[test]
    fn retry_after_rate_limited() {
        let err = FigmaError::RateLimited {
            retry_after_secs: 60,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(60)));
    }

    #[test]
    fn retry_after_other_none() {
        assert_eq!(FigmaError::Unauthorized.retry_after(), None);
    }

    // ---- to_fcp_error ----

    #[test]
    fn to_fcp_error_api_401() {
        let err = FigmaError::Api {
            status: 401,
            message: "bad token".into(),
        };
        assert!(matches!(err.to_fcp_error(), FcpError::Unauthorized { .. }));
    }

    #[test]
    fn to_fcp_error_api_403() {
        let err = FigmaError::Api {
            status: 403,
            message: "forbidden".into(),
        };
        assert!(matches!(err.to_fcp_error(), FcpError::Unauthorized { .. }));
    }

    #[test]
    fn to_fcp_error_api_429() {
        let err = FigmaError::Api {
            status: 429,
            message: "rate limited".into(),
        };
        match err.to_fcp_error() {
            FcpError::RateLimited {
                retry_after_ms, ..
            } => assert_eq!(retry_after_ms, 60_000),
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_404() {
        let err = FigmaError::Api {
            status: 404,
            message: "not found".into(),
        };
        assert!(matches!(
            err.to_fcp_error(),
            FcpError::ResourceNotFound { .. }
        ));
    }

    #[test]
    fn to_fcp_error_api_500() {
        let err = FigmaError::Api {
            status: 500,
            message: "internal".into(),
        };
        match err.to_fcp_error() {
            FcpError::External {
                service, retryable, ..
            } => {
                assert_eq!(service, "figma");
                assert!(retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_rate_limited_ms_conversion() {
        let err = FigmaError::RateLimited {
            retry_after_secs: 10,
        };
        match err.to_fcp_error() {
            FcpError::RateLimited {
                retry_after_ms, ..
            } => assert_eq!(retry_after_ms, 10_000),
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_unauthorized() {
        match FigmaError::Unauthorized.to_fcp_error() {
            FcpError::Unauthorized { code, .. } => assert_eq!(code, 2001),
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_file_not_found() {
        let err = FigmaError::FileNotFound {
            file_key: "abc".into(),
        };
        match err.to_fcp_error() {
            FcpError::ResourceNotFound { resource } => assert!(resource.contains("file:abc")),
            other => panic!("expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_comment_not_found() {
        let err = FigmaError::CommentNotFound {
            comment_id: "c_1".into(),
        };
        match err.to_fcp_error() {
            FcpError::ResourceNotFound { resource } => assert!(resource.contains("comment:c_1")),
            other => panic!("expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_webhook_not_found() {
        let err = FigmaError::WebhookNotFound {
            webhook_id: "wh_1".into(),
        };
        match err.to_fcp_error() {
            FcpError::ResourceNotFound { resource } => assert!(resource.contains("webhook:wh_1")),
            other => panic!("expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_json() {
        let json_err = serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err();
        let err = FigmaError::Json(json_err);
        assert!(matches!(err.to_fcp_error(), FcpError::Internal { .. }));
    }

    // ---- From / Result / trait ----

    #[test]
    fn from_serde_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("x").unwrap_err();
        let err: FigmaError = json_err.into();
        assert!(matches!(err, FigmaError::Json(_)));
    }

    #[test]
    fn figma_result_ok() {
        let r: FigmaResult<u32> = Ok(42);
        assert!(r.is_ok());
    }

    #[test]
    fn error_trait_impl() {
        let _: &dyn std::error::Error = &FigmaError::Unauthorized;
    }
}
