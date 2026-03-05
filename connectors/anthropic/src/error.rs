//! Anthropic-specific error types.

use std::time::Duration;

use fcp_core::FcpError;
use thiserror::Error;

/// Anthropic-specific errors.
#[derive(Error, Debug)]
pub enum AnthropicError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Anthropic API returned an error
    #[error("Anthropic API error ({error_type}): {message}")]
    Api {
        error_type: String,
        message: String,
        status_code: Option<u16>,
    },

    /// Rate limited
    #[error("Rate limited, retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },

    /// Overloaded (529)
    #[error("API overloaded, retry after {retry_after_ms}ms")]
    Overloaded { retry_after_ms: u64 },

    /// Invalid API key
    #[error("Invalid API key")]
    InvalidApiKey,

    /// Context length exceeded
    #[error("Context length exceeded: {message}")]
    ContextLengthExceeded { message: String },
}

impl AnthropicError {
    /// Check if this error is retryable.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) => true,
            Self::RateLimited { .. } => true,
            Self::Overloaded { .. } => true,
            Self::Api { status_code, .. } => {
                matches!(status_code, Some(500..=599 | 429))
            }
            _ => false,
        }
    }

    /// Get the suggested retry delay.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after_ms } | Self::Overloaded { retry_after_ms } => {
                Some(Duration::from_millis(*retry_after_ms))
            }
            _ => None,
        }
    }

    /// Convert to FCP error.
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Http(e) => FcpError::External {
                service: "anthropic".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Api {
                error_type,
                message,
                status_code,
            } => {
                if *status_code == Some(401) {
                    FcpError::Unauthorized {
                        code: 2001,
                        message: "Invalid Anthropic API key".into(),
                    }
                } else if *status_code == Some(429) {
                    FcpError::RateLimited {
                        retry_after_ms: 30_000,
                        violation: None,
                    }
                } else {
                    FcpError::External {
                        service: "anthropic".into(),
                        message: format!("{error_type}: {message}"),
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
            Self::Overloaded { retry_after_ms } => FcpError::External {
                service: "anthropic".into(),
                message: "API overloaded".into(),
                status_code: Some(529),
                retryable: true,
                retry_after: Some(Duration::from_millis(*retry_after_ms)),
            },
            Self::InvalidApiKey => FcpError::Unauthorized {
                code: 2001,
                message: "Invalid Anthropic API key".into(),
            },
            Self::ContextLengthExceeded { message } => FcpError::InvalidRequest {
                code: 1004,
                message: message.clone(),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
        }
    }
}

/// Result type for Anthropic operations.
pub type AnthropicResult<T> = Result<T, AnthropicError>;

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Display ----

    #[test]
    fn display_api_error() {
        let err = AnthropicError::Api {
            error_type: "invalid_request_error".into(),
            message: "max tokens exceeded".into(),
            status_code: Some(400),
        };
        let s = err.to_string();
        assert!(s.contains("invalid_request_error"));
        assert!(s.contains("max tokens exceeded"));
    }

    #[test]
    fn display_rate_limited() {
        let err = AnthropicError::RateLimited {
            retry_after_ms: 5000,
        };
        assert!(err.to_string().contains("5000ms"));
    }

    #[test]
    fn display_overloaded() {
        let err = AnthropicError::Overloaded {
            retry_after_ms: 10_000,
        };
        assert!(err.to_string().contains("overloaded"));
    }

    #[test]
    fn display_invalid_api_key() {
        let err = AnthropicError::InvalidApiKey;
        assert!(err.to_string().contains("Invalid API key"));
    }

    #[test]
    fn display_context_length_exceeded() {
        let err = AnthropicError::ContextLengthExceeded {
            message: "200k token limit".into(),
        };
        assert!(err.to_string().contains("200k token limit"));
    }

    #[test]
    fn display_json() {
        let json_err = serde_json::from_str::<serde_json::Value>("bad").unwrap_err();
        let err = AnthropicError::Json(json_err);
        assert!(err.to_string().contains("JSON error"));
    }

    // ---- is_retryable ----

    #[test]
    fn is_retryable_rate_limited() {
        assert!(
            AnthropicError::RateLimited {
                retry_after_ms: 1000
            }
            .is_retryable()
        );
    }

    #[test]
    fn is_retryable_overloaded() {
        assert!(
            AnthropicError::Overloaded {
                retry_after_ms: 1000
            }
            .is_retryable()
        );
    }

    #[test]
    fn is_retryable_api_500() {
        assert!(
            AnthropicError::Api {
                error_type: "server_error".into(),
                message: "internal".into(),
                status_code: Some(500),
            }
            .is_retryable()
        );
    }

    #[test]
    fn is_retryable_api_429() {
        assert!(
            AnthropicError::Api {
                error_type: "rate_limit_error".into(),
                message: "too many".into(),
                status_code: Some(429),
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_api_400() {
        assert!(
            !AnthropicError::Api {
                error_type: "invalid_request_error".into(),
                message: "bad".into(),
                status_code: Some(400),
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_invalid_api_key() {
        assert!(!AnthropicError::InvalidApiKey.is_retryable());
    }

    #[test]
    fn not_retryable_context_length() {
        assert!(
            !AnthropicError::ContextLengthExceeded {
                message: "x".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_json() {
        let json_err = serde_json::from_str::<serde_json::Value>("x").unwrap_err();
        assert!(!AnthropicError::Json(json_err).is_retryable());
    }

    // ---- retry_after ----

    #[test]
    fn retry_after_rate_limited() {
        let err = AnthropicError::RateLimited {
            retry_after_ms: 5000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn retry_after_overloaded() {
        let err = AnthropicError::Overloaded {
            retry_after_ms: 10_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(10)));
    }

    #[test]
    fn retry_after_other_none() {
        assert_eq!(AnthropicError::InvalidApiKey.retry_after(), None);
        assert_eq!(
            AnthropicError::Api {
                error_type: "x".into(),
                message: "x".into(),
                status_code: Some(500)
            }
            .retry_after(),
            None
        );
    }

    // ---- to_fcp_error ----

    #[test]
    fn to_fcp_error_api_401() {
        let err = AnthropicError::Api {
            error_type: "authentication_error".into(),
            message: "invalid key".into(),
            status_code: Some(401),
        };
        match err.to_fcp_error() {
            FcpError::Unauthorized { code, message } => {
                assert_eq!(code, 2001);
                assert!(message.contains("Anthropic API key"));
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_429() {
        let err = AnthropicError::Api {
            error_type: "rate_limit_error".into(),
            message: "too many".into(),
            status_code: Some(429),
        };
        match err.to_fcp_error() {
            FcpError::RateLimited { retry_after_ms, .. } => assert_eq!(retry_after_ms, 30_000),
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_500_external() {
        let err = AnthropicError::Api {
            error_type: "api_error".into(),
            message: "server error".into(),
            status_code: Some(500),
        };
        match err.to_fcp_error() {
            FcpError::External {
                service,
                retryable,
                status_code,
                message,
                ..
            } => {
                assert_eq!(service, "anthropic");
                assert!(retryable);
                assert_eq!(status_code, Some(500));
                assert!(message.contains("api_error"));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_rate_limited() {
        let err = AnthropicError::RateLimited {
            retry_after_ms: 2000,
        };
        match err.to_fcp_error() {
            FcpError::RateLimited {
                retry_after_ms,
                violation,
            } => {
                assert_eq!(retry_after_ms, 2000);
                assert!(violation.is_none());
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_overloaded_529() {
        let err = AnthropicError::Overloaded {
            retry_after_ms: 15_000,
        };
        match err.to_fcp_error() {
            FcpError::External {
                service,
                status_code,
                retryable,
                retry_after,
                ..
            } => {
                assert_eq!(service, "anthropic");
                assert_eq!(status_code, Some(529));
                assert!(retryable);
                assert_eq!(retry_after, Some(Duration::from_secs(15)));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_invalid_api_key() {
        match AnthropicError::InvalidApiKey.to_fcp_error() {
            FcpError::Unauthorized { code, .. } => assert_eq!(code, 2001),
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_context_length() {
        let err = AnthropicError::ContextLengthExceeded {
            message: "200k tokens".into(),
        };
        match err.to_fcp_error() {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1004);
                assert!(message.contains("200k tokens"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_json_internal() {
        let json_err = serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err();
        let err = AnthropicError::Json(json_err);
        match err.to_fcp_error() {
            FcpError::Internal { message } => assert!(message.contains("JSON error")),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    // ---- From impls ----

    #[test]
    fn from_serde_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("nope").unwrap_err();
        let err: AnthropicError = json_err.into();
        assert!(matches!(err, AnthropicError::Json(_)));
    }

    // ---- Result alias ----

    #[test]
    fn anthropic_result_ok() {
        let r: AnthropicResult<u32> = Ok(42);
        assert!(r.is_ok());
    }

    #[test]
    fn anthropic_result_err() {
        let r: AnthropicResult<u32> = Err(AnthropicError::InvalidApiKey);
        assert!(r.is_err());
    }

    // ---- std::error::Error trait ----

    #[test]
    fn error_trait_impl() {
        let err = AnthropicError::InvalidApiKey;
        let _: &dyn std::error::Error = &err;
    }
}
