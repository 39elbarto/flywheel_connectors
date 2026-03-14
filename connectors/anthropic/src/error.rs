//! Anthropic-specific error types.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_core::FcpError;
use fcp_sdk::migration::ConnectorErrorMapping;
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

impl ConnectorErrorMapping for AnthropicError {
    fn from_async_error(error: AsyncError) -> Self {
        match error {
            AsyncError::Timeout { timeout_ms } => Self::Api {
                error_type: "deadline_timeout".into(),
                message: format!("deadline exceeded after {timeout_ms}ms"),
                status_code: Some(408),
            },
            AsyncError::Cancelled => Self::Api {
                error_type: "request_cancelled".into(),
                message: "request cancelled".into(),
                status_code: None,
            },
            other => Self::Api {
                error_type: "runtime".into(),
                message: other.to_string(),
                status_code: None,
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

    // ---- Additional Display tests ----

    #[test]
    fn display_http_includes_http_error() {
        // We can only test that the format works with a real reqwest error
        // by triggering one, but we can test the other variants more thoroughly.
        let err = AnthropicError::Api {
            error_type: "server_error".into(),
            message: "internal server error".into(),
            status_code: Some(500),
        };
        let s = err.to_string();
        assert!(s.contains("server_error"));
        assert!(s.contains("internal server error"));
    }

    #[test]
    fn display_api_error_no_status() {
        let err = AnthropicError::Api {
            error_type: "unknown".into(),
            message: "something went wrong".into(),
            status_code: None,
        };
        let s = err.to_string();
        assert!(s.contains("unknown"));
        assert!(s.contains("something went wrong"));
    }

    // ---- is_retryable additional cases ----

    #[test]
    fn is_retryable_api_502() {
        assert!(
            AnthropicError::Api {
                error_type: "api_error".into(),
                message: "bad gateway".into(),
                status_code: Some(502),
            }
            .is_retryable()
        );
    }

    #[test]
    fn is_retryable_api_503() {
        assert!(
            AnthropicError::Api {
                error_type: "api_error".into(),
                message: "service unavailable".into(),
                status_code: Some(503),
            }
            .is_retryable()
        );
    }

    #[test]
    fn is_retryable_api_599() {
        assert!(
            AnthropicError::Api {
                error_type: "api_error".into(),
                message: "server error".into(),
                status_code: Some(599),
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_api_none_status() {
        assert!(
            !AnthropicError::Api {
                error_type: "x".into(),
                message: "x".into(),
                status_code: None,
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_api_403() {
        assert!(
            !AnthropicError::Api {
                error_type: "x".into(),
                message: "x".into(),
                status_code: Some(403),
            }
            .is_retryable()
        );
    }

    // ---- retry_after additional cases ----

    #[test]
    fn retry_after_zero_ms() {
        let err = AnthropicError::RateLimited { retry_after_ms: 0 };
        assert_eq!(err.retry_after(), Some(Duration::from_millis(0)));
    }

    #[test]
    fn retry_after_context_length_none() {
        assert_eq!(
            AnthropicError::ContextLengthExceeded {
                message: "x".into()
            }
            .retry_after(),
            None
        );
    }

    #[test]
    fn retry_after_json_none() {
        let json_err = serde_json::from_str::<serde_json::Value>("x").unwrap_err();
        assert_eq!(AnthropicError::Json(json_err).retry_after(), None);
    }

    // ---- to_fcp_error additional cases ----

    #[test]
    fn to_fcp_error_api_none_status_external() {
        let err = AnthropicError::Api {
            error_type: "unknown_error".into(),
            message: "something".into(),
            status_code: None,
        };
        match err.to_fcp_error() {
            FcpError::External {
                service,
                status_code,
                retryable,
                message,
                ..
            } => {
                assert_eq!(service, "anthropic");
                assert_eq!(status_code, None);
                assert!(!retryable);
                assert!(message.contains("unknown_error"));
                assert!(message.contains("something"));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_403_external() {
        let err = AnthropicError::Api {
            error_type: "forbidden_error".into(),
            message: "no access".into(),
            status_code: Some(403),
        };
        match err.to_fcp_error() {
            FcpError::External {
                service,
                status_code,
                ..
            } => {
                assert_eq!(service, "anthropic");
                assert_eq!(status_code, Some(403));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    // ---- Debug format ----

    #[test]
    fn debug_api_error() {
        let err = AnthropicError::Api {
            error_type: "test_type".into(),
            message: "test_msg".into(),
            status_code: Some(418),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Api"));
        assert!(dbg.contains("test_type"));
        assert!(dbg.contains("418"));
    }

    #[test]
    fn debug_rate_limited() {
        let err = AnthropicError::RateLimited {
            retry_after_ms: 7777,
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("RateLimited"));
        assert!(dbg.contains("7777"));
    }

    #[test]
    fn debug_overloaded() {
        let err = AnthropicError::Overloaded {
            retry_after_ms: 9999,
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Overloaded"));
        assert!(dbg.contains("9999"));
    }

    #[test]
    fn debug_invalid_api_key() {
        let dbg = format!("{:?}", AnthropicError::InvalidApiKey);
        assert!(dbg.contains("InvalidApiKey"));
    }

    #[test]
    fn debug_context_length() {
        let err = AnthropicError::ContextLengthExceeded {
            message: "ctx_msg".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("ContextLengthExceeded"));
        assert!(dbg.contains("ctx_msg"));
    }

    // ---- Source chain ----

    #[test]
    fn source_json_variant() {
        let json_err = serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err();
        let err = AnthropicError::Json(json_err);
        let source = std::error::Error::source(&err);
        assert!(source.is_some());
    }

    #[test]
    fn source_invalid_api_key_none() {
        let err = AnthropicError::InvalidApiKey;
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn source_api_none() {
        let err = AnthropicError::Api {
            error_type: "x".into(),
            message: "x".into(),
            status_code: None,
        };
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn source_rate_limited_none() {
        let err = AnthropicError::RateLimited {
            retry_after_ms: 100,
        };
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn source_overloaded_none() {
        let err = AnthropicError::Overloaded {
            retry_after_ms: 100,
        };
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn source_context_length_none() {
        let err = AnthropicError::ContextLengthExceeded {
            message: "x".into(),
        };
        assert!(std::error::Error::source(&err).is_none());
    }

    // ---- Overloaded display with large value ----

    #[test]
    fn display_overloaded_large_value() {
        let err = AnthropicError::Overloaded {
            retry_after_ms: 120_000,
        };
        assert!(err.to_string().contains("120000ms"));
    }

    // ---- Rate limited display with exact format ----

    #[test]
    fn display_rate_limited_exact() {
        let err = AnthropicError::RateLimited {
            retry_after_ms: 30_000,
        };
        assert_eq!(err.to_string(), "Rate limited, retry after 30000ms");
    }
}
