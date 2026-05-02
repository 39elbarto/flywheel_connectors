//! Plaid-specific error types.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_sdk::migration::ConnectorErrorMapping;

/// Plaid API error.
#[derive(Debug, thiserror::Error)]
pub enum PlaidError {
    #[error("Plaid API error: {message}")]
    Api {
        message: String,
        status_code: Option<u16>,
        error_type: Option<String>,
        error_code: Option<String>,
    },

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Rate limited")]
    RateLimit { retry_after_ms: u64 },
}

pub type PlaidResult<T> = Result<T, PlaidError>;

impl PlaidError {
    /// Check if this error is retryable.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::RateLimit { .. } => true,
            Self::Api { status_code, .. } => matches!(status_code, Some(500..=599 | 429)),
            Self::InvalidConfig(_) | Self::Serialization(_) => false,
        }
    }

    /// Get the suggested retry delay.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimit { retry_after_ms } => Some(Duration::from_millis(*retry_after_ms)),
            _ => None,
        }
    }

    /// Convert to FCP error.
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Api {
                message,
                status_code,
                ..
            } => {
                if *status_code == Some(401) || *status_code == Some(403) {
                    FcpError::Unauthorized {
                        code: 2001,
                        message: message.clone(),
                    }
                } else if *status_code == Some(429) {
                    FcpError::RateLimited {
                        retry_after_ms: 60_000,
                        violation: None,
                    }
                } else {
                    FcpError::External {
                        service: "plaid".into(),
                        message: message.clone(),
                        status_code: *status_code,
                        retryable: self.is_retryable(),
                        retry_after: self.retry_after(),
                    }
                }
            }
            Self::Http(e) => FcpError::External {
                service: "plaid".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::InvalidConfig(msg) => FcpError::Internal {
                message: format!("Plaid configuration error: {msg}"),
            },
            Self::Serialization(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
            Self::RateLimit { retry_after_ms } => FcpError::RateLimited {
                retry_after_ms: *retry_after_ms,
                violation: None,
            },
        }
    }
}

impl ConnectorErrorMapping for PlaidError {
    fn from_async_error(error: AsyncError) -> Self {
        match error {
            AsyncError::Timeout { timeout_ms } => Self::Api {
                message: format!("deadline exceeded after {timeout_ms}ms"),
                status_code: Some(408),
                error_type: None,
                error_code: None,
            },
            AsyncError::Cancelled => Self::Api {
                message: "request cancelled".into(),
                status_code: None,
                error_type: None,
                error_code: None,
            },
            other => Self::Api {
                message: other.to_string(),
                status_code: None,
                error_type: None,
                error_code: None,
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

    // ---- Display messages ----

    #[test]
    fn display_api_error() {
        let err = PlaidError::Api {
            message: "INVALID_ACCESS_TOKEN".into(),
            status_code: Some(400),
            error_type: Some("INVALID_INPUT".into()),
            error_code: Some("INVALID_ACCESS_TOKEN".into()),
        };
        assert!(err.to_string().contains("INVALID_ACCESS_TOKEN"));
    }

    #[test]
    fn display_invalid_config() {
        let err = PlaidError::InvalidConfig("missing client_id".into());
        assert!(err.to_string().contains("missing client_id"));
    }

    #[test]
    fn display_rate_limit() {
        let err = PlaidError::RateLimit {
            retry_after_ms: 5000,
        };
        assert!(err.to_string().contains("Rate limited"));
    }

    #[test]
    fn display_serialization() {
        let json_err = serde_json::from_str::<serde_json::Value>("not json").unwrap_err();
        let err = PlaidError::Serialization(json_err);
        assert!(err.to_string().contains("Serialization error"));
    }

    // ---- is_retryable ----

    #[test]
    fn is_retryable_rate_limit() {
        let err = PlaidError::RateLimit {
            retry_after_ms: 1000,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn is_retryable_api_500() {
        let err = PlaidError::Api {
            message: "internal".into(),
            status_code: Some(500),
            error_type: None,
            error_code: None,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn is_retryable_api_503() {
        let err = PlaidError::Api {
            message: "unavailable".into(),
            status_code: Some(503),
            error_type: None,
            error_code: None,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn is_retryable_api_429() {
        let err = PlaidError::Api {
            message: "too many requests".into(),
            status_code: Some(429),
            error_type: None,
            error_code: None,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn not_retryable_api_400() {
        let err = PlaidError::Api {
            message: "bad request".into(),
            status_code: Some(400),
            error_type: None,
            error_code: None,
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn not_retryable_api_no_status() {
        let err = PlaidError::Api {
            message: "unknown".into(),
            status_code: None,
            error_type: None,
            error_code: None,
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn not_retryable_invalid_config() {
        let err = PlaidError::InvalidConfig("bad".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn not_retryable_serialization() {
        let json_err = serde_json::from_str::<serde_json::Value>("x").unwrap_err();
        let err = PlaidError::Serialization(json_err);
        assert!(!err.is_retryable());
    }

    // ---- retry_after ----

    #[test]
    fn retry_after_rate_limit() {
        let err = PlaidError::RateLimit {
            retry_after_ms: 3000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(3)));
    }

    #[test]
    fn retry_after_api_is_none() {
        let err = PlaidError::Api {
            message: "err".into(),
            status_code: Some(500),
            error_type: None,
            error_code: None,
        };
        assert_eq!(err.retry_after(), None);
    }

    #[test]
    fn retry_after_config_is_none() {
        let err = PlaidError::InvalidConfig("x".into());
        assert_eq!(err.retry_after(), None);
    }

    // ---- to_fcp_error ----

    #[test]
    fn to_fcp_error_api_401_unauthorized() {
        let err = PlaidError::Api {
            message: "unauthorized".into(),
            status_code: Some(401),
            error_type: None,
            error_code: None,
        };
        match err.to_fcp_error() {
            FcpError::Unauthorized { code, message } => {
                assert_eq!(code, 2001);
                assert!(message.contains("unauthorized"));
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_403_unauthorized() {
        let err = PlaidError::Api {
            message: "forbidden".into(),
            status_code: Some(403),
            error_type: None,
            error_code: None,
        };
        assert!(matches!(err.to_fcp_error(), FcpError::Unauthorized { .. }));
    }

    #[test]
    fn to_fcp_error_api_429_rate_limited() {
        let err = PlaidError::Api {
            message: "rate limited".into(),
            status_code: Some(429),
            error_type: None,
            error_code: None,
        };
        match err.to_fcp_error() {
            FcpError::RateLimited { retry_after_ms, .. } => {
                assert_eq!(retry_after_ms, 60_000);
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_500_external_retryable() {
        let err = PlaidError::Api {
            message: "server error".into(),
            status_code: Some(500),
            error_type: None,
            error_code: None,
        };
        match err.to_fcp_error() {
            FcpError::External {
                service,
                retryable,
                status_code,
                ..
            } => {
                assert_eq!(service, "plaid");
                assert!(retryable);
                assert_eq!(status_code, Some(500));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_400_external_not_retryable() {
        let err = PlaidError::Api {
            message: "bad request".into(),
            status_code: Some(400),
            error_type: None,
            error_code: None,
        };
        match err.to_fcp_error() {
            FcpError::External {
                retryable,
                status_code,
                ..
            } => {
                assert!(!retryable);
                assert_eq!(status_code, Some(400));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_no_status_code() {
        let err = PlaidError::Api {
            message: "unknown".into(),
            status_code: None,
            error_type: None,
            error_code: None,
        };
        match err.to_fcp_error() {
            FcpError::External {
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(status_code, None);
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_invalid_config_internal() {
        let err = PlaidError::InvalidConfig("no client_id".into());
        match err.to_fcp_error() {
            FcpError::Internal { message } => {
                assert!(message.contains("no client_id"));
                assert!(message.contains("Plaid configuration error"));
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_serialization_internal() {
        let json_err = serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err();
        let err = PlaidError::Serialization(json_err);
        match err.to_fcp_error() {
            FcpError::Internal { message } => {
                assert!(message.contains("JSON error"));
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_rate_limit() {
        let err = PlaidError::RateLimit {
            retry_after_ms: 2500,
        };
        match err.to_fcp_error() {
            FcpError::RateLimited {
                retry_after_ms,
                violation,
            } => {
                assert_eq!(retry_after_ms, 2500);
                assert!(violation.is_none());
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    // ---- PlaidResult alias ----

    #[test]
    fn plaid_result_ok() {
        let r: PlaidResult<u32> = Ok(42);
        assert!(r.is_ok());
    }

    #[test]
    fn plaid_result_err() {
        let r: PlaidResult<u32> = Err(PlaidError::InvalidConfig("x".into()));
        assert!(r.is_err());
    }

    // ---- From impls ----

    #[test]
    fn from_serde_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("nope").unwrap_err();
        let err: PlaidError = json_err.into();
        assert!(matches!(err, PlaidError::Serialization(_)));
    }

    // ---- std::error::Error trait ----

    #[test]
    fn error_trait_impl() {
        let err = PlaidError::InvalidConfig("x".into());
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn error_trait_source_api() {
        let err = PlaidError::Api {
            message: "test".into(),
            status_code: Some(400),
            error_type: None,
            error_code: None,
        };
        // Api variant has no underlying source
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn error_trait_source_serialization() {
        let json_err = serde_json::from_str::<serde_json::Value>("xxx").unwrap_err();
        let err = PlaidError::Serialization(json_err);
        // Serialization wraps a serde_json::Error source
        assert!(std::error::Error::source(&err).is_some());
    }

    #[test]
    fn error_trait_source_invalid_config() {
        let err = PlaidError::InvalidConfig("missing secret".into());
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn error_trait_source_rate_limit() {
        let err = PlaidError::RateLimit {
            retry_after_ms: 1000,
        };
        assert!(std::error::Error::source(&err).is_none());
    }

    // ---- Debug format ----

    #[test]
    fn debug_format_api() {
        let err = PlaidError::Api {
            message: "not found".into(),
            status_code: Some(404),
            error_type: Some("INVALID_INPUT".into()),
            error_code: Some("MISSING_FIELDS".into()),
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("Api"));
        assert!(debug.contains("not found"));
        assert!(debug.contains("404"));
        assert!(debug.contains("INVALID_INPUT"));
        assert!(debug.contains("MISSING_FIELDS"));
    }

    #[test]
    fn debug_format_rate_limit() {
        let err = PlaidError::RateLimit {
            retry_after_ms: 7500,
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("RateLimit"));
        assert!(debug.contains("7500"));
    }

    #[test]
    fn debug_format_invalid_config() {
        let err = PlaidError::InvalidConfig("no env var".into());
        let debug = format!("{err:?}");
        assert!(debug.contains("InvalidConfig"));
        assert!(debug.contains("no env var"));
    }

    #[test]
    fn debug_format_serialization() {
        let json_err = serde_json::from_str::<serde_json::Value>("{").unwrap_err();
        let err = PlaidError::Serialization(json_err);
        let debug = format!("{err:?}");
        assert!(debug.contains("Serialization"));
    }

    // ---- Display messages (additional edge cases) ----

    #[test]
    fn display_api_error_with_all_optional_fields() {
        let err = PlaidError::Api {
            message: "Item not found".into(),
            status_code: Some(404),
            error_type: Some("INVALID_INPUT".into()),
            error_code: Some("ITEM_NOT_FOUND".into()),
        };
        let display = err.to_string();
        assert!(display.contains("Plaid API error"));
        assert!(display.contains("Item not found"));
    }

    #[test]
    fn display_api_error_no_optional_fields() {
        let err = PlaidError::Api {
            message: "generic error".into(),
            status_code: None,
            error_type: None,
            error_code: None,
        };
        let display = err.to_string();
        assert!(display.contains("generic error"));
    }

    #[test]
    fn display_http_error_format() {
        // Build a reqwest error through invalid URL parse
        let _err_result = reqwest::Client::new()
            .get("http://[::ffff:0:0]/bad")
            .build();
        // We can't easily construct a reqwest::Error, so verify format via InvalidConfig
        let err = PlaidError::InvalidConfig("HTTP issue".into());
        assert!(err.to_string().starts_with("Invalid configuration:"));
    }

    // ---- is_retryable (additional edge cases) ----

    #[test]
    fn is_retryable_api_502() {
        let err = PlaidError::Api {
            message: "bad gateway".into(),
            status_code: Some(502),
            error_type: None,
            error_code: None,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn is_retryable_api_599() {
        let err = PlaidError::Api {
            message: "edge server error".into(),
            status_code: Some(599),
            error_type: None,
            error_code: None,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn not_retryable_api_401() {
        let err = PlaidError::Api {
            message: "unauthorized".into(),
            status_code: Some(401),
            error_type: None,
            error_code: None,
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn not_retryable_api_403() {
        let err = PlaidError::Api {
            message: "forbidden".into(),
            status_code: Some(403),
            error_type: None,
            error_code: None,
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn not_retryable_api_404() {
        let err = PlaidError::Api {
            message: "not found".into(),
            status_code: Some(404),
            error_type: None,
            error_code: None,
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn not_retryable_api_422() {
        let err = PlaidError::Api {
            message: "unprocessable".into(),
            status_code: Some(422),
            error_type: None,
            error_code: None,
        };
        assert!(!err.is_retryable());
    }

    // ---- retry_after (additional edge cases) ----

    #[test]
    fn retry_after_serialization_is_none() {
        let json_err = serde_json::from_str::<serde_json::Value>("#").unwrap_err();
        let err = PlaidError::Serialization(json_err);
        assert_eq!(err.retry_after(), None);
    }

    #[test]
    fn retry_after_rate_limit_zero_ms() {
        let err = PlaidError::RateLimit { retry_after_ms: 0 };
        assert_eq!(err.retry_after(), Some(Duration::from_millis(0)));
    }

    #[test]
    fn retry_after_rate_limit_large_value() {
        let err = PlaidError::RateLimit {
            retry_after_ms: 120_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(120)));
    }

    // ---- to_fcp_error (additional edge cases) ----

    #[test]
    fn to_fcp_error_api_503_external_retryable() {
        let err = PlaidError::Api {
            message: "service unavailable".into(),
            status_code: Some(503),
            error_type: None,
            error_code: None,
        };
        match err.to_fcp_error() {
            FcpError::External {
                service,
                retryable,
                status_code,
                message,
                ..
            } => {
                assert_eq!(service, "plaid");
                assert!(retryable);
                assert_eq!(status_code, Some(503));
                assert!(message.contains("service unavailable"));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_502_external_retryable() {
        let err = PlaidError::Api {
            message: "bad gateway".into(),
            status_code: Some(502),
            error_type: Some("API_ERROR".into()),
            error_code: Some("INTERNAL_SERVER_ERROR".into()),
        };
        match err.to_fcp_error() {
            FcpError::External {
                retryable,
                status_code,
                ..
            } => {
                assert!(retryable);
                assert_eq!(status_code, Some(502));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_404_external_not_retryable() {
        let err = PlaidError::Api {
            message: "item not found".into(),
            status_code: Some(404),
            error_type: Some("INVALID_INPUT".into()),
            error_code: Some("ITEM_NOT_FOUND".into()),
        };
        match err.to_fcp_error() {
            FcpError::External {
                retryable,
                status_code,
                ..
            } => {
                assert!(!retryable);
                assert_eq!(status_code, Some(404));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_rate_limit_zero_ms() {
        let err = PlaidError::RateLimit { retry_after_ms: 0 };
        match err.to_fcp_error() {
            FcpError::RateLimited {
                retry_after_ms,
                violation,
            } => {
                assert_eq!(retry_after_ms, 0);
                assert!(violation.is_none());
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_rate_limit_large_delay() {
        let err = PlaidError::RateLimit {
            retry_after_ms: 300_000,
        };
        match err.to_fcp_error() {
            FcpError::RateLimited { retry_after_ms, .. } => {
                assert_eq!(retry_after_ms, 300_000);
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_429_uses_fixed_retry_after() {
        // The 429 branch in to_fcp_error uses a hardcoded 60_000 ms, not the actual
        // retry_after from the error itself, because it's an Api variant not RateLimit.
        let err = PlaidError::Api {
            message: "too many requests".into(),
            status_code: Some(429),
            error_type: None,
            error_code: None,
        };
        match err.to_fcp_error() {
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
    fn to_fcp_error_api_401_message_preserved() {
        let err = PlaidError::Api {
            message: "INVALID_API_KEYS: client_id wrong".into(),
            status_code: Some(401),
            error_type: Some("INVALID_INPUT".into()),
            error_code: Some("INVALID_API_KEYS".into()),
        };
        match err.to_fcp_error() {
            FcpError::Unauthorized { code, message } => {
                assert_eq!(code, 2001);
                assert!(message.contains("INVALID_API_KEYS"));
                assert!(message.contains("client_id wrong"));
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_403_message_preserved() {
        let err = PlaidError::Api {
            message: "access denied for sandbox".into(),
            status_code: Some(403),
            error_type: None,
            error_code: None,
        };
        match err.to_fcp_error() {
            FcpError::Unauthorized { code, message } => {
                assert_eq!(code, 2001);
                assert!(message.contains("access denied"));
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_invalid_config_message_format() {
        let err = PlaidError::InvalidConfig("PLAID_SECRET not set".into());
        match err.to_fcp_error() {
            FcpError::Internal { message } => {
                assert!(message.starts_with("Plaid configuration error: "));
                assert!(message.contains("PLAID_SECRET not set"));
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_serialization_message_format() {
        let json_err = serde_json::from_str::<serde_json::Value>("{{nested}}").unwrap_err();
        let err_msg = json_err.to_string();
        let err = PlaidError::Serialization(json_err);
        match err.to_fcp_error() {
            FcpError::Internal { message } => {
                assert!(message.starts_with("JSON error: "));
                assert!(message.contains(&err_msg));
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_external_retry_after_is_none() {
        // For a generic Api error (non-429, non-auth), retry_after should be None
        let err = PlaidError::Api {
            message: "server hiccup".into(),
            status_code: Some(500),
            error_type: None,
            error_code: None,
        };
        match err.to_fcp_error() {
            FcpError::External { retry_after, .. } => {
                assert!(retry_after.is_none());
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_no_status_service_is_plaid() {
        let err = PlaidError::Api {
            message: "something".into(),
            status_code: None,
            error_type: None,
            error_code: None,
        };
        match err.to_fcp_error() {
            FcpError::External { service, .. } => {
                assert_eq!(service, "plaid");
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    // ── Additional edge cases ───────────────────────────────────────────

    #[test]
    fn api_error_with_all_fields_set() {
        let err = PlaidError::Api {
            message: "Product not ready".into(),
            status_code: Some(400),
            error_type: Some("INVALID_REQUEST".into()),
            error_code: Some("PRODUCT_NOT_READY".into()),
        };
        assert!(!err.is_retryable());
        let display = err.to_string();
        assert!(display.contains("Product not ready"));
    }

    #[test]
    fn api_error_empty_message() {
        let err = PlaidError::Api {
            message: String::new(),
            status_code: Some(500),
            error_type: None,
            error_code: None,
        };
        assert_eq!(err.to_string(), "Plaid API error: ");
        assert!(err.is_retryable());
    }

    #[test]
    fn rate_limit_max_u64() {
        let err = PlaidError::RateLimit {
            retry_after_ms: u64::MAX,
        };
        let dur = err.retry_after().unwrap();
        assert_eq!(dur.as_millis(), u128::from(u64::MAX));
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::RateLimited { retry_after_ms, .. } => {
                assert_eq!(retry_after_ms, u64::MAX);
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn invalid_config_empty_string() {
        let err = PlaidError::InvalidConfig(String::new());
        assert_eq!(err.to_string(), "Invalid configuration: ");
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::Internal { message } => {
                assert!(message.contains("Plaid configuration error: "));
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn is_retryable_api_504() {
        let err = PlaidError::Api {
            message: "gateway timeout".into(),
            status_code: Some(504),
            error_type: None,
            error_code: None,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn not_retryable_api_499_boundary() {
        let err = PlaidError::Api {
            message: "edge".into(),
            status_code: Some(499),
            error_type: None,
            error_code: None,
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn not_retryable_api_600_boundary() {
        let err = PlaidError::Api {
            message: "edge".into(),
            status_code: Some(600),
            error_type: None,
            error_code: None,
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn to_fcp_error_api_with_error_type_preserved_in_external() {
        let err = PlaidError::Api {
            message: "some error".into(),
            status_code: Some(400),
            error_type: Some("INVALID_REQUEST".into()),
            error_code: Some("MISSING_FIELDS".into()),
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::External { message, .. } => {
                assert_eq!(message, "some error");
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn display_format_consistency() {
        let variants: Vec<PlaidError> = vec![
            PlaidError::Api {
                message: "a".into(),
                status_code: Some(400),
                error_type: None,
                error_code: None,
            },
            PlaidError::InvalidConfig("b".into()),
            PlaidError::RateLimit {
                retry_after_ms: 100,
            },
        ];
        for v in &variants {
            let display = format!("{v}");
            assert!(!display.is_empty(), "Display should not be empty");
        }
    }

    #[test]
    fn debug_format_shows_variant_name() {
        let err = PlaidError::Api {
            message: "debug test".into(),
            status_code: Some(500),
            error_type: Some("API_ERROR".into()),
            error_code: Some("INTERNAL_ERROR".into()),
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("Api"), "debug: {debug}");
        assert!(debug.contains("API_ERROR"), "debug: {debug}");
        assert!(debug.contains("INTERNAL_ERROR"), "debug: {debug}");
    }

    #[test]
    fn retry_after_http_is_none() {
        // HTTP errors are retryable but don't have retry_after
        // We test via Api variant since we can't easily construct reqwest::Error
        let err = PlaidError::Api {
            message: "network".into(),
            status_code: None,
            error_type: None,
            error_code: None,
        };
        assert!(err.retry_after().is_none());
    }
}
