//! Plaid-specific error types.

use std::time::Duration;

use fcp_core::FcpError;

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
}
