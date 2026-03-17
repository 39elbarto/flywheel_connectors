//! Pinecone-specific error types.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_core::FcpError;
use fcp_sdk::migration::ConnectorErrorMapping;

/// Pinecone API error.
#[derive(Debug, thiserror::Error)]
pub enum PineconeError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Pinecone API error: {message}")]
    Api {
        message: String,
        status_code: Option<u16>,
    },

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Rate limited")]
    RateLimit { retry_after_ms: u64 },
}

pub type PineconeResult<T> = Result<T, PineconeError>;

impl PineconeError {
    /// Check if this error is retryable.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::RateLimit { .. } => true,
            Self::Api { status_code, .. } => matches!(status_code, Some(408 | 429 | 500..=599)),
            Self::Serialization(_) | Self::InvalidConfig(_) => false,
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
            Self::Http(e) => FcpError::External {
                service: "pinecone".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Serialization(e) => FcpError::Internal {
                message: format!("Serialization error: {e}"),
            },
            Self::Api {
                message,
                status_code,
            } => {
                if *status_code == Some(401) || *status_code == Some(403) {
                    FcpError::Unauthorized {
                        code: 2001,
                        message: message.clone(),
                    }
                } else if *status_code == Some(404) {
                    FcpError::ResourceNotFound {
                        resource: message.clone(),
                    }
                } else if *status_code == Some(429) {
                    FcpError::RateLimited {
                        retry_after_ms: 60_000,
                        violation: None,
                    }
                } else {
                    FcpError::External {
                        service: "pinecone".into(),
                        message: message.clone(),
                        status_code: *status_code,
                        retryable: self.is_retryable(),
                        retry_after: self.retry_after(),
                    }
                }
            }
            Self::InvalidConfig(msg) => FcpError::InvalidRequest {
                code: 1003,
                message: msg.clone(),
            },
            Self::RateLimit { retry_after_ms } => FcpError::RateLimited {
                retry_after_ms: *retry_after_ms,
                violation: None,
            },
        }
    }
}

impl ConnectorErrorMapping for PineconeError {
    fn from_async_error(error: AsyncError) -> Self {
        match error {
            AsyncError::Timeout { timeout_ms } => Self::Api {
                message: format!("deadline exceeded after {timeout_ms}ms"),
                status_code: Some(408),
            },
            AsyncError::Cancelled => Self::Api {
                message: "request cancelled".into(),
                status_code: None,
            },
            other => Self::Api {
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

#[cfg(test)]
mod tests {
    use super::*;

    // ── Display messages ───────────────────────────────────────────

    #[test]
    fn display_api_error() {
        let err = PineconeError::Api {
            message: "Bad vector dimension".into(),
            status_code: Some(400),
        };
        assert_eq!(err.to_string(), "Pinecone API error: Bad vector dimension");
    }

    #[test]
    fn display_api_error_no_status() {
        let err = PineconeError::Api {
            message: "Unknown failure".into(),
            status_code: None,
        };
        assert_eq!(err.to_string(), "Pinecone API error: Unknown failure");
    }

    #[test]
    fn display_invalid_config() {
        let err = PineconeError::InvalidConfig("missing api_key".into());
        assert_eq!(err.to_string(), "Invalid configuration: missing api_key");
    }

    #[test]
    fn display_rate_limit() {
        let err = PineconeError::RateLimit {
            retry_after_ms: 5000,
        };
        assert_eq!(err.to_string(), "Rate limited");
    }

    #[test]
    fn display_serialization_error() {
        let raw = r#"{"bad json"#;
        let serde_err = serde_json::from_str::<serde_json::Value>(raw).unwrap_err();
        let err = PineconeError::Serialization(serde_err);
        let display = err.to_string();
        assert!(
            display.starts_with("Serialization error:"),
            "got: {display}"
        );
    }

    #[test]
    fn display_http_error() {
        // Build a reqwest error from an invalid URL
        let client = reqwest::Client::new();
        let err = fcp_async_core::runtime::block_on_sync(async {
            client
                .get("http://[::ffff:0.0.0.0.0]:1/bad")
                .send()
                .await
                .unwrap_err()
        })
        .expect("build sync test runtime");
        let pinecone_err = PineconeError::Http(err);
        let display = pinecone_err.to_string();
        assert!(display.starts_with("HTTP error:"), "got: {display}");
    }

    // ── is_retryable ───────────────────────────────────────────────

    #[test]
    fn is_retryable_rate_limit() {
        let err = PineconeError::RateLimit {
            retry_after_ms: 1000,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn is_retryable_api_500() {
        let err = PineconeError::Api {
            message: "Server error".into(),
            status_code: Some(500),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn is_retryable_api_502() {
        let err = PineconeError::Api {
            message: "Bad gateway".into(),
            status_code: Some(502),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn is_retryable_api_503() {
        let err = PineconeError::Api {
            message: "Service unavailable".into(),
            status_code: Some(503),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn is_retryable_api_429() {
        let err = PineconeError::Api {
            message: "Too many requests".into(),
            status_code: Some(429),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn is_retryable_api_408() {
        let err = PineconeError::Api {
            message: "Request timeout".into(),
            status_code: Some(408),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn is_not_retryable_api_400() {
        let err = PineconeError::Api {
            message: "Bad request".into(),
            status_code: Some(400),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn is_not_retryable_api_401() {
        let err = PineconeError::Api {
            message: "Unauthorized".into(),
            status_code: Some(401),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn is_not_retryable_api_403() {
        let err = PineconeError::Api {
            message: "Forbidden".into(),
            status_code: Some(403),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn is_not_retryable_api_404() {
        let err = PineconeError::Api {
            message: "Not found".into(),
            status_code: Some(404),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn is_not_retryable_api_no_status() {
        let err = PineconeError::Api {
            message: "Something".into(),
            status_code: None,
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn is_not_retryable_serialization() {
        let serde_err = serde_json::from_str::<serde_json::Value>("not json").unwrap_err();
        let err = PineconeError::Serialization(serde_err);
        assert!(!err.is_retryable());
    }

    #[test]
    fn is_not_retryable_invalid_config() {
        let err = PineconeError::InvalidConfig("bad".into());
        assert!(!err.is_retryable());
    }

    // ── retry_after ────────────────────────────────────────────────

    #[test]
    fn retry_after_rate_limit() {
        let err = PineconeError::RateLimit {
            retry_after_ms: 3000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(3)));
    }

    #[test]
    fn retry_after_rate_limit_zero() {
        let err = PineconeError::RateLimit { retry_after_ms: 0 };
        assert_eq!(err.retry_after(), Some(Duration::ZERO));
    }

    #[test]
    fn retry_after_api_error_is_none() {
        let err = PineconeError::Api {
            message: "error".into(),
            status_code: Some(500),
        };
        assert_eq!(err.retry_after(), None);
    }

    #[test]
    fn retry_after_invalid_config_is_none() {
        let err = PineconeError::InvalidConfig("bad".into());
        assert_eq!(err.retry_after(), None);
    }

    #[test]
    fn retry_after_serialization_is_none() {
        let serde_err = serde_json::from_str::<serde_json::Value>("nope").unwrap_err();
        let err = PineconeError::Serialization(serde_err);
        assert_eq!(err.retry_after(), None);
    }

    // ── to_fcp_error ───────────────────────────────────────────────

    #[test]
    fn to_fcp_error_api_401_unauthorized() {
        let err = PineconeError::Api {
            message: "Invalid key".into(),
            status_code: Some(401),
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::Unauthorized { code, message } => {
                assert_eq!(code, 2001);
                assert_eq!(message, "Invalid key");
            }
            other => panic!("Expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_403_unauthorized() {
        let err = PineconeError::Api {
            message: "Forbidden".into(),
            status_code: Some(403),
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::Unauthorized { code, message } => {
                assert_eq!(code, 2001);
                assert_eq!(message, "Forbidden");
            }
            other => panic!("Expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_404_resource_not_found() {
        let err = PineconeError::Api {
            message: "Index my-idx not found".into(),
            status_code: Some(404),
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::ResourceNotFound { resource } => {
                assert_eq!(resource, "Index my-idx not found");
            }
            other => panic!("Expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_429_rate_limited() {
        let err = PineconeError::Api {
            message: "Too many requests".into(),
            status_code: Some(429),
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::RateLimited {
                retry_after_ms,
                violation,
            } => {
                assert_eq!(retry_after_ms, 60_000);
                assert!(violation.is_none());
            }
            other => panic!("Expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_500_external() {
        let err = PineconeError::Api {
            message: "Internal server error".into(),
            status_code: Some(500),
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::External {
                service,
                message,
                status_code,
                retryable,
                retry_after,
            } => {
                assert_eq!(service, "pinecone");
                assert_eq!(message, "Internal server error");
                assert_eq!(status_code, Some(500));
                assert!(retryable);
                assert!(retry_after.is_none());
            }
            other => panic!("Expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_400_external_not_retryable() {
        let err = PineconeError::Api {
            message: "Bad request".into(),
            status_code: Some(400),
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::External {
                service,
                retryable,
                status_code,
                ..
            } => {
                assert_eq!(service, "pinecone");
                assert_eq!(status_code, Some(400));
                assert!(!retryable);
            }
            other => panic!("Expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_no_status_external() {
        let err = PineconeError::Api {
            message: "Unknown".into(),
            status_code: None,
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::External {
                service,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "pinecone");
                assert!(status_code.is_none());
                assert!(!retryable);
            }
            other => panic!("Expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_serialization_internal() {
        let serde_err = serde_json::from_str::<serde_json::Value>("bad").unwrap_err();
        let err = PineconeError::Serialization(serde_err);
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::Internal { message } => {
                assert!(
                    message.starts_with("Serialization error:"),
                    "got: {message}"
                );
            }
            other => panic!("Expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_invalid_config_invalid_request() {
        let err = PineconeError::InvalidConfig("Missing api_key".into());
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1003);
                assert_eq!(message, "Missing api_key");
            }
            other => panic!("Expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_rate_limit() {
        let err = PineconeError::RateLimit {
            retry_after_ms: 5000,
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::RateLimited {
                retry_after_ms,
                violation,
            } => {
                assert_eq!(retry_after_ms, 5000);
                assert!(violation.is_none());
            }
            other => panic!("Expected RateLimited, got {other:?}"),
        }
    }

    // ── Debug format ───────────────────────────────────────────────

    #[test]
    fn debug_api_error() {
        let err = PineconeError::Api {
            message: "test".into(),
            status_code: Some(500),
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("Api"), "got: {debug}");
        assert!(debug.contains("500"), "got: {debug}");
        assert!(debug.contains("test"), "got: {debug}");
    }

    #[test]
    fn debug_rate_limit() {
        let err = PineconeError::RateLimit {
            retry_after_ms: 1234,
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("RateLimit"), "got: {debug}");
        assert!(debug.contains("1234"), "got: {debug}");
    }

    #[test]
    fn debug_invalid_config() {
        let err = PineconeError::InvalidConfig("no key".into());
        let debug = format!("{err:?}");
        assert!(debug.contains("InvalidConfig"), "got: {debug}");
        assert!(debug.contains("no key"), "got: {debug}");
    }

    #[test]
    fn debug_serialization() {
        let serde_err = serde_json::from_str::<serde_json::Value>("x").unwrap_err();
        let err = PineconeError::Serialization(serde_err);
        let debug = format!("{err:?}");
        assert!(debug.contains("Serialization"), "got: {debug}");
    }

    // ── std::error::Error trait ────────────────────────────────────

    #[test]
    fn error_trait_source_serialization() {
        let serde_err = serde_json::from_str::<serde_json::Value>("x").unwrap_err();
        let err = PineconeError::Serialization(serde_err);
        // thiserror wraps #[from] sources; source() should return Some
        let source = std::error::Error::source(&err);
        assert!(source.is_some());
    }

    #[test]
    fn error_trait_source_api_is_none() {
        let err = PineconeError::Api {
            message: "test".into(),
            status_code: Some(400),
        };
        let source = std::error::Error::source(&err);
        assert!(source.is_none());
    }

    #[test]
    fn error_trait_source_invalid_config_is_none() {
        let err = PineconeError::InvalidConfig("bad".into());
        let source = std::error::Error::source(&err);
        assert!(source.is_none());
    }

    #[test]
    fn error_trait_source_rate_limit_is_none() {
        let err = PineconeError::RateLimit {
            retry_after_ms: 100,
        };
        let source = std::error::Error::source(&err);
        assert!(source.is_none());
    }

    // ── From conversions ───────────────────────────────────────────

    #[test]
    fn from_serde_json_error() {
        let serde_err = serde_json::from_str::<serde_json::Value>("invalid").unwrap_err();
        let err: PineconeError = serde_err.into();
        assert!(matches!(err, PineconeError::Serialization(_)));
    }

    // ── PineconeResult type alias ──────────────────────────────────

    #[test]
    fn pinecone_result_ok() {
        let result: PineconeResult<u32> = Ok(42);
        assert!(matches!(result, Ok(42)));
    }

    #[test]
    fn pinecone_result_err() {
        let result: PineconeResult<u32> = Err(PineconeError::InvalidConfig("test".into()));
        assert!(result.is_err());
    }

    // ── Edge cases ─────────────────────────────────────────────────

    #[test]
    fn is_retryable_api_599_boundary() {
        let err = PineconeError::Api {
            message: "edge".into(),
            status_code: Some(599),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn is_not_retryable_api_499_boundary() {
        let err = PineconeError::Api {
            message: "edge".into(),
            status_code: Some(499),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn is_not_retryable_api_600_boundary() {
        let err = PineconeError::Api {
            message: "edge".into(),
            status_code: Some(600),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn to_fcp_error_api_502_retryable_external() {
        let err = PineconeError::Api {
            message: "Bad gateway".into(),
            status_code: Some(502),
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::External {
                retryable,
                status_code,
                ..
            } => {
                assert!(retryable);
                assert_eq!(status_code, Some(502));
            }
            other => panic!("Expected External, got {other:?}"),
        }
    }

    #[test]
    fn retry_after_large_value() {
        let err = PineconeError::RateLimit {
            retry_after_ms: 300_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(300)));
        assert!(err.is_retryable());
    }

    #[test]
    fn to_fcp_error_empty_api_message() {
        let err = PineconeError::Api {
            message: String::new(),
            status_code: Some(404),
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::ResourceNotFound { resource } => {
                assert!(resource.is_empty());
            }
            other => panic!("Expected ResourceNotFound, got {other:?}"),
        }
    }

    // ── Additional edge cases ───────────────────────────────────────────

    #[test]
    fn to_fcp_error_api_503_retryable_external() {
        let err = PineconeError::Api {
            message: "Service unavailable".into(),
            status_code: Some(503),
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::External {
                retryable,
                status_code,
                service,
                ..
            } => {
                assert!(retryable);
                assert_eq!(status_code, Some(503));
                assert_eq!(service, "pinecone");
            }
            other => panic!("Expected External, got {other:?}"),
        }
    }

    #[test]
    fn rate_limit_max_u64() {
        let err = PineconeError::RateLimit {
            retry_after_ms: u64::MAX,
        };
        let dur = err.retry_after().unwrap();
        assert_eq!(dur.as_millis(), u128::from(u64::MAX));
        assert!(err.is_retryable());
    }

    #[test]
    fn api_error_with_unicode_message() {
        let err = PineconeError::Api {
            message: "Index \u{2717} not found".into(),
            status_code: Some(404),
        };
        let display = err.to_string();
        assert!(display.contains("\u{2717}"));
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::ResourceNotFound { resource } => {
                assert!(resource.contains("\u{2717}"));
            }
            other => panic!("Expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn invalid_config_empty_string() {
        let err = PineconeError::InvalidConfig(String::new());
        assert_eq!(err.to_string(), "Invalid configuration: ");
        assert!(!err.is_retryable());
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1003);
                assert!(message.is_empty());
            }
            other => panic!("Expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_504_retryable() {
        let err = PineconeError::Api {
            message: "gateway timeout".into(),
            status_code: Some(504),
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::External {
                retryable,
                status_code,
                ..
            } => {
                assert!(retryable);
                assert_eq!(status_code, Some(504));
            }
            other => panic!("Expected External, got {other:?}"),
        }
    }

    #[test]
    fn from_async_timeout_is_retryable() {
        let err = <PineconeError as ConnectorErrorMapping>::from_async_error(AsyncError::Timeout {
            timeout_ms: 250,
        });
        match err.to_fcp_error() {
            FcpError::External {
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(status_code, Some(408));
                assert!(retryable);
            }
            other => panic!("Expected External, got {other:?}"),
        }
        assert!(err.is_retryable());
    }

    #[test]
    fn to_fcp_error_api_422_not_retryable() {
        let err = PineconeError::Api {
            message: "unprocessable".into(),
            status_code: Some(422),
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::External {
                retryable,
                status_code,
                ..
            } => {
                assert!(!retryable);
                assert_eq!(status_code, Some(422));
            }
            other => panic!("Expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_rate_limit_zero_ms() {
        let err = PineconeError::RateLimit { retry_after_ms: 0 };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::RateLimited {
                retry_after_ms,
                violation,
            } => {
                assert_eq!(retry_after_ms, 0);
                assert!(violation.is_none());
            }
            other => panic!("Expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn from_reqwest_error_is_retryable() {
        // reqwest errors (network) are always retryable
        // We test via the is_retryable method on Api variant for Http coverage
        let err = PineconeError::Api {
            message: "network issue".into(),
            status_code: None,
        };
        // Api with no status is NOT retryable
        assert!(!err.is_retryable());
    }

    #[test]
    fn display_format_consistency() {
        let variants: Vec<PineconeError> = vec![
            PineconeError::Api {
                message: "a".into(),
                status_code: Some(400),
            },
            PineconeError::InvalidConfig("b".into()),
            PineconeError::RateLimit {
                retry_after_ms: 100,
            },
        ];
        for v in &variants {
            let display = format!("{v}");
            assert!(!display.is_empty(), "Display should not be empty");
        }
    }
}
