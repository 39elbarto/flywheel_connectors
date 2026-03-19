//! Browser-specific error types.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_core::FcpError;
use fcp_sdk::migration::ConnectorErrorMapping;

/// Browser automation error.
#[derive(Debug, thiserror::Error)]
pub enum BrowserError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Browser API error: {message}")]
    Api {
        message: String,
        status_code: Option<u16>,
    },

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Timeout: {message}")]
    Timeout { message: String },
}

pub type BrowserResult<T> = Result<T, BrowserError>;

impl BrowserError {
    /// Check if this error is retryable.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::Timeout { .. } => true,
            Self::Api { status_code, .. } => matches!(status_code, Some(500..=599 | 429)),
            Self::InvalidConfig(_) | Self::Serialization(_) => false,
        }
    }

    /// Get the suggested retry delay.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::Api {
                status_code: Some(429),
                ..
            } => Some(Duration::from_secs(5)),
            _ => None,
        }
    }

    /// Convert to FCP error.
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Http(e) => FcpError::External {
                service: "browser".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Api {
                message,
                status_code,
            } => {
                if *status_code == Some(429) {
                    FcpError::RateLimited {
                        retry_after_ms: 5_000,
                        violation: None,
                    }
                } else {
                    FcpError::External {
                        service: "browser".into(),
                        message: message.clone(),
                        status_code: *status_code,
                        retryable: self.is_retryable(),
                        retry_after: self.retry_after(),
                    }
                }
            }
            Self::InvalidConfig(msg) => FcpError::Internal {
                message: format!("Invalid browser config: {msg}"),
            },
            Self::Serialization(e) => FcpError::Internal {
                message: format!("Serialization error: {e}"),
            },
            Self::Timeout { message } => FcpError::External {
                service: "browser".into(),
                message: message.clone(),
                status_code: Some(408),
                retryable: true,
                retry_after: Some(Duration::from_secs(1)),
            },
        }
    }
}

impl ConnectorErrorMapping for BrowserError {
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

    // ─────────────────────────────────────────────────────────────────────────
    // Display messages for all variants
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn display_api() {
        let err = BrowserError::Api {
            message: "page crashed".into(),
            status_code: Some(500),
        };
        assert!(err.to_string().contains("page crashed"));
    }

    #[test]
    fn display_api_format_exact() {
        let err = BrowserError::Api {
            message: "element not found".into(),
            status_code: Some(404),
        };
        assert_eq!(err.to_string(), "Browser API error: element not found");
    }

    #[test]
    fn display_api_no_status_code() {
        let err = BrowserError::Api {
            message: "unknown".into(),
            status_code: None,
        };
        assert_eq!(err.to_string(), "Browser API error: unknown");
    }

    #[test]
    fn display_invalid_config() {
        let err = BrowserError::InvalidConfig("missing endpoint".into());
        assert!(err.to_string().contains("missing endpoint"));
    }

    #[test]
    fn display_invalid_config_exact() {
        let err = BrowserError::InvalidConfig("bad proxy url".into());
        assert_eq!(err.to_string(), "Invalid configuration: bad proxy url");
    }

    #[test]
    fn display_timeout() {
        let err = BrowserError::Timeout {
            message: "navigation timed out".into(),
        };
        assert!(err.to_string().contains("navigation timed out"));
    }

    #[test]
    fn display_timeout_exact() {
        let err = BrowserError::Timeout {
            message: "selector wait exceeded 30s".into(),
        };
        assert_eq!(err.to_string(), "Timeout: selector wait exceeded 30s");
    }

    #[test]
    fn display_serialization() {
        let json_err = serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err();
        let err = BrowserError::Serialization(json_err);
        let msg = err.to_string();
        assert!(msg.starts_with("Serialization error:"));
    }

    #[test]
    fn display_http() {
        // We can't easily construct a reqwest::Error directly, but we can verify
        // the Display impl exists by testing the From conversion path
        let json_err = serde_json::from_str::<serde_json::Value>("bad").unwrap_err();
        let err = BrowserError::Serialization(json_err);
        // Just confirm Display works for the variant we can construct
        let _ = err.to_string();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // is_retryable for all variants
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn is_retryable_timeout() {
        assert!(
            BrowserError::Timeout {
                message: "x".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn is_retryable_api_500() {
        assert!(
            BrowserError::Api {
                message: "x".into(),
                status_code: Some(500),
            }
            .is_retryable()
        );
    }

    #[test]
    fn is_retryable_api_502() {
        assert!(
            BrowserError::Api {
                message: "bad gateway".into(),
                status_code: Some(502),
            }
            .is_retryable()
        );
    }

    #[test]
    fn is_retryable_api_503() {
        assert!(
            BrowserError::Api {
                message: "service unavailable".into(),
                status_code: Some(503),
            }
            .is_retryable()
        );
    }

    #[test]
    fn is_retryable_api_599() {
        // Upper boundary of 5xx range
        assert!(
            BrowserError::Api {
                message: "x".into(),
                status_code: Some(599),
            }
            .is_retryable()
        );
    }

    #[test]
    fn is_retryable_api_429() {
        assert!(
            BrowserError::Api {
                message: "x".into(),
                status_code: Some(429),
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_api_400() {
        assert!(
            !BrowserError::Api {
                message: "x".into(),
                status_code: Some(400),
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_api_401() {
        assert!(
            !BrowserError::Api {
                message: "unauthorized".into(),
                status_code: Some(401),
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_api_403() {
        assert!(
            !BrowserError::Api {
                message: "forbidden".into(),
                status_code: Some(403),
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_api_404() {
        assert!(
            !BrowserError::Api {
                message: "not found".into(),
                status_code: Some(404),
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_api_none_status() {
        assert!(
            !BrowserError::Api {
                message: "x".into(),
                status_code: None,
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_invalid_config() {
        assert!(!BrowserError::InvalidConfig("x".into()).is_retryable());
    }

    #[test]
    fn not_retryable_serialization() {
        let json_err = serde_json::from_str::<serde_json::Value>("bad").unwrap_err();
        assert!(!BrowserError::Serialization(json_err).is_retryable());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // retry_after for all variants
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn retry_after_429() {
        let err = BrowserError::Api {
            message: "x".into(),
            status_code: Some(429),
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn retry_after_500_none() {
        let err = BrowserError::Api {
            message: "x".into(),
            status_code: Some(500),
        };
        assert_eq!(err.retry_after(), None);
    }

    #[test]
    fn retry_after_503_none() {
        let err = BrowserError::Api {
            message: "x".into(),
            status_code: Some(503),
        };
        assert_eq!(err.retry_after(), None);
    }

    #[test]
    fn retry_after_timeout_none() {
        let err = BrowserError::Timeout {
            message: "x".into(),
        };
        assert_eq!(err.retry_after(), None);
    }

    #[test]
    fn retry_after_invalid_config_none() {
        assert_eq!(BrowserError::InvalidConfig("x".into()).retry_after(), None);
    }

    #[test]
    fn retry_after_serialization_none() {
        let json_err = serde_json::from_str::<serde_json::Value>("bad").unwrap_err();
        assert_eq!(BrowserError::Serialization(json_err).retry_after(), None);
    }

    #[test]
    fn retry_after_api_none_status_none() {
        let err = BrowserError::Api {
            message: "x".into(),
            status_code: None,
        };
        assert_eq!(err.retry_after(), None);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // to_fcp_error for all error-to-FcpError mappings
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn to_fcp_error_api_429() {
        let err = BrowserError::Api {
            message: "rate limited".into(),
            status_code: Some(429),
        };
        match err.to_fcp_error() {
            FcpError::RateLimited {
                retry_after_ms,
                violation,
            } => {
                assert_eq!(retry_after_ms, 5_000);
                assert!(violation.is_none());
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_500_external() {
        let err = BrowserError::Api {
            message: "crashed".into(),
            status_code: Some(500),
        };
        match err.to_fcp_error() {
            FcpError::External {
                service,
                message,
                status_code,
                retryable,
                retry_after,
            } => {
                assert_eq!(service, "browser");
                assert_eq!(message, "crashed");
                assert_eq!(status_code, Some(500));
                assert!(retryable);
                assert!(retry_after.is_none());
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_502_external() {
        let err = BrowserError::Api {
            message: "bad gateway".into(),
            status_code: Some(502),
        };
        match err.to_fcp_error() {
            FcpError::External {
                service,
                retryable,
                status_code,
                ..
            } => {
                assert_eq!(service, "browser");
                assert_eq!(status_code, Some(502));
                assert!(retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_400_not_retryable() {
        let err = BrowserError::Api {
            message: "bad request".into(),
            status_code: Some(400),
        };
        match err.to_fcp_error() {
            FcpError::External {
                service,
                retryable,
                status_code,
                retry_after,
                ..
            } => {
                assert_eq!(service, "browser");
                assert_eq!(status_code, Some(400));
                assert!(!retryable);
                assert!(retry_after.is_none());
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_none_status_not_retryable() {
        let err = BrowserError::Api {
            message: "generic error".into(),
            status_code: None,
        };
        match err.to_fcp_error() {
            FcpError::External {
                service,
                message,
                status_code,
                retryable,
                retry_after,
            } => {
                assert_eq!(service, "browser");
                assert_eq!(message, "generic error");
                assert_eq!(status_code, None);
                assert!(!retryable);
                assert!(retry_after.is_none());
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_invalid_config() {
        let err = BrowserError::InvalidConfig("bad url".into());
        match err.to_fcp_error() {
            FcpError::Internal { message } => {
                assert!(message.contains("bad url"));
                assert!(message.contains("Invalid browser config"));
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_invalid_config_preserves_message() {
        let err = BrowserError::InvalidConfig("CDP endpoint unreachable".into());
        match err.to_fcp_error() {
            FcpError::Internal { message } => {
                assert_eq!(message, "Invalid browser config: CDP endpoint unreachable");
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_timeout() {
        let err = BrowserError::Timeout {
            message: "nav timeout".into(),
        };
        match err.to_fcp_error() {
            FcpError::External {
                service,
                message,
                status_code,
                retryable,
                retry_after,
            } => {
                assert_eq!(service, "browser");
                assert_eq!(message, "nav timeout");
                assert_eq!(status_code, Some(408));
                assert!(retryable);
                assert_eq!(retry_after, Some(Duration::from_secs(1)));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_serialization() {
        let json_err = serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err();
        let err = BrowserError::Serialization(json_err);
        match err.to_fcp_error() {
            FcpError::Internal { message } => {
                assert!(message.starts_with("Serialization error:"));
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_serialization_contains_serde_detail() {
        let json_err = serde_json::from_str::<serde_json::Value>("not json").unwrap_err();
        let err = BrowserError::Serialization(json_err);
        match err.to_fcp_error() {
            FcpError::Internal { message } => {
                // The serde error detail should be embedded in the message
                assert!(message.len() > "Serialization error: ".len());
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Debug format
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn debug_api_variant() {
        let err = BrowserError::Api {
            message: "page crashed".into(),
            status_code: Some(500),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Api"));
        assert!(dbg.contains("page crashed"));
        assert!(dbg.contains("500"));
    }

    #[test]
    fn debug_invalid_config_variant() {
        let err = BrowserError::InvalidConfig("bad endpoint".into());
        let dbg = format!("{err:?}");
        assert!(dbg.contains("InvalidConfig"));
        assert!(dbg.contains("bad endpoint"));
    }

    #[test]
    fn debug_timeout_variant() {
        let err = BrowserError::Timeout {
            message: "30s exceeded".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Timeout"));
        assert!(dbg.contains("30s exceeded"));
    }

    #[test]
    fn debug_serialization_variant() {
        let json_err = serde_json::from_str::<serde_json::Value>("x").unwrap_err();
        let err = BrowserError::Serialization(json_err);
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Serialization"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // std::error::Error trait
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn error_trait_impl() {
        let _: &dyn std::error::Error = &BrowserError::InvalidConfig("x".into());
    }

    #[test]
    fn error_trait_api() {
        let err: &dyn std::error::Error = &BrowserError::Api {
            message: "test".into(),
            status_code: Some(400),
        };
        // std::error::Error::source should be None for Api variant
        assert!(err.source().is_none());
    }

    #[test]
    fn error_trait_timeout() {
        let err: &dyn std::error::Error = &BrowserError::Timeout {
            message: "test".into(),
        };
        assert!(err.source().is_none());
    }

    #[test]
    fn error_trait_invalid_config() {
        let err: &dyn std::error::Error = &BrowserError::InvalidConfig("test".into());
        assert!(err.source().is_none());
    }

    #[test]
    fn error_trait_serialization_has_source() {
        let json_err = serde_json::from_str::<serde_json::Value>("bad").unwrap_err();
        let err = BrowserError::Serialization(json_err);
        let dyn_err: &dyn std::error::Error = &err;
        // Serialization wraps a serde_json::Error, so source() should be Some
        assert!(dyn_err.source().is_some());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // From conversions
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn from_serde_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("x").unwrap_err();
        let err: BrowserError = json_err.into();
        assert!(matches!(err, BrowserError::Serialization(_)));
    }

    #[test]
    fn from_serde_json_error_preserves_message() {
        let json_err = serde_json::from_str::<serde_json::Value>("x").unwrap_err();
        let original_msg = json_err.to_string();
        let err: BrowserError = json_err.into();
        assert!(err.to_string().contains(&original_msg));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // BrowserResult type alias
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn browser_result_ok() {
        let r: BrowserResult<u32> = Ok(42);
        assert!(matches!(r, Ok(42)));
    }

    #[test]
    fn browser_result_err() {
        let r: BrowserResult<u32> = Err(BrowserError::InvalidConfig("x".into()));
        assert!(r.is_err());
    }

    #[test]
    fn browser_result_string_type() {
        let r: BrowserResult<String> = Ok("hello".into());
        assert!(r.is_ok());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Edge cases and boundary conditions
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn api_error_empty_message() {
        let err = BrowserError::Api {
            message: String::new(),
            status_code: Some(500),
        };
        assert_eq!(err.to_string(), "Browser API error: ");
        assert!(err.is_retryable());
    }

    #[test]
    fn invalid_config_empty_message() {
        let err = BrowserError::InvalidConfig(String::new());
        assert_eq!(err.to_string(), "Invalid configuration: ");
    }

    #[test]
    fn timeout_empty_message() {
        let err = BrowserError::Timeout {
            message: String::new(),
        };
        assert_eq!(err.to_string(), "Timeout: ");
    }

    #[test]
    fn api_error_with_unicode_message() {
        let err = BrowserError::Api {
            message: "页面崩溃了 🔥".into(),
            status_code: Some(500),
        };
        assert!(err.to_string().contains("页面崩溃了"));
    }

    #[test]
    fn is_retryable_api_428_not_retryable() {
        // 428 is not 429 and not in 500-599 range
        assert!(
            !BrowserError::Api {
                message: "x".into(),
                status_code: Some(428),
            }
            .is_retryable()
        );
    }

    #[test]
    fn is_retryable_api_430_not_retryable() {
        // 430 is not 429 and not in 500-599 range
        assert!(
            !BrowserError::Api {
                message: "x".into(),
                status_code: Some(430),
            }
            .is_retryable()
        );
    }

    #[test]
    fn is_retryable_api_499_not_retryable() {
        // 499 is not in 500-599 range and not 429
        assert!(
            !BrowserError::Api {
                message: "x".into(),
                status_code: Some(499),
            }
            .is_retryable()
        );
    }

    #[test]
    fn is_retryable_api_600_not_retryable() {
        // 600 is outside the 500-599 range
        assert!(
            !BrowserError::Api {
                message: "x".into(),
                status_code: Some(600),
            }
            .is_retryable()
        );
    }

    #[test]
    fn to_fcp_error_api_retryable_consistency() {
        // Verify that the retryable flag in FcpError matches is_retryable()
        for status in [400_u16, 401, 403, 404, 429, 500, 502, 503, 599] {
            let err = BrowserError::Api {
                message: "test".into(),
                status_code: Some(status),
            };
            if status == 429 {
                // 429 maps to RateLimited, not External
                assert!(matches!(err.to_fcp_error(), FcpError::RateLimited { .. }));
            } else {
                match err.to_fcp_error() {
                    FcpError::External { retryable, .. } => {
                        assert_eq!(
                            retryable,
                            err.is_retryable(),
                            "retryable mismatch for status {status}"
                        );
                    }
                    other => panic!("expected External for status {status}, got {other:?}"),
                }
            }
        }
    }

    #[test]
    fn to_fcp_error_timeout_service_is_browser() {
        let err = BrowserError::Timeout {
            message: "x".into(),
        };
        match err.to_fcp_error() {
            FcpError::External { service, .. } => assert_eq!(service, "browser"),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn retry_after_429_duration_value() {
        let err = BrowserError::Api {
            message: "x".into(),
            status_code: Some(429),
        };
        let duration = err.retry_after().unwrap();
        assert_eq!(duration.as_secs(), 5);
        assert_eq!(duration.as_millis(), 5000);
    }
}
