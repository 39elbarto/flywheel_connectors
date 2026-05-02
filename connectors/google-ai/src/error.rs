//! Google AI-specific error types.

use std::time::Duration;

use fcp_prelude::FcpError;

/// Google AI API error.
#[derive(Debug, thiserror::Error)]
pub enum GoogleAiError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Google AI API error: {message}")]
    Api {
        message: String,
        status_code: Option<u16>,
        error_type: Option<String>,
    },

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Rate limited")]
    RateLimit { retry_after_ms: u64 },
}

pub type GoogleAiResult<T> = Result<T, GoogleAiError>;

impl GoogleAiError {
    /// Check if this error is retryable.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::RateLimit { .. } => true,
            Self::Api { status_code, .. } => matches!(status_code, Some(500..=599 | 429)),
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
                service: "google-ai".into(),
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
                        service: "google-ai".into(),
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

impl fcp_sdk::migration::ConnectorErrorMapping for GoogleAiError {
    fn from_async_error(error: fcp_async_core::AsyncError) -> Self {
        use fcp_async_core::AsyncError;
        match error {
            AsyncError::Timeout { timeout_ms } => Self::Api {
                message: format!("deadline exceeded after {timeout_ms}ms"),
                status_code: Some(408),
                error_type: None,
            },
            AsyncError::Cancelled => Self::Api {
                message: "request cancelled".into(),
                status_code: None,
                error_type: None,
            },
            other => Self::Api {
                message: other.to_string(),
                status_code: None,
                error_type: None,
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

    // ── Display messages ──────────────────────────────────────────────

    #[test]
    fn display_http_error() {
        // We cannot easily construct a reqwest::Error directly, but we can
        // verify the Display impl via a serialization error converted to Http
        // indirectly. Instead, test the format string pattern.
        let err = GoogleAiError::InvalidConfig("test".into());
        let display = format!("{err}");
        assert!(display.starts_with("Invalid configuration:"));
    }

    #[test]
    fn display_serialization_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err();
        let err = GoogleAiError::Serialization(json_err);
        let display = err.to_string();
        assert!(display.starts_with("Serialization error:"));
    }

    #[test]
    fn display_api() {
        let err = GoogleAiError::Api {
            message: "model not found".into(),
            status_code: Some(404),
            error_type: Some("NOT_FOUND".into()),
        };
        let display = err.to_string();
        assert!(display.contains("model not found"));
        assert!(display.starts_with("Google AI API error:"));
    }

    #[test]
    fn display_api_no_optional_fields() {
        let err = GoogleAiError::Api {
            message: "something went wrong".into(),
            status_code: None,
            error_type: None,
        };
        assert_eq!(err.to_string(), "Google AI API error: something went wrong");
    }

    #[test]
    fn display_invalid_config() {
        let err = GoogleAiError::InvalidConfig("missing API key".into());
        assert_eq!(err.to_string(), "Invalid configuration: missing API key");
    }

    #[test]
    fn display_rate_limit() {
        let err = GoogleAiError::RateLimit {
            retry_after_ms: 5000,
        };
        assert_eq!(err.to_string(), "Rate limited");
    }

    // ── is_retryable ──────────────────────────────────────────────────

    #[test]
    fn is_retryable_rate_limit() {
        assert!(
            GoogleAiError::RateLimit {
                retry_after_ms: 1000
            }
            .is_retryable()
        );
    }

    #[test]
    fn is_retryable_api_429() {
        assert!(
            GoogleAiError::Api {
                message: "rate limited".into(),
                status_code: Some(429),
                error_type: None,
            }
            .is_retryable()
        );
    }

    #[test]
    fn is_retryable_api_500() {
        assert!(
            GoogleAiError::Api {
                message: "x".into(),
                status_code: Some(500),
                error_type: None,
            }
            .is_retryable()
        );
    }

    #[test]
    fn is_retryable_api_502() {
        assert!(
            GoogleAiError::Api {
                message: "bad gateway".into(),
                status_code: Some(502),
                error_type: None,
            }
            .is_retryable()
        );
    }

    #[test]
    fn is_retryable_api_503() {
        assert!(
            GoogleAiError::Api {
                message: "service unavailable".into(),
                status_code: Some(503),
                error_type: None,
            }
            .is_retryable()
        );
    }

    #[test]
    fn is_retryable_api_599() {
        assert!(
            GoogleAiError::Api {
                message: "x".into(),
                status_code: Some(599),
                error_type: None,
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_api_400() {
        assert!(
            !GoogleAiError::Api {
                message: "x".into(),
                status_code: Some(400),
                error_type: None,
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_api_401() {
        assert!(
            !GoogleAiError::Api {
                message: "x".into(),
                status_code: Some(401),
                error_type: None,
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_api_403() {
        assert!(
            !GoogleAiError::Api {
                message: "x".into(),
                status_code: Some(403),
                error_type: None,
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_api_404() {
        assert!(
            !GoogleAiError::Api {
                message: "x".into(),
                status_code: Some(404),
                error_type: None,
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_api_none_status() {
        assert!(
            !GoogleAiError::Api {
                message: "x".into(),
                status_code: None,
                error_type: None,
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_invalid_config() {
        assert!(!GoogleAiError::InvalidConfig("x".into()).is_retryable());
    }

    #[test]
    fn not_retryable_serialization() {
        let json_err = serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err();
        assert!(!GoogleAiError::Serialization(json_err).is_retryable());
    }

    // ── retry_after ───────────────────────────────────────────────────

    #[test]
    fn retry_after_rate_limit() {
        let err = GoogleAiError::RateLimit {
            retry_after_ms: 5000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn retry_after_rate_limit_zero() {
        let err = GoogleAiError::RateLimit { retry_after_ms: 0 };
        assert_eq!(err.retry_after(), Some(Duration::from_millis(0)));
    }

    #[test]
    fn retry_after_rate_limit_large_value() {
        let err = GoogleAiError::RateLimit {
            retry_after_ms: 120_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(120)));
    }

    #[test]
    fn retry_after_api_is_none() {
        let err = GoogleAiError::Api {
            message: "x".into(),
            status_code: Some(500),
            error_type: None,
        };
        assert_eq!(err.retry_after(), None);
    }

    #[test]
    fn retry_after_http_is_none() {
        // InvalidConfig is not Http, but we can at least verify non-RateLimit returns None
        assert_eq!(GoogleAiError::InvalidConfig("x".into()).retry_after(), None);
    }

    #[test]
    fn retry_after_serialization_is_none() {
        let json_err = serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err();
        assert_eq!(GoogleAiError::Serialization(json_err).retry_after(), None);
    }

    // ── to_fcp_error: Http variant ────────────────────────────────────

    // Note: reqwest::Error can't be directly constructed. We test Http
    // through the from_reqwest_error integration path in client tests.
    // Here we cover all other to_fcp_error paths.

    // ── to_fcp_error: Serialization → Internal ────────────────────────

    #[test]
    fn to_fcp_error_serialization() {
        let json_err = serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err();
        let err = GoogleAiError::Serialization(json_err);
        match err.to_fcp_error() {
            FcpError::Internal { message } => {
                assert!(message.starts_with("Serialization error:"));
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_serialization_preserves_detail() {
        let json_err = serde_json::from_str::<serde_json::Value>("not json at all").unwrap_err();
        let err = GoogleAiError::Serialization(json_err);
        match err.to_fcp_error() {
            FcpError::Internal { message } => {
                assert!(message.contains("Serialization error:"));
                // The serde_json error message should be embedded
                assert!(message.len() > "Serialization error: ".len());
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    // ── to_fcp_error: Api 401 → Unauthorized ──────────────────────────

    #[test]
    fn to_fcp_error_api_401() {
        let err = GoogleAiError::Api {
            message: "bad key".into(),
            status_code: Some(401),
            error_type: None,
        };
        match err.to_fcp_error() {
            FcpError::Unauthorized { code, message } => {
                assert_eq!(code, 2001);
                assert_eq!(message, "bad key");
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    // ── to_fcp_error: Api 403 → Unauthorized ──────────────────────────

    #[test]
    fn to_fcp_error_api_403() {
        let err = GoogleAiError::Api {
            message: "forbidden".into(),
            status_code: Some(403),
            error_type: Some("PERMISSION_DENIED".into()),
        };
        match err.to_fcp_error() {
            FcpError::Unauthorized { code, message } => {
                assert_eq!(code, 2001);
                assert_eq!(message, "forbidden");
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    // ── to_fcp_error: Api 429 → RateLimited ──────────────────────────

    #[test]
    fn to_fcp_error_api_429() {
        let err = GoogleAiError::Api {
            message: "rate limited".into(),
            status_code: Some(429),
            error_type: None,
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

    // ── to_fcp_error: Api 500 → External (retryable) ─────────────────

    #[test]
    fn to_fcp_error_api_500() {
        let err = GoogleAiError::Api {
            message: "internal".into(),
            status_code: Some(500),
            error_type: None,
        };
        match err.to_fcp_error() {
            FcpError::External {
                service,
                message,
                status_code,
                retryable,
                retry_after,
            } => {
                assert_eq!(service, "google-ai");
                assert_eq!(message, "internal");
                assert_eq!(status_code, Some(500));
                assert!(retryable);
                assert!(retry_after.is_none());
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    // ── to_fcp_error: Api 502 → External (retryable) ─────────────────

    #[test]
    fn to_fcp_error_api_502() {
        let err = GoogleAiError::Api {
            message: "bad gateway".into(),
            status_code: Some(502),
            error_type: None,
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

    // ── to_fcp_error: Api 400 → External (not retryable) ─────────────

    #[test]
    fn to_fcp_error_api_400() {
        let err = GoogleAiError::Api {
            message: "bad request".into(),
            status_code: Some(400),
            error_type: Some("INVALID_ARGUMENT".into()),
        };
        match err.to_fcp_error() {
            FcpError::External {
                service,
                message,
                status_code,
                retryable,
                retry_after,
            } => {
                assert_eq!(service, "google-ai");
                assert_eq!(message, "bad request");
                assert_eq!(status_code, Some(400));
                assert!(!retryable);
                assert!(retry_after.is_none());
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    // ── to_fcp_error: Api 404 → External (not retryable) ─────────────

    #[test]
    fn to_fcp_error_api_404() {
        let err = GoogleAiError::Api {
            message: "not found".into(),
            status_code: Some(404),
            error_type: Some("NOT_FOUND".into()),
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

    // ── to_fcp_error: Api with no status → External (not retryable) ──

    #[test]
    fn to_fcp_error_api_no_status() {
        let err = GoogleAiError::Api {
            message: "unknown".into(),
            status_code: None,
            error_type: None,
        };
        match err.to_fcp_error() {
            FcpError::External {
                service,
                message,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "google-ai");
                assert_eq!(message, "unknown");
                assert!(status_code.is_none());
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    // ── to_fcp_error: InvalidConfig → InvalidRequest ──────────────────

    #[test]
    fn to_fcp_error_invalid_config() {
        let err = GoogleAiError::InvalidConfig("missing key".into());
        match err.to_fcp_error() {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1003);
                assert_eq!(message, "missing key");
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_invalid_config_empty_message() {
        let err = GoogleAiError::InvalidConfig(String::new());
        match err.to_fcp_error() {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1003);
                assert!(message.is_empty());
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    // ── to_fcp_error: RateLimit → RateLimited ─────────────────────────

    #[test]
    fn to_fcp_error_rate_limit() {
        let err = GoogleAiError::RateLimit {
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
    fn to_fcp_error_rate_limit_zero_delay() {
        let err = GoogleAiError::RateLimit { retry_after_ms: 0 };
        match err.to_fcp_error() {
            FcpError::RateLimited { retry_after_ms, .. } => assert_eq!(retry_after_ms, 0),
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    // ── From impls ────────────────────────────────────────────────────

    #[test]
    fn from_serde_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("x").unwrap_err();
        let err: GoogleAiError = json_err.into();
        assert!(matches!(err, GoogleAiError::Serialization(_)));
    }

    #[test]
    fn from_serde_json_error_eof() {
        let json_err = serde_json::from_str::<serde_json::Value>("").unwrap_err();
        let err: GoogleAiError = json_err.into();
        assert!(matches!(err, GoogleAiError::Serialization(_)));
        assert!(!err.is_retryable());
    }

    // ── GoogleAiResult type alias ─────────────────────────────────────

    #[test]
    fn google_ai_result_ok() {
        let r: GoogleAiResult<u32> = Ok(42);
        assert!(matches!(r, Ok(42)));
    }

    #[test]
    fn google_ai_result_err() {
        let r: GoogleAiResult<u32> = Err(GoogleAiError::InvalidConfig("bad".into()));
        assert!(matches!(r, Err(GoogleAiError::InvalidConfig(_))));
    }

    // ── Debug format ──────────────────────────────────────────────────

    #[test]
    fn debug_format_api() {
        let err = GoogleAiError::Api {
            message: "oops".into(),
            status_code: Some(500),
            error_type: Some("INTERNAL".into()),
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("Api"));
        assert!(debug.contains("oops"));
        assert!(debug.contains("500"));
        assert!(debug.contains("INTERNAL"));
    }

    #[test]
    fn debug_format_invalid_config() {
        let err = GoogleAiError::InvalidConfig("bad config".into());
        let debug = format!("{err:?}");
        assert!(debug.contains("InvalidConfig"));
        assert!(debug.contains("bad config"));
    }

    #[test]
    fn debug_format_rate_limit() {
        let err = GoogleAiError::RateLimit {
            retry_after_ms: 3000,
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("RateLimit"));
        assert!(debug.contains("3000"));
    }

    #[test]
    fn debug_format_serialization() {
        let json_err = serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err();
        let err = GoogleAiError::Serialization(json_err);
        let debug = format!("{err:?}");
        assert!(debug.contains("Serialization"));
    }

    // ── std::error::Error trait ───────────────────────────────────────

    #[test]
    fn error_trait_impl_invalid_config() {
        let err: &dyn std::error::Error = &GoogleAiError::InvalidConfig("x".into());
        // source() should be None for string-based variants
        assert!(err.source().is_none());
    }

    #[test]
    fn error_trait_impl_api() {
        let err: &dyn std::error::Error = &GoogleAiError::Api {
            message: "x".into(),
            status_code: None,
            error_type: None,
        };
        assert!(err.source().is_none());
    }

    #[test]
    fn error_trait_impl_rate_limit() {
        let err: &dyn std::error::Error = &GoogleAiError::RateLimit {
            retry_after_ms: 1000,
        };
        assert!(err.source().is_none());
    }

    #[test]
    fn error_trait_impl_serialization_has_source() {
        let json_err = serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err();
        let err = GoogleAiError::Serialization(json_err);
        let dyn_err: &dyn std::error::Error = &err;
        // Serialization wraps a serde_json::Error, so source() should be Some
        assert!(dyn_err.source().is_some());
    }

    #[test]
    fn error_trait_can_be_boxed() {
        let err = GoogleAiError::InvalidConfig("test".into());
        let boxed: Box<dyn std::error::Error> = Box::new(err);
        assert!(boxed.to_string().contains("test"));
    }

    #[test]
    fn error_trait_can_be_boxed_send_sync() {
        let err = GoogleAiError::InvalidConfig("test".into());
        let _: Box<dyn std::error::Error + Send + Sync> = Box::new(err);
    }

    // ── ConnectorErrorMapping ────────────────────────────────────────

    #[test]
    fn connector_error_mapping_timeout() {
        use fcp_async_core::AsyncError;
        use fcp_sdk::migration::ConnectorErrorMapping;
        let err = GoogleAiError::from_async_error(AsyncError::Timeout { timeout_ms: 3000 });
        assert!(matches!(
            err,
            GoogleAiError::Api {
                status_code: Some(408),
                ..
            }
        ));
        assert!(err.to_string().contains("3000"));
    }

    #[test]
    fn connector_error_mapping_cancelled() {
        use fcp_async_core::AsyncError;
        use fcp_sdk::migration::ConnectorErrorMapping;
        let err = GoogleAiError::from_async_error(AsyncError::Cancelled);
        assert!(matches!(
            err,
            GoogleAiError::Api {
                status_code: None,
                ..
            }
        ));
    }

    #[test]
    fn connector_error_mapping_channel_closed() {
        use fcp_async_core::AsyncError;
        use fcp_sdk::migration::ConnectorErrorMapping;
        let err = GoogleAiError::from_async_error(AsyncError::ChannelClosed);
        assert!(matches!(err, GoogleAiError::Api { .. }));
    }

    #[test]
    fn connector_error_mapping_runtime_error() {
        use fcp_async_core::AsyncError;
        use fcp_sdk::migration::ConnectorErrorMapping;
        let err = GoogleAiError::from_async_error(AsyncError::Runtime {
            message: "runtime panic".into(),
        });
        assert!(matches!(err, GoogleAiError::Api { .. }));
        assert!(err.to_string().contains("runtime"));
    }

    #[test]
    fn connector_error_mapping_to_fcp_delegates() {
        use fcp_sdk::migration::ConnectorErrorMapping;
        let err = GoogleAiError::InvalidConfig("bad".into());
        let fcp = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp, FcpError::InvalidRequest { code: 1003, .. }));
    }

    #[test]
    fn connector_error_mapping_is_retryable_delegates() {
        use fcp_sdk::migration::ConnectorErrorMapping;
        let err = GoogleAiError::RateLimit {
            retry_after_ms: 1000,
        };
        assert!(ConnectorErrorMapping::is_retryable(&err));
    }

    #[test]
    fn connector_error_mapping_retry_after_delegates() {
        use fcp_sdk::migration::ConnectorErrorMapping;
        let err = GoogleAiError::RateLimit {
            retry_after_ms: 5000,
        };
        assert_eq!(
            ConnectorErrorMapping::retry_after(&err),
            Some(Duration::from_secs(5))
        );
    }

    // ── Additional coverage ─────────────────────────────────────────

    #[test]
    fn to_fcp_error_api_503() {
        let err = GoogleAiError::Api {
            message: "service unavailable".into(),
            status_code: Some(503),
            error_type: None,
        };
        match err.to_fcp_error() {
            FcpError::External {
                retryable,
                status_code,
                service,
                ..
            } => {
                assert!(retryable);
                assert_eq!(status_code, Some(503));
                assert_eq!(service, "google-ai");
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_rate_limit_large_value() {
        let err = GoogleAiError::RateLimit {
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
    fn is_retryable_api_504() {
        assert!(
            GoogleAiError::Api {
                message: "gateway timeout".into(),
                status_code: Some(504),
                error_type: None,
            }
            .is_retryable()
        );
    }

    #[test]
    fn display_rate_limit_is_generic() {
        // The display string is just "Rate limited" regardless of retry_after_ms value
        let err1 = GoogleAiError::RateLimit {
            retry_after_ms: 100,
        };
        let err2 = GoogleAiError::RateLimit {
            retry_after_ms: 99_999,
        };
        assert_eq!(err1.to_string(), err2.to_string());
    }

    #[test]
    fn api_error_long_message_preserved() {
        let long_msg = "m".repeat(10_000);
        let err = GoogleAiError::Api {
            message: long_msg.clone(),
            status_code: Some(500),
            error_type: None,
        };
        assert!(err.to_string().contains(&long_msg));
    }

    #[test]
    fn invalid_config_empty_is_valid() {
        let err = GoogleAiError::InvalidConfig(String::new());
        assert_eq!(err.to_string(), "Invalid configuration: ");
        assert!(!err.is_retryable());
        assert!(err.retry_after().is_none());
    }

    // ── Edge cases ────────────────────────────────────────────────────

    #[test]
    fn api_error_with_empty_message() {
        let err = GoogleAiError::Api {
            message: String::new(),
            status_code: Some(400),
            error_type: None,
        };
        assert_eq!(err.to_string(), "Google AI API error: ");
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_error_boundary_499_not_retryable() {
        let err = GoogleAiError::Api {
            message: "x".into(),
            status_code: Some(499),
            error_type: None,
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_error_boundary_600_not_retryable() {
        // 600 is outside the 500..=599 range
        let err = GoogleAiError::Api {
            message: "x".into(),
            status_code: Some(600),
            error_type: None,
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn to_fcp_error_api_429_has_fixed_retry() {
        // Api variant with 429 always returns 60_000ms retry, regardless of error message
        let err = GoogleAiError::Api {
            message: "anything".into(),
            status_code: Some(429),
            error_type: Some("RESOURCE_EXHAUSTED".into()),
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
}
