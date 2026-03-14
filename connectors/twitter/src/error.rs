//! Twitter-specific error types.

use std::time::Duration;

use fcp_core::FcpError;
use thiserror::Error;

/// Twitter-specific errors.
#[derive(Error, Debug)]
pub enum TwitterError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// OAuth signature generation failed
    #[error("OAuth error: {0}")]
    OAuth(String),

    /// Twitter API returned an error
    #[error("Twitter API error {status}: {message}")]
    Api {
        status: u16,
        message: String,
        error_code: Option<i32>,
        retry_after: Option<u64>,
    },

    /// Rate limited
    #[error("Rate limited, retry after {retry_after} seconds")]
    RateLimited { retry_after: u64 },

    /// Stream error
    #[error("Stream error: {0}")]
    Stream(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Not configured
    #[error("Connector not configured")]
    NotConfigured,
}

impl TwitterError {
    /// Check if this error is retryable.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) => true,
            Self::Api { status, .. } => *status >= 500 || *status == 429 || *status == 503,
            Self::RateLimited { .. } => true,
            Self::Stream(_) => true,
            _ => false,
        }
    }

    /// Get the suggested retry delay.
    #[must_use]
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after } => Some(Duration::from_secs(*retry_after)),
            Self::Api { retry_after, .. } => retry_after.map(Duration::from_secs),
            _ => None,
        }
    }

    /// Convert to FCP error.
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Http(e) => FcpError::External {
                service: "twitter".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
            Self::OAuth(msg) => FcpError::Unauthorized {
                code: 2001,
                message: format!("OAuth error: {msg}"),
            },
            Self::Api {
                status,
                message,
                retry_after,
                ..
            } => {
                if *status == 429 {
                    FcpError::RateLimited {
                        retry_after_ms: retry_after.unwrap_or(60) * 1000,
                        violation: None,
                    }
                } else if *status == 401 {
                    FcpError::Unauthorized {
                        code: 2001,
                        message: message.clone(),
                    }
                } else if *status == 403 {
                    FcpError::CapabilityDenied {
                        capability: "twitter.api".into(),
                        reason: message.clone(),
                    }
                } else {
                    FcpError::External {
                        service: "twitter".into(),
                        message: message.clone(),
                        status_code: Some(*status),
                        retryable: self.is_retryable(),
                        retry_after: self.retry_after(),
                    }
                }
            }
            Self::RateLimited { retry_after } => FcpError::RateLimited {
                retry_after_ms: retry_after * 1000,
                violation: None,
            },
            Self::Stream(msg) => FcpError::ConnectorUnavailable {
                code: 5001,
                message: format!("Twitter stream error: {msg}"),
            },
            Self::Config(msg) => FcpError::ConnectorUnavailable {
                code: 5001,
                message: format!("Configuration error: {msg}"),
            },
            Self::NotConfigured => FcpError::NotConfigured,
        }
    }
}

impl fcp_sdk::migration::ConnectorErrorMapping for TwitterError {
    fn from_async_error(error: fcp_async_core::AsyncError) -> Self {
        use fcp_async_core::AsyncError;
        match error {
            AsyncError::Timeout { timeout_ms } => Self::Api {
                status: 408,
                message: format!("deadline exceeded after {timeout_ms}ms"),
                error_code: None,
                retry_after: None,
            },
            AsyncError::Cancelled => Self::Stream("request cancelled".into()),
            AsyncError::ChannelClosed
            | AsyncError::ChannelFull
            | AsyncError::ProtocolIo { .. }
            | AsyncError::Join { .. }
            | AsyncError::Runtime { .. } => Self::Stream(error.to_string()),
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

/// Result type for Twitter operations.
pub type TwitterResult<T> = Result<T, TwitterError>;

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_core::FcpError;

    #[test]
    fn test_api_error_maps_to_capability_denied() {
        let err = TwitterError::Api {
            status: 403,
            message: "forbidden".into(),
            error_code: None,
            retry_after: None,
        };

        let fcp = err.to_fcp_error();
        assert!(matches!(
            fcp,
            FcpError::CapabilityDenied {
                capability,
                reason
            } if capability == "twitter.api" && reason == "forbidden"
        ));
    }

    #[test]
    fn test_api_error_maps_to_unauthorized() {
        let err = TwitterError::Api {
            status: 401,
            message: "unauthorized".into(),
            error_code: None,
            retry_after: None,
        };

        let fcp = err.to_fcp_error();
        assert!(matches!(
            fcp,
            FcpError::Unauthorized { code: 2001, message }
                if message == "unauthorized"
        ));
    }

    #[test]
    fn test_api_error_maps_to_rate_limited() {
        let err = TwitterError::Api {
            status: 429,
            message: "rate limited".into(),
            error_code: None,
            retry_after: Some(5),
        };

        let fcp = err.to_fcp_error();
        assert!(matches!(
            fcp,
            FcpError::RateLimited {
                retry_after_ms: 5000,
                violation: None
            }
        ));
    }

    #[test]
    fn test_api_error_maps_to_external() {
        let err = TwitterError::Api {
            status: 500,
            message: "server error".into(),
            error_code: None,
            retry_after: None,
        };

        let fcp = err.to_fcp_error();
        assert!(matches!(
            fcp,
            FcpError::External {
                service,
                message,
                status_code: Some(500),
                retryable: true,
                retry_after: None
            } if service == "twitter" && message == "server error"
        ));
    }

    #[test]
    fn test_stream_error_maps_to_connector_unavailable() {
        let err = TwitterError::Stream("connection dropped".into());
        let fcp = err.to_fcp_error();
        assert!(matches!(
            fcp,
            FcpError::ConnectorUnavailable { code: 5001, message }
                if message.contains("stream error")
        ));
    }

    #[test]
    fn test_config_error_maps_to_connector_unavailable() {
        let err = TwitterError::Config("missing bearer token".into());
        let fcp = err.to_fcp_error();
        assert!(matches!(
            fcp,
            FcpError::ConnectorUnavailable { code: 5001, message }
                if message.contains("Configuration error")
        ));
    }

    #[test]
    fn test_not_configured_maps_to_fcp_not_configured() {
        let err = TwitterError::NotConfigured;
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::NotConfigured));
    }

    #[test]
    fn test_oauth_error_maps_to_unauthorized() {
        let err = TwitterError::OAuth("invalid signature".into());
        let fcp = err.to_fcp_error();
        assert!(matches!(
            fcp,
            FcpError::Unauthorized { code: 2001, message }
                if message.contains("OAuth error")
        ));
    }

    #[test]
    fn test_rate_limited_error_maps_with_correct_ms() {
        let err = TwitterError::RateLimited { retry_after: 30 };
        let fcp = err.to_fcp_error();
        assert!(matches!(
            fcp,
            FcpError::RateLimited {
                retry_after_ms: 30_000,
                violation: None
            }
        ));
    }

    #[test]
    fn test_retryable_checks() {
        // Retryable
        assert!(TwitterError::RateLimited { retry_after: 1 }.is_retryable());
        assert!(TwitterError::Stream("test".into()).is_retryable());
        assert!(
            TwitterError::Api {
                status: 500,
                message: String::new(),
                error_code: None,
                retry_after: None,
            }
            .is_retryable()
        );
        assert!(
            TwitterError::Api {
                status: 429,
                message: String::new(),
                error_code: None,
                retry_after: None,
            }
            .is_retryable()
        );
        assert!(
            TwitterError::Api {
                status: 503,
                message: String::new(),
                error_code: None,
                retry_after: None,
            }
            .is_retryable()
        );

        // Not retryable
        assert!(!TwitterError::NotConfigured.is_retryable());
        assert!(!TwitterError::Config("x".into()).is_retryable());
        assert!(!TwitterError::OAuth("x".into()).is_retryable());
        assert!(
            !TwitterError::Api {
                status: 401,
                message: String::new(),
                error_code: None,
                retry_after: None,
            }
            .is_retryable()
        );
        assert!(
            !TwitterError::Api {
                status: 403,
                message: String::new(),
                error_code: None,
                retry_after: None,
            }
            .is_retryable()
        );
        assert!(
            !TwitterError::Api {
                status: 404,
                message: String::new(),
                error_code: None,
                retry_after: None,
            }
            .is_retryable()
        );
    }

    #[test]
    fn test_retry_after_extraction() {
        // Has retry_after
        assert_eq!(
            TwitterError::RateLimited { retry_after: 60 }
                .retry_after()
                .map(|d| d.as_secs()),
            Some(60)
        );
        assert_eq!(
            TwitterError::Api {
                status: 429,
                message: String::new(),
                error_code: None,
                retry_after: Some(30),
            }
            .retry_after()
            .map(|d| d.as_secs()),
            Some(30)
        );

        // No retry_after
        assert!(TwitterError::NotConfigured.retry_after().is_none());
        assert!(TwitterError::OAuth("x".into()).retry_after().is_none());
        assert!(TwitterError::Stream("x".into()).retry_after().is_none());
        assert!(TwitterError::Config("x".into()).retry_after().is_none());
    }

    #[test]
    fn test_api_error_without_retry_after() {
        let err = TwitterError::Api {
            status: 429,
            message: "rate limited".into(),
            error_code: None,
            retry_after: None,
        };
        let fcp = err.to_fcp_error();
        // Default 60 seconds when no retry_after is specified
        assert!(matches!(
            fcp,
            FcpError::RateLimited {
                retry_after_ms: 60_000,
                violation: None
            }
        ));
    }

    #[test]
    fn test_json_error_maps_to_internal() {
        let json_err: serde_json::Error =
            serde_json::from_str::<serde_json::Value>("invalid").unwrap_err();
        let err = TwitterError::Json(json_err);
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::Internal { message } if message.contains("JSON error")));
    }

    // ── Display ──────────────────────────────────────────────────────

    #[test]
    fn display_api_error() {
        let err = TwitterError::Api {
            status: 500,
            message: "Internal".into(),
            error_code: Some(131),
            retry_after: None,
        };
        assert_eq!(err.to_string(), "Twitter API error 500: Internal");
    }

    #[test]
    fn display_rate_limited() {
        let err = TwitterError::RateLimited { retry_after: 60 };
        assert_eq!(err.to_string(), "Rate limited, retry after 60 seconds");
    }

    #[test]
    fn display_oauth() {
        let err = TwitterError::OAuth("bad signature".into());
        assert_eq!(err.to_string(), "OAuth error: bad signature");
    }

    #[test]
    fn display_stream() {
        let err = TwitterError::Stream("connection lost".into());
        assert_eq!(err.to_string(), "Stream error: connection lost");
    }

    #[test]
    fn display_config() {
        let err = TwitterError::Config("missing key".into());
        assert_eq!(err.to_string(), "Configuration error: missing key");
    }

    #[test]
    fn display_not_configured() {
        assert_eq!(
            TwitterError::NotConfigured.to_string(),
            "Connector not configured"
        );
    }

    // ── Edge cases ──────────────────────────────────────────────────

    #[test]
    fn api_retry_after_propagates_to_fcp() {
        let err = TwitterError::Api {
            status: 500,
            message: "overloaded".into(),
            error_code: None,
            retry_after: Some(10),
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::External { retry_after, .. } => {
                assert_eq!(retry_after, Some(Duration::from_secs(10)));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn api_no_retry_after_none_in_fcp() {
        let err = TwitterError::Api {
            status: 500,
            message: "error".into(),
            error_code: None,
            retry_after: None,
        };
        assert_eq!(err.retry_after(), None);
    }

    #[test]
    fn debug_format_all_variants() {
        let variants: Vec<TwitterError> = vec![
            TwitterError::OAuth("sig fail".into()),
            TwitterError::Api {
                status: 418,
                message: "teapot".into(),
                error_code: Some(99),
                retry_after: Some(5),
            },
            TwitterError::RateLimited { retry_after: 120 },
            TwitterError::Stream("dropped".into()),
            TwitterError::Config("bad key".into()),
            TwitterError::NotConfigured,
        ];
        for v in &variants {
            let dbg = format!("{v:?}");
            assert!(!dbg.is_empty());
        }
    }

    #[test]
    fn api_error_with_error_code_debug() {
        let err = TwitterError::Api {
            status: 400,
            message: "bad request".into(),
            error_code: Some(88),
            retry_after: None,
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("88"));
        assert!(dbg.contains("bad request"));
    }

    #[test]
    fn rate_limited_retry_after_zero() {
        let err = TwitterError::RateLimited { retry_after: 0 };
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(Duration::from_secs(0)));
        match err.to_fcp_error() {
            FcpError::RateLimited { retry_after_ms, .. } => assert_eq!(retry_after_ms, 0),
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn api_503_is_retryable_and_external() {
        let err = TwitterError::Api {
            status: 503,
            message: "service unavailable".into(),
            error_code: None,
            retry_after: Some(15),
        };
        assert!(err.is_retryable());
        match err.to_fcp_error() {
            FcpError::External {
                service,
                retryable,
                retry_after,
                ..
            } => {
                assert_eq!(service, "twitter");
                assert!(retryable);
                assert_eq!(retry_after, Some(Duration::from_secs(15)));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn api_404_maps_to_external_not_retryable() {
        let err = TwitterError::Api {
            status: 404,
            message: "not found".into(),
            error_code: None,
            retry_after: None,
        };
        assert!(!err.is_retryable());
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
    fn display_json_error() {
        let json_err: serde_json::Error =
            serde_json::from_str::<serde_json::Value>("bad").unwrap_err();
        let err = TwitterError::Json(json_err);
        let display = err.to_string();
        assert!(display.starts_with("JSON error:"));
    }

    #[test]
    fn display_http_contains_prefix() {
        // Cannot easily construct a reqwest::Error, but we test the pattern via Json
        let json_err: serde_json::Error =
            serde_json::from_str::<serde_json::Value>("{invalid}").unwrap_err();
        let err = TwitterError::Json(json_err);
        assert!(!err.is_retryable());
        assert!(err.retry_after().is_none());
    }

    // ── ConnectorErrorMapping ────────────────────────────────────────

    #[test]
    fn connector_error_mapping_timeout() {
        use fcp_async_core::AsyncError;
        use fcp_sdk::migration::ConnectorErrorMapping;
        let err = TwitterError::from_async_error(AsyncError::Timeout { timeout_ms: 5000 });
        assert!(matches!(
            err,
            TwitterError::Api {
                status: 408,
                ..
            }
        ));
        assert!(err.to_string().contains("5000"));
    }

    #[test]
    fn connector_error_mapping_cancelled() {
        use fcp_async_core::AsyncError;
        use fcp_sdk::migration::ConnectorErrorMapping;
        let err = TwitterError::from_async_error(AsyncError::Cancelled);
        assert!(matches!(err, TwitterError::Stream(_)));
    }

    #[test]
    fn connector_error_mapping_channel_closed() {
        use fcp_async_core::AsyncError;
        use fcp_sdk::migration::ConnectorErrorMapping;
        let err = TwitterError::from_async_error(AsyncError::ChannelClosed);
        assert!(matches!(err, TwitterError::Stream(_)));
        assert!(err.is_retryable());
    }

    #[test]
    fn connector_error_mapping_to_fcp_delegates() {
        use fcp_sdk::migration::ConnectorErrorMapping;
        let err = TwitterError::NotConfigured;
        let fcp = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp, FcpError::NotConfigured));
    }

    #[test]
    fn connector_error_mapping_is_retryable_delegates() {
        use fcp_sdk::migration::ConnectorErrorMapping;
        let err = TwitterError::RateLimited { retry_after: 10 };
        assert!(ConnectorErrorMapping::is_retryable(&err));
    }

    #[test]
    fn connector_error_mapping_retry_after_delegates() {
        use fcp_sdk::migration::ConnectorErrorMapping;
        let err = TwitterError::RateLimited { retry_after: 30 };
        assert_eq!(
            ConnectorErrorMapping::retry_after(&err),
            Some(Duration::from_secs(30))
        );
    }

    #[test]
    fn api_error_200_not_retryable() {
        let err = TwitterError::Api {
            status: 200,
            message: "ok somehow an error".into(),
            error_code: None,
            retry_after: None,
        };
        assert!(!err.is_retryable());
    }
}
