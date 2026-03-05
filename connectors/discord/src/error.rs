//! Discord-specific error types.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_core::FcpError;
use fcp_sdk::migration::ConnectorErrorMapping;
use thiserror::Error;

/// Discord-specific errors.
#[derive(Error, Debug)]
pub enum DiscordError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// WebSocket error
    #[error("WebSocket error: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),

    /// Discord API returned an error
    #[error("Discord API error {code}: {message}")]
    Api {
        code: i32,
        message: String,
        retry_after: Option<f64>,
    },

    /// Rate limited
    #[error("Rate limited, retry after {retry_after} seconds")]
    RateLimited { retry_after: f64 },

    /// Generic gateway error
    #[error("Gateway error: {0}")]
    Gateway(String),
}

impl DiscordError {
    /// Check if this error is retryable.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) => true,
            Self::WebSocket(_) => true,
            Self::Api { code, .. } => *code >= 500 || *code == 429,
            Self::RateLimited { .. } => true,
            Self::Gateway(_) => true,
            _ => false,
        }
    }

    /// Get the suggested retry delay.
    #[must_use]
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after } => Some(Duration::from_secs_f64(*retry_after)),
            Self::Api { retry_after, .. } => retry_after.map(Duration::from_secs_f64),
            _ => None,
        }
    }

    /// Convert to FCP error.
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        ConnectorErrorMapping::to_fcp_error(self)
    }

    fn fcp_error_impl(&self) -> FcpError {
        match self {
            Self::Http(e) => FcpError::External {
                service: "discord".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::WebSocket(e) => FcpError::External {
                service: "discord_gateway".into(),
                message: e.to_string(),
                status_code: None,
                retryable: self.is_retryable(),
                retry_after: None,
            },
            Self::Api {
                code,
                message,
                retry_after,
            } => {
                if *code == 429 {
                    // Clamp retry_after to reasonable bounds to prevent overflow
                    let retry_secs = retry_after.unwrap_or(30.0).clamp(0.0, 3600.0);
                    FcpError::RateLimited {
                        retry_after_ms: (retry_secs * 1000.0) as u64,
                        violation: None,
                    }
                } else {
                    FcpError::External {
                        service: "discord".into(),
                        message: message.clone(),
                        status_code: u16::try_from(*code).ok(),
                        retryable: self.is_retryable(),
                        retry_after: self.retry_after(),
                    }
                }
            }
            Self::RateLimited { retry_after } => {
                // Clamp retry_after to reasonable bounds to prevent overflow
                let retry_secs = retry_after.clamp(0.0, 3600.0);
                FcpError::RateLimited {
                    retry_after_ms: (retry_secs * 1000.0) as u64,
                    violation: None,
                }
            }
            Self::Gateway(msg) => FcpError::ConnectorUnavailable {
                code: 5001,
                message: format!("Discord Gateway error: {msg}"),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
        }
    }
}

impl ConnectorErrorMapping for DiscordError {
    fn from_async_error(error: AsyncError) -> Self {
        match error {
            AsyncError::Timeout { timeout_ms } => Self::Api {
                code: 408,
                message: format!("request context deadline exceeded after {timeout_ms}ms"),
                retry_after: None,
            },
            AsyncError::Cancelled => Self::Api {
                code: 499,
                message: "request context cancelled".into(),
                retry_after: None,
            },
            other => Self::Gateway(other.to_string()),
        }
    }

    fn to_fcp_error(&self) -> FcpError {
        self.fcp_error_impl()
    }

    fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::WebSocket(_) | Self::RateLimited { .. } | Self::Gateway(_) => {
                true
            }
            Self::Api { code, .. } => *code >= 500 || *code == 429,
            _ => false,
        }
    }

    fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after } => Some(Duration::from_secs_f64(*retry_after)),
            Self::Api { retry_after, .. } => retry_after.map(Duration::from_secs_f64),
            _ => None,
        }
    }
}

/// Result type for Discord operations.
pub type DiscordResult<T> = Result<T, DiscordError>;

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Display ----

    #[test]
    fn display_api_error() {
        let err = DiscordError::Api {
            code: 50001,
            message: "Missing Access".into(),
            retry_after: None,
        };
        assert_eq!(err.to_string(), "Discord API error 50001: Missing Access");
    }

    #[test]
    fn display_rate_limited() {
        let err = DiscordError::RateLimited { retry_after: 5.0 };
        assert_eq!(err.to_string(), "Rate limited, retry after 5 seconds");
    }

    #[test]
    fn display_gateway() {
        let err = DiscordError::Gateway("connection reset".into());
        assert_eq!(err.to_string(), "Gateway error: connection reset");
    }

    #[test]
    fn display_json_error() {
        let raw = serde_json::from_str::<serde_json::Value>("not json");
        let json_err = raw.unwrap_err();
        let msg = json_err.to_string();
        let err = DiscordError::Json(json_err);
        assert_eq!(err.to_string(), format!("JSON error: {msg}"));
    }

    // ---- is_retryable ----

    #[test]
    fn api_429_is_retryable() {
        let err = DiscordError::Api {
            code: 429,
            message: "rate limited".into(),
            retry_after: Some(5.0),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_500_is_retryable() {
        let err = DiscordError::Api {
            code: 500,
            message: "internal server error".into(),
            retry_after: None,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_503_is_retryable() {
        let err = DiscordError::Api {
            code: 503,
            message: "service unavailable".into(),
            retry_after: None,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_400_not_retryable() {
        let err = DiscordError::Api {
            code: 400,
            message: "bad request".into(),
            retry_after: None,
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_401_not_retryable() {
        let err = DiscordError::Api {
            code: 401,
            message: "unauthorized".into(),
            retry_after: None,
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_404_not_retryable() {
        let err = DiscordError::Api {
            code: 404,
            message: "not found".into(),
            retry_after: None,
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn rate_limited_is_retryable() {
        let err = DiscordError::RateLimited { retry_after: 10.0 };
        assert!(err.is_retryable());
    }

    #[test]
    fn gateway_is_retryable() {
        let err = DiscordError::Gateway("reconnect".into());
        assert!(err.is_retryable());
    }

    #[test]
    fn json_not_retryable() {
        let json_err = serde_json::from_str::<serde_json::Value>("bad").unwrap_err();
        let err = DiscordError::Json(json_err);
        assert!(!err.is_retryable());
    }

    // ---- retry_after ----

    #[test]
    fn retry_after_rate_limited() {
        let err = DiscordError::RateLimited { retry_after: 2.5 };
        let d = err.retry_after().unwrap();
        assert_eq!(d, Duration::from_secs_f64(2.5));
    }

    #[test]
    fn retry_after_api_with_value() {
        let err = DiscordError::Api {
            code: 429,
            message: "rate limited".into(),
            retry_after: Some(1.5),
        };
        let d = err.retry_after().unwrap();
        assert_eq!(d, Duration::from_secs_f64(1.5));
    }

    #[test]
    fn retry_after_api_without_value() {
        let err = DiscordError::Api {
            code: 500,
            message: "server error".into(),
            retry_after: None,
        };
        assert!(err.retry_after().is_none());
    }

    #[test]
    fn retry_after_gateway_is_none() {
        let err = DiscordError::Gateway("disconnect".into());
        assert!(err.retry_after().is_none());
    }

    #[test]
    fn retry_after_json_is_none() {
        let json_err = serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err();
        let err = DiscordError::Json(json_err);
        assert!(err.retry_after().is_none());
    }

    // ---- to_fcp_error ----

    #[test]
    fn to_fcp_error_api_429_maps_to_rate_limited() {
        let err = DiscordError::Api {
            code: 429,
            message: "rate limited".into(),
            retry_after: Some(5.0),
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::RateLimited {
                retry_after_ms, ..
            } => {
                assert_eq!(retry_after_ms, 5000);
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_429_no_retry_after_defaults_to_30s() {
        let err = DiscordError::Api {
            code: 429,
            message: "rate limited".into(),
            retry_after: None,
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::RateLimited {
                retry_after_ms, ..
            } => {
                assert_eq!(retry_after_ms, 30_000);
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_500_maps_to_external() {
        let err = DiscordError::Api {
            code: 500,
            message: "internal error".into(),
            retry_after: None,
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::External {
                service,
                message,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "discord");
                assert_eq!(message, "internal error");
                assert_eq!(status_code, Some(500));
                assert!(retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_400_maps_to_external_not_retryable() {
        let err = DiscordError::Api {
            code: 400,
            message: "bad request".into(),
            retry_after: None,
        };
        let fcp = err.to_fcp_error();
        match fcp {
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
    fn to_fcp_error_gateway_maps_to_connector_unavailable() {
        let err = DiscordError::Gateway("heartbeat timeout".into());
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::ConnectorUnavailable { code, message } => {
                assert_eq!(code, 5001);
                assert!(message.contains("heartbeat timeout"));
            }
            other => panic!("expected ConnectorUnavailable, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_json_maps_to_internal() {
        let json_err = serde_json::from_str::<serde_json::Value>("nope").unwrap_err();
        let err = DiscordError::Json(json_err);
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::Internal { message } => {
                assert!(message.starts_with("JSON error:"));
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_rate_limited_maps_to_rate_limited() {
        let err = DiscordError::RateLimited { retry_after: 12.0 };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::RateLimited {
                retry_after_ms,
                violation,
            } => {
                assert_eq!(retry_after_ms, 12_000);
                assert!(violation.is_none());
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    // ---- retry_after clamping ----

    #[test]
    fn to_fcp_error_rate_limited_clamps_large_value() {
        let err = DiscordError::RateLimited {
            retry_after: 99999.0,
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::RateLimited {
                retry_after_ms, ..
            } => {
                // Clamped to 3600s = 3_600_000ms
                assert_eq!(retry_after_ms, 3_600_000);
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_429_clamps_large_retry_after() {
        let err = DiscordError::Api {
            code: 429,
            message: "rate limited".into(),
            retry_after: Some(7200.0),
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::RateLimited {
                retry_after_ms, ..
            } => {
                assert_eq!(retry_after_ms, 3_600_000);
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_rate_limited_clamps_negative_to_zero() {
        let err = DiscordError::RateLimited {
            retry_after: -5.0,
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::RateLimited {
                retry_after_ms, ..
            } => {
                assert_eq!(retry_after_ms, 0);
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    // ---- Debug ----

    #[test]
    fn debug_format_api() {
        let err = DiscordError::Api {
            code: 403,
            message: "forbidden".into(),
            retry_after: None,
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Api"));
        assert!(dbg.contains("403"));
        assert!(dbg.contains("forbidden"));
    }

    #[test]
    fn debug_format_rate_limited() {
        let err = DiscordError::RateLimited { retry_after: 3.0 };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("RateLimited"));
        assert!(dbg.contains("3.0"));
    }

    #[test]
    fn debug_format_gateway() {
        let err = DiscordError::Gateway("session closed".into());
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Gateway"));
        assert!(dbg.contains("session closed"));
    }

    // ---- std::error::Error trait ----

    #[test]
    fn error_trait_is_implemented() {
        let err = DiscordError::Api {
            code: 500,
            message: "oops".into(),
            retry_after: None,
        };
        // source() for Api variant should be None (no inner error)
        let e: &dyn std::error::Error = &err;
        assert!(e.source().is_none());
    }

    #[test]
    fn error_trait_json_has_source() {
        let json_err = serde_json::from_str::<serde_json::Value>("!!!").unwrap_err();
        let err = DiscordError::Json(json_err);
        let e: &dyn std::error::Error = &err;
        // Json wraps serde_json::Error, so source() is Some
        assert!(e.source().is_some());
    }

    // ---- DiscordResult type alias ----

    #[test]
    fn discord_result_ok() {
        let r: DiscordResult<u32> = Ok(42);
        assert_eq!(r.unwrap(), 42);
    }

    #[test]
    fn discord_result_err() {
        let r: DiscordResult<u32> = Err(DiscordError::Gateway("fail".into()));
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("fail"));
    }

    // ---- ConnectorErrorMapping::from_async_error ----

    #[test]
    fn from_async_error_timeout() {
        let err =
            <DiscordError as ConnectorErrorMapping>::from_async_error(AsyncError::Timeout {
                timeout_ms: 5000,
            });
        match err {
            DiscordError::Api {
                code,
                message,
                retry_after,
            } => {
                assert_eq!(code, 408);
                assert!(message.contains("5000ms"));
                assert!(retry_after.is_none());
            }
            other => panic!("expected Api(408), got {other:?}"),
        }
    }

    #[test]
    fn from_async_error_cancelled() {
        let err =
            <DiscordError as ConnectorErrorMapping>::from_async_error(AsyncError::Cancelled);
        match err {
            DiscordError::Api {
                code,
                message,
                retry_after,
            } => {
                assert_eq!(code, 499);
                assert!(message.contains("cancelled"));
                assert!(retry_after.is_none());
            }
            other => panic!("expected Api(499), got {other:?}"),
        }
    }

    #[test]
    fn from_async_error_channel_closed() {
        let err =
            <DiscordError as ConnectorErrorMapping>::from_async_error(AsyncError::ChannelClosed);
        match err {
            DiscordError::Gateway(msg) => {
                assert!(msg.contains("channel closed"));
            }
            other => panic!("expected Gateway, got {other:?}"),
        }
    }

    #[test]
    fn from_async_error_channel_full() {
        let err =
            <DiscordError as ConnectorErrorMapping>::from_async_error(AsyncError::ChannelFull);
        match err {
            DiscordError::Gateway(msg) => {
                assert!(msg.contains("channel full"));
            }
            other => panic!("expected Gateway, got {other:?}"),
        }
    }

    #[test]
    fn from_async_error_protocol_io() {
        let err =
            <DiscordError as ConnectorErrorMapping>::from_async_error(AsyncError::ProtocolIo {
                message: "broken pipe".into(),
            });
        match err {
            DiscordError::Gateway(msg) => {
                assert!(msg.contains("broken pipe"));
            }
            other => panic!("expected Gateway, got {other:?}"),
        }
    }

    #[test]
    fn from_async_error_runtime() {
        let err =
            <DiscordError as ConnectorErrorMapping>::from_async_error(AsyncError::Runtime {
                message: "panic in task".into(),
            });
        match err {
            DiscordError::Gateway(msg) => {
                assert!(msg.contains("panic in task"));
            }
            other => panic!("expected Gateway, got {other:?}"),
        }
    }

    // ---- ConnectorErrorMapping trait methods ----

    #[test]
    fn trait_is_retryable_matches_inherent() {
        let err = DiscordError::Api {
            code: 429,
            message: "rl".into(),
            retry_after: None,
        };
        assert_eq!(
            err.is_retryable(),
            ConnectorErrorMapping::is_retryable(&err)
        );

        let err2 = DiscordError::Api {
            code: 400,
            message: "bad".into(),
            retry_after: None,
        };
        assert_eq!(
            err2.is_retryable(),
            ConnectorErrorMapping::is_retryable(&err2)
        );
    }

    #[test]
    fn trait_retry_after_matches_inherent() {
        let err = DiscordError::RateLimited { retry_after: 7.0 };
        assert_eq!(
            err.retry_after(),
            ConnectorErrorMapping::retry_after(&err)
        );
    }

    #[test]
    fn trait_to_fcp_error_matches_inherent() {
        let err = DiscordError::Gateway("test".into());
        let fcp1 = err.to_fcp_error();
        let fcp2 = ConnectorErrorMapping::to_fcp_error(&err);
        assert_eq!(format!("{fcp1:?}"), format!("{fcp2:?}"));
    }

    // ---- Api with negative code ----

    #[test]
    fn api_negative_code_not_retryable() {
        let err = DiscordError::Api {
            code: -1,
            message: "unknown".into(),
            retry_after: None,
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_negative_code_to_fcp_error_status_code_none() {
        let err = DiscordError::Api {
            code: -1,
            message: "unknown".into(),
            retry_after: None,
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::External { status_code, .. } => {
                // u16::try_from(-1) fails → None
                assert!(status_code.is_none());
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    // ---- Api with retry_after in to_fcp_error (non-429) ----

    #[test]
    fn api_non_429_with_retry_after_passes_through() {
        let err = DiscordError::Api {
            code: 503,
            message: "unavailable".into(),
            retry_after: Some(10.0),
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::External {
                retry_after,
                retryable,
                ..
            } => {
                assert!(retryable);
                assert_eq!(retry_after, Some(Duration::from_secs_f64(10.0)));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }
}
