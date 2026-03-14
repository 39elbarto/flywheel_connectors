//! `Home Assistant`-specific error types.

use std::time::Duration;

use fcp_core::FcpError;
use thiserror::Error;

/// Result alias for `Home Assistant` operations.
pub type HomeAssistantResult<T> = Result<T, HomeAssistantError>;

/// `Home Assistant`-specific errors.
#[derive(Error, Debug)]
pub enum HomeAssistantError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// `Home Assistant` API returned an error
    #[error("Home Assistant API error ({status_code}): {message}")]
    Api { status_code: u16, message: String },

    /// Rate limited (429)
    #[error("Rate limited, retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },

    /// Authentication failed (401)
    #[error("Authentication failed: invalid or expired access token")]
    Unauthorized,

    /// Entity not found (404)
    #[error("Entity not found: {entity_id}")]
    EntityNotFound { entity_id: String },

    /// Service not found (404)
    #[error("Service not found: {service}")]
    ServiceNotFound { service: String },

    /// Home Assistant unavailable (503)
    #[error("Home Assistant is unavailable")]
    Unavailable,
}

impl HomeAssistantError {
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::RateLimited { .. } | Self::Unavailable => true,
            Self::Api { status_code, .. } => matches!(status_code, 500..=599 | 429),
            _ => false,
        }
    }

    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after_ms } => Some(Duration::from_millis(*retry_after_ms)),
            _ => None,
        }
    }

    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Http(e) => FcpError::External {
                service: "homeassistant".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
            Self::Api {
                status_code,
                message,
            } => FcpError::External {
                service: "homeassistant".into(),
                message: message.clone(),
                status_code: Some(*status_code),
                retryable: self.is_retryable(),
                retry_after: None,
            },
            Self::RateLimited { retry_after_ms } => FcpError::External {
                service: "homeassistant".into(),
                message: format!("Rate limited, retry after {retry_after_ms}ms"),
                status_code: Some(429),
                retryable: true,
                retry_after: self.retry_after(),
            },
            Self::Unauthorized => FcpError::External {
                service: "homeassistant".into(),
                message: "Authentication failed".into(),
                status_code: Some(401),
                retryable: false,
                retry_after: None,
            },
            Self::EntityNotFound { entity_id } => FcpError::External {
                service: "homeassistant".into(),
                message: format!("Entity not found: {entity_id}"),
                status_code: Some(404),
                retryable: false,
                retry_after: None,
            },
            Self::ServiceNotFound { service } => FcpError::External {
                service: "homeassistant".into(),
                message: format!("Service not found: {service}"),
                status_code: Some(404),
                retryable: false,
                retry_after: None,
            },
            Self::Unavailable => FcpError::External {
                service: "homeassistant".into(),
                message: "Home Assistant is unavailable".into(),
                status_code: Some(503),
                retryable: true,
                retry_after: None,
            },
        }
    }
}

impl fcp_sdk::migration::ConnectorErrorMapping for HomeAssistantError {
    fn from_async_error(error: fcp_async_core::AsyncError) -> Self {
        use fcp_async_core::AsyncError;
        match error {
            AsyncError::Timeout { timeout_ms } => Self::Api {
                status_code: 408,
                message: format!("deadline exceeded after {timeout_ms}ms"),
            },
            AsyncError::Cancelled => Self::Api {
                status_code: 0,
                message: "request cancelled".into(),
            },
            other => Self::Api {
                status_code: 0,
                message: other.to_string(),
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

    #[test]
    fn rate_limited_is_retryable() {
        assert!(
            HomeAssistantError::RateLimited {
                retry_after_ms: 5000
            }
            .is_retryable()
        );
    }

    #[test]
    fn unavailable_is_retryable() {
        assert!(HomeAssistantError::Unavailable.is_retryable());
    }

    #[test]
    fn api_500_is_retryable() {
        assert!(
            HomeAssistantError::Api {
                status_code: 500,
                message: "err".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_503_is_retryable() {
        assert!(
            HomeAssistantError::Api {
                status_code: 503,
                message: "unavailable".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_429_is_retryable() {
        assert!(
            HomeAssistantError::Api {
                status_code: 429,
                message: "too many".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn unauthorized_not_retryable() {
        assert!(!HomeAssistantError::Unauthorized.is_retryable());
    }

    #[test]
    fn entity_not_found_not_retryable() {
        assert!(
            !HomeAssistantError::EntityNotFound {
                entity_id: "light.test".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn service_not_found_not_retryable() {
        assert!(
            !HomeAssistantError::ServiceNotFound {
                service: "light.blink".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_400_not_retryable() {
        assert!(
            !HomeAssistantError::Api {
                status_code: 400,
                message: "bad request".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn retry_after_for_rate_limited() {
        let err = HomeAssistantError::RateLimited {
            retry_after_ms: 30_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn retry_after_none_for_unauthorized() {
        assert_eq!(HomeAssistantError::Unauthorized.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_unavailable() {
        assert_eq!(HomeAssistantError::Unavailable.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_api_error() {
        assert_eq!(
            HomeAssistantError::Api {
                status_code: 500,
                message: "err".into()
            }
            .retry_after(),
            None
        );
    }

    #[test]
    fn retry_after_none_for_entity_not_found() {
        assert_eq!(
            HomeAssistantError::EntityNotFound {
                entity_id: "x".into()
            }
            .retry_after(),
            None
        );
    }

    #[test]
    fn retry_after_none_for_service_not_found() {
        assert_eq!(
            HomeAssistantError::ServiceNotFound {
                service: "x".into()
            }
            .retry_after(),
            None
        );
    }

    #[test]
    fn unauthorized_to_fcp_error() {
        match HomeAssistantError::Unauthorized.to_fcp_error() {
            FcpError::External {
                service,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "homeassistant");
                assert_eq!(status_code, Some(401));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn entity_not_found_to_fcp_error() {
        match (HomeAssistantError::EntityNotFound {
            entity_id: "light.test".into(),
        })
        .to_fcp_error()
        {
            FcpError::External {
                status_code,
                message,
                retryable,
                ..
            } => {
                assert_eq!(status_code, Some(404));
                assert!(message.contains("light.test"));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn service_not_found_to_fcp_error() {
        match (HomeAssistantError::ServiceNotFound {
            service: "light.blink".into(),
        })
        .to_fcp_error()
        {
            FcpError::External {
                status_code,
                message,
                retryable,
                ..
            } => {
                assert_eq!(status_code, Some(404));
                assert!(message.contains("light.blink"));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn unavailable_to_fcp_error() {
        match HomeAssistantError::Unavailable.to_fcp_error() {
            FcpError::External {
                service,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "homeassistant");
                assert_eq!(status_code, Some(503));
                assert!(retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_to_fcp_error() {
        match (HomeAssistantError::RateLimited {
            retry_after_ms: 60_000,
        })
        .to_fcp_error()
        {
            FcpError::External {
                status_code,
                retryable,
                retry_after,
                ..
            } => {
                assert_eq!(status_code, Some(429));
                assert!(retryable);
                assert_eq!(retry_after, Some(Duration::from_secs(60)));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn api_error_to_fcp_error() {
        match (HomeAssistantError::Api {
            status_code: 503,
            message: "unavailable".into(),
        })
        .to_fcp_error()
        {
            FcpError::External {
                service,
                status_code,
                retryable,
                message,
                ..
            } => {
                assert_eq!(service, "homeassistant");
                assert_eq!(status_code, Some(503));
                assert!(retryable);
                assert_eq!(message, "unavailable");
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn json_error_to_fcp_internal() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{invalid");
        match HomeAssistantError::Json(bad.unwrap_err()).to_fcp_error() {
            FcpError::Internal { message } => assert!(message.starts_with("JSON error:")),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn api_error_non_retryable_to_fcp_error() {
        match (HomeAssistantError::Api {
            status_code: 400,
            message: "bad".into(),
        })
        .to_fcp_error()
        {
            FcpError::External {
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(status_code, Some(400));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn error_display_unauthorized() {
        assert_eq!(
            HomeAssistantError::Unauthorized.to_string(),
            "Authentication failed: invalid or expired access token"
        );
    }

    #[test]
    fn error_display_entity_not_found() {
        assert_eq!(
            HomeAssistantError::EntityNotFound {
                entity_id: "light.living_room".into()
            }
            .to_string(),
            "Entity not found: light.living_room"
        );
    }

    #[test]
    fn error_display_service_not_found() {
        assert_eq!(
            HomeAssistantError::ServiceNotFound {
                service: "light.blink".into()
            }
            .to_string(),
            "Service not found: light.blink"
        );
    }

    #[test]
    fn error_display_unavailable() {
        assert_eq!(
            HomeAssistantError::Unavailable.to_string(),
            "Home Assistant is unavailable"
        );
    }

    #[test]
    fn error_display_rate_limited() {
        assert_eq!(
            HomeAssistantError::RateLimited {
                retry_after_ms: 2000
            }
            .to_string(),
            "Rate limited, retry after 2000ms"
        );
    }

    #[test]
    fn error_display_api() {
        assert_eq!(
            HomeAssistantError::Api {
                status_code: 500,
                message: "Internal".into()
            }
            .to_string(),
            "Home Assistant API error (500): Internal"
        );
    }

    // ── ConnectorErrorMapping ────────────────────────────────────────

    #[test]
    fn connector_error_mapping_timeout() {
        use fcp_async_core::AsyncError;
        use fcp_sdk::migration::ConnectorErrorMapping;
        let err =
            HomeAssistantError::from_async_error(AsyncError::Timeout { timeout_ms: 2000 });
        assert!(matches!(
            err,
            HomeAssistantError::Api {
                status_code: 408,
                ..
            }
        ));
        assert!(err.to_string().contains("2000"));
    }

    #[test]
    fn connector_error_mapping_cancelled() {
        use fcp_async_core::AsyncError;
        use fcp_sdk::migration::ConnectorErrorMapping;
        let err = HomeAssistantError::from_async_error(AsyncError::Cancelled);
        assert!(matches!(
            err,
            HomeAssistantError::Api {
                status_code: 0,
                ..
            }
        ));
    }

    #[test]
    fn connector_error_mapping_protocol_io() {
        use fcp_async_core::AsyncError;
        use fcp_sdk::migration::ConnectorErrorMapping;
        let err = HomeAssistantError::from_async_error(AsyncError::ProtocolIo {
            message: "connection reset".into(),
        });
        assert!(matches!(err, HomeAssistantError::Api { .. }));
    }

    #[test]
    fn connector_error_mapping_to_fcp_delegates() {
        use fcp_sdk::migration::ConnectorErrorMapping;
        let err = HomeAssistantError::Unauthorized;
        let fcp = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(
            fcp,
            FcpError::External {
                status_code: Some(401),
                ..
            }
        ));
    }

    #[test]
    fn connector_error_mapping_is_retryable_delegates() {
        use fcp_sdk::migration::ConnectorErrorMapping;
        let err = HomeAssistantError::Unavailable;
        assert!(ConnectorErrorMapping::is_retryable(&err));
    }

    #[test]
    fn connector_error_mapping_retry_after_delegates() {
        use fcp_sdk::migration::ConnectorErrorMapping;
        let err = HomeAssistantError::RateLimited {
            retry_after_ms: 10_000,
        };
        assert_eq!(
            ConnectorErrorMapping::retry_after(&err),
            Some(Duration::from_secs(10))
        );
    }

    #[test]
    fn api_501_is_retryable() {
        assert!(
            HomeAssistantError::Api {
                status_code: 501,
                message: "not implemented".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_599_is_retryable() {
        assert!(
            HomeAssistantError::Api {
                status_code: 599,
                message: "edge".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_499_not_retryable() {
        assert!(
            !HomeAssistantError::Api {
                status_code: 499,
                message: "client".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn json_not_retryable() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{bad");
        assert!(!HomeAssistantError::Json(bad.unwrap_err()).is_retryable());
    }

    #[test]
    fn error_debug_format_api() {
        let err = HomeAssistantError::Api {
            status_code: 503,
            message: "unavailable".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Api"));
        assert!(dbg.contains("503"));
    }

    #[test]
    fn error_debug_format_unauthorized() {
        let dbg = format!("{:?}", HomeAssistantError::Unauthorized);
        assert!(dbg.contains("Unauthorized"));
    }

    #[test]
    fn error_debug_format_unavailable() {
        let dbg = format!("{:?}", HomeAssistantError::Unavailable);
        assert!(dbg.contains("Unavailable"));
    }

    #[test]
    fn error_debug_format_entity_not_found() {
        let err = HomeAssistantError::EntityNotFound {
            entity_id: "light.test".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("EntityNotFound"));
        assert!(dbg.contains("light.test"));
    }

    #[test]
    fn error_debug_format_service_not_found() {
        let err = HomeAssistantError::ServiceNotFound {
            service: "light.blink".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("ServiceNotFound"));
    }

    #[test]
    fn retry_after_zero_ms() {
        let err = HomeAssistantError::RateLimited { retry_after_ms: 0 };
        assert_eq!(err.retry_after(), Some(Duration::from_millis(0)));
    }

    #[test]
    fn retry_after_large_value() {
        let err = HomeAssistantError::RateLimited {
            retry_after_ms: 3_600_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(3600)));
    }

    #[test]
    fn api_error_retryable_has_no_retry_after() {
        match (HomeAssistantError::Api {
            status_code: 500,
            message: "err".into(),
        })
        .to_fcp_error()
        {
            FcpError::External { retry_after, .. } => assert!(retry_after.is_none()),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn error_display_json() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{{");
        let err = HomeAssistantError::Json(bad.unwrap_err());
        let display = err.to_string();
        assert!(display.starts_with("JSON error:"));
    }

    #[test]
    fn api_502_is_retryable() {
        assert!(
            HomeAssistantError::Api {
                status_code: 502,
                message: "bad gateway".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_504_is_retryable() {
        assert!(
            HomeAssistantError::Api {
                status_code: 504,
                message: "gateway timeout".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn retry_after_none_for_json_error() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{bad");
        assert_eq!(
            HomeAssistantError::Json(bad.unwrap_err()).retry_after(),
            None
        );
    }

    #[test]
    fn unavailable_to_fcp_error_retryable() {
        match HomeAssistantError::Unavailable.to_fcp_error() {
            FcpError::External {
                retryable,
                retry_after,
                ..
            } => {
                assert!(retryable);
                assert!(retry_after.is_none());
            }
            other => panic!("expected External, got {other:?}"),
        }
    }
}
