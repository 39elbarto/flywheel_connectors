//! Zendesk-specific error types.

use std::time::Duration;

use fcp_core::FcpError;

/// Zendesk API error.
#[derive(Debug, thiserror::Error)]
pub enum ZendeskError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Zendesk API error: {message}")]
    Api {
        message: String,
        status_code: Option<u16>,
    },

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Rate limited")]
    RateLimit { retry_after_ms: u64 },
}

pub type ZendeskResult<T> = Result<T, ZendeskError>;

impl ZendeskError {
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
                service: "zendesk".into(),
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
                        service: "zendesk".into(),
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

#[cfg(test)]
mod tests {
    use super::*;

    // ── Display messages for all variants ─────────────────────────────

    #[test]
    fn display_http() {
        // Build a reqwest::Error via an invalid URL
        let err_inner = reqwest::Client::new().get("://bad").build().unwrap_err();
        let err = ZendeskError::Http(err_inner);
        let msg = err.to_string();
        assert!(msg.starts_with("HTTP error:"), "got: {msg}");
    }

    #[test]
    fn display_serialization() {
        let json_err = serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err();
        let err = ZendeskError::Serialization(json_err);
        let msg = err.to_string();
        assert!(msg.starts_with("Serialization error:"), "got: {msg}");
    }

    #[test]
    fn display_api() {
        let err = ZendeskError::Api {
            message: "Record not found".into(),
            status_code: Some(404),
        };
        let msg = err.to_string();
        assert!(msg.contains("Record not found"), "got: {msg}");
        assert!(msg.starts_with("Zendesk API error:"), "got: {msg}");
    }

    #[test]
    fn display_api_no_status() {
        let err = ZendeskError::Api {
            message: "Unknown error".into(),
            status_code: None,
        };
        let msg = err.to_string();
        assert!(msg.contains("Unknown error"), "got: {msg}");
    }

    #[test]
    fn display_invalid_config() {
        let err = ZendeskError::InvalidConfig("missing subdomain".into());
        let msg = err.to_string();
        assert!(msg.contains("missing subdomain"), "got: {msg}");
        assert!(msg.starts_with("Invalid configuration:"), "got: {msg}");
    }

    #[test]
    fn display_rate_limit() {
        let err = ZendeskError::RateLimit {
            retry_after_ms: 5000,
        };
        let msg = err.to_string();
        assert_eq!(msg, "Rate limited");
    }

    // ── is_retryable for all variants ─────────────────────────────────

    #[test]
    fn is_retryable_http() {
        let err_inner = reqwest::Client::new().get("://bad").build().unwrap_err();
        assert!(ZendeskError::Http(err_inner).is_retryable());
    }

    #[test]
    fn is_retryable_rate_limit() {
        assert!(
            ZendeskError::RateLimit {
                retry_after_ms: 1000
            }
            .is_retryable()
        );
    }

    #[test]
    fn is_retryable_api_429() {
        assert!(
            ZendeskError::Api {
                message: "rate limited".into(),
                status_code: Some(429),
            }
            .is_retryable()
        );
    }

    #[test]
    fn is_retryable_api_500() {
        assert!(
            ZendeskError::Api {
                message: "x".into(),
                status_code: Some(500),
            }
            .is_retryable()
        );
    }

    #[test]
    fn is_retryable_api_502() {
        assert!(
            ZendeskError::Api {
                message: "bad gateway".into(),
                status_code: Some(502),
            }
            .is_retryable()
        );
    }

    #[test]
    fn is_retryable_api_503() {
        assert!(
            ZendeskError::Api {
                message: "service unavailable".into(),
                status_code: Some(503),
            }
            .is_retryable()
        );
    }

    #[test]
    fn is_retryable_api_599() {
        assert!(
            ZendeskError::Api {
                message: "high server error".into(),
                status_code: Some(599),
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_api_400() {
        assert!(
            !ZendeskError::Api {
                message: "x".into(),
                status_code: Some(400),
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_api_401() {
        assert!(
            !ZendeskError::Api {
                message: "unauthorized".into(),
                status_code: Some(401),
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_api_403() {
        assert!(
            !ZendeskError::Api {
                message: "forbidden".into(),
                status_code: Some(403),
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_api_404() {
        assert!(
            !ZendeskError::Api {
                message: "not found".into(),
                status_code: Some(404),
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_api_422() {
        assert!(
            !ZendeskError::Api {
                message: "unprocessable".into(),
                status_code: Some(422),
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_api_none_status() {
        assert!(
            !ZendeskError::Api {
                message: "no code".into(),
                status_code: None,
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_serialization() {
        let json_err = serde_json::from_str::<serde_json::Value>("bad").unwrap_err();
        assert!(!ZendeskError::Serialization(json_err).is_retryable());
    }

    #[test]
    fn not_retryable_invalid_config() {
        assert!(!ZendeskError::InvalidConfig("x".into()).is_retryable());
    }

    // ── retry_after ───────────────────────────────────────────────────

    #[test]
    fn retry_after_rate_limit() {
        let err = ZendeskError::RateLimit {
            retry_after_ms: 5000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn retry_after_rate_limit_zero() {
        let err = ZendeskError::RateLimit { retry_after_ms: 0 };
        assert_eq!(err.retry_after(), Some(Duration::from_millis(0)));
    }

    #[test]
    fn retry_after_rate_limit_large() {
        let err = ZendeskError::RateLimit {
            retry_after_ms: 120_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(120)));
    }

    #[test]
    fn retry_after_http_none() {
        let err_inner = reqwest::Client::new().get("://bad").build().unwrap_err();
        assert_eq!(ZendeskError::Http(err_inner).retry_after(), None);
    }

    #[test]
    fn retry_after_serialization_none() {
        let json_err = serde_json::from_str::<serde_json::Value>("bad").unwrap_err();
        assert_eq!(ZendeskError::Serialization(json_err).retry_after(), None);
    }

    #[test]
    fn retry_after_api_none() {
        let err = ZendeskError::Api {
            message: "error".into(),
            status_code: Some(500),
        };
        assert_eq!(err.retry_after(), None);
    }

    #[test]
    fn retry_after_invalid_config_none() {
        assert_eq!(ZendeskError::InvalidConfig("x".into()).retry_after(), None);
    }

    // ── to_fcp_error: all error-to-FcpError mappings ──────────────────

    #[test]
    fn to_fcp_error_http() {
        let err_inner = reqwest::Client::new().get("://bad").build().unwrap_err();
        let err = ZendeskError::Http(err_inner);
        match err.to_fcp_error() {
            FcpError::External {
                service,
                retryable,
                retry_after,
                ..
            } => {
                assert_eq!(service, "zendesk");
                assert!(retryable);
                assert!(retry_after.is_none());
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_serialization() {
        let json_err = serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err();
        let err = ZendeskError::Serialization(json_err);
        match err.to_fcp_error() {
            FcpError::Internal { message } => {
                assert!(
                    message.starts_with("Serialization error:"),
                    "got: {message}"
                );
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_401() {
        let err = ZendeskError::Api {
            message: "bad token".into(),
            status_code: Some(401),
        };
        match err.to_fcp_error() {
            FcpError::Unauthorized { code, message } => {
                assert_eq!(code, 2001);
                assert_eq!(message, "bad token");
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_403() {
        let err = ZendeskError::Api {
            message: "access denied".into(),
            status_code: Some(403),
        };
        match err.to_fcp_error() {
            FcpError::Unauthorized { code, message } => {
                assert_eq!(code, 2001);
                assert_eq!(message, "access denied");
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_404() {
        let err = ZendeskError::Api {
            message: "Ticket #123".into(),
            status_code: Some(404),
        };
        match err.to_fcp_error() {
            FcpError::ResourceNotFound { resource } => {
                assert_eq!(resource, "Ticket #123");
            }
            other => panic!("expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_429() {
        let err = ZendeskError::Api {
            message: "rate limited".into(),
            status_code: Some(429),
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
    fn to_fcp_error_api_500() {
        let err = ZendeskError::Api {
            message: "internal".into(),
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
                assert_eq!(service, "zendesk");
                assert_eq!(message, "internal");
                assert_eq!(status_code, Some(500));
                assert!(retryable);
                assert!(retry_after.is_none());
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_502() {
        let err = ZendeskError::Api {
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
                assert_eq!(service, "zendesk");
                assert_eq!(status_code, Some(502));
                assert!(retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_400_generic_external() {
        let err = ZendeskError::Api {
            message: "bad request".into(),
            status_code: Some(400),
        };
        match err.to_fcp_error() {
            FcpError::External {
                service,
                message,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "zendesk");
                assert_eq!(message, "bad request");
                assert_eq!(status_code, Some(400));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_no_status_code() {
        let err = ZendeskError::Api {
            message: "unknown".into(),
            status_code: None,
        };
        match err.to_fcp_error() {
            FcpError::External {
                service,
                message,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "zendesk");
                assert_eq!(message, "unknown");
                assert!(status_code.is_none());
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_invalid_config() {
        let err = ZendeskError::InvalidConfig("missing subdomain".into());
        match err.to_fcp_error() {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1003);
                assert_eq!(message, "missing subdomain");
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_rate_limit() {
        let err = ZendeskError::RateLimit {
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
    fn to_fcp_error_rate_limit_zero_ms() {
        let err = ZendeskError::RateLimit { retry_after_ms: 0 };
        match err.to_fcp_error() {
            FcpError::RateLimited { retry_after_ms, .. } => assert_eq!(retry_after_ms, 0),
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    // ── Debug format ──────────────────────────────────────────────────

    #[test]
    fn debug_api_error() {
        let err = ZendeskError::Api {
            message: "test".into(),
            status_code: Some(404),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Api"), "got: {dbg}");
        assert!(dbg.contains("test"), "got: {dbg}");
        assert!(dbg.contains("404"), "got: {dbg}");
    }

    #[test]
    fn debug_invalid_config() {
        let err = ZendeskError::InvalidConfig("bad config".into());
        let dbg = format!("{err:?}");
        assert!(dbg.contains("InvalidConfig"), "got: {dbg}");
        assert!(dbg.contains("bad config"), "got: {dbg}");
    }

    #[test]
    fn debug_rate_limit() {
        let err = ZendeskError::RateLimit {
            retry_after_ms: 3000,
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("RateLimit"), "got: {dbg}");
        assert!(dbg.contains("3000"), "got: {dbg}");
    }

    #[test]
    fn debug_serialization() {
        let json_err = serde_json::from_str::<serde_json::Value>("bad").unwrap_err();
        let err = ZendeskError::Serialization(json_err);
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Serialization"), "got: {dbg}");
    }

    #[test]
    fn debug_http() {
        let err_inner = reqwest::Client::new().get("://bad").build().unwrap_err();
        let err = ZendeskError::Http(err_inner);
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Http"), "got: {dbg}");
    }

    // ── std::error::Error trait ───────────────────────────────────────

    #[test]
    fn error_trait_invalid_config() {
        let err: &dyn std::error::Error = &ZendeskError::InvalidConfig("x".into());
        // source() should be None for InvalidConfig (plain string, no inner error)
        assert!(err.source().is_none());
    }

    #[test]
    fn error_trait_api() {
        let err: &dyn std::error::Error = &ZendeskError::Api {
            message: "err".into(),
            status_code: Some(500),
        };
        assert!(err.source().is_none());
    }

    #[test]
    fn error_trait_rate_limit() {
        let err: &dyn std::error::Error = &ZendeskError::RateLimit {
            retry_after_ms: 1000,
        };
        assert!(err.source().is_none());
    }

    #[test]
    fn error_trait_serialization_source() {
        let json_err = serde_json::from_str::<serde_json::Value>("bad").unwrap_err();
        let err = ZendeskError::Serialization(json_err);
        let dyn_err: &dyn std::error::Error = &err;
        // Serialization wraps a serde_json::Error via #[from], so source() should be Some
        assert!(dyn_err.source().is_some());
    }

    #[test]
    fn error_trait_http_source() {
        let err_inner = reqwest::Client::new().get("://bad").build().unwrap_err();
        let err = ZendeskError::Http(err_inner);
        let dyn_err: &dyn std::error::Error = &err;
        // Http wraps a reqwest::Error via #[from], so source() should be Some
        assert!(dyn_err.source().is_some());
    }

    // ── From conversions ──────────────────────────────────────────────

    #[test]
    fn from_serde_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("x").unwrap_err();
        let err: ZendeskError = json_err.into();
        assert!(matches!(err, ZendeskError::Serialization(_)));
    }

    #[test]
    fn from_reqwest_error() {
        let err_inner = reqwest::Client::new().get("://bad").build().unwrap_err();
        let err: ZendeskError = err_inner.into();
        assert!(matches!(err, ZendeskError::Http(_)));
    }

    // ── ZendeskResult type alias ──────────────────────────────────────

    #[test]
    fn zendesk_result_ok() {
        let r: ZendeskResult<u32> = Ok(42);
        assert!(matches!(r, Ok(42)));
    }

    #[test]
    fn zendesk_result_err() {
        let r: ZendeskResult<u32> = Err(ZendeskError::InvalidConfig("test".into()));
        assert!(matches!(r, Err(ZendeskError::InvalidConfig(msg)) if msg == "test"));
    }

    // ── Edge cases ────────────────────────────────────────────────────

    #[test]
    fn api_error_empty_message() {
        let err = ZendeskError::Api {
            message: String::new(),
            status_code: Some(400),
        };
        let msg = err.to_string();
        assert!(msg.contains("Zendesk API error:"), "got: {msg}");
        // Empty message still produces valid FcpError
        match err.to_fcp_error() {
            FcpError::External { message, .. } => assert!(message.is_empty()),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn invalid_config_empty_message() {
        let err = ZendeskError::InvalidConfig(String::new());
        let msg = err.to_string();
        assert_eq!(msg, "Invalid configuration: ");
        match err.to_fcp_error() {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1003);
                assert!(message.is_empty());
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn api_boundary_status_499_not_retryable() {
        let err = ZendeskError::Api {
            message: "x".into(),
            status_code: Some(499),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_boundary_status_600_not_retryable() {
        let err = ZendeskError::Api {
            message: "x".into(),
            status_code: Some(600),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn to_fcp_error_api_422_is_external() {
        let err = ZendeskError::Api {
            message: "unprocessable entity".into(),
            status_code: Some(422),
        };
        match err.to_fcp_error() {
            FcpError::External {
                service,
                retryable,
                status_code,
                ..
            } => {
                assert_eq!(service, "zendesk");
                assert!(!retryable);
                assert_eq!(status_code, Some(422));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }
}
