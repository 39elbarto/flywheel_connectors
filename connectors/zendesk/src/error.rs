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

    #[test]
    fn display_api() {
        let err = ZendeskError::Api {
            message: "Record not found".into(),
            status_code: Some(404),
        };
        assert!(err.to_string().contains("Record not found"));
    }

    #[test]
    fn display_invalid_config() {
        let err = ZendeskError::InvalidConfig("missing subdomain".into());
        assert!(err.to_string().contains("missing subdomain"));
    }

    #[test]
    fn is_retryable_rate_limit() {
        assert!(ZendeskError::RateLimit {
            retry_after_ms: 1000
        }
        .is_retryable());
    }

    #[test]
    fn is_retryable_api_500() {
        assert!(ZendeskError::Api {
            message: "x".into(),
            status_code: Some(500),
        }
        .is_retryable());
    }

    #[test]
    fn not_retryable_api_400() {
        assert!(!ZendeskError::Api {
            message: "x".into(),
            status_code: Some(400),
        }
        .is_retryable());
    }

    #[test]
    fn not_retryable_invalid_config() {
        assert!(!ZendeskError::InvalidConfig("x".into()).is_retryable());
    }

    #[test]
    fn retry_after_rate_limit() {
        let err = ZendeskError::RateLimit {
            retry_after_ms: 5000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn retry_after_other_none() {
        assert_eq!(
            ZendeskError::InvalidConfig("x".into()).retry_after(),
            None
        );
    }

    #[test]
    fn to_fcp_error_api_401() {
        let err = ZendeskError::Api {
            message: "bad token".into(),
            status_code: Some(401),
        };
        assert!(matches!(err.to_fcp_error(), FcpError::Unauthorized { .. }));
    }

    #[test]
    fn to_fcp_error_api_404() {
        let err = ZendeskError::Api {
            message: "Ticket #123".into(),
            status_code: Some(404),
        };
        match err.to_fcp_error() {
            FcpError::ResourceNotFound { resource } => assert!(resource.contains("Ticket #123")),
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
                retry_after_ms, ..
            } => assert_eq!(retry_after_ms, 60_000),
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
                service, retryable, ..
            } => {
                assert_eq!(service, "zendesk");
                assert!(retryable);
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
                assert!(message.contains("missing subdomain"));
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
                retry_after_ms, ..
            } => assert_eq!(retry_after_ms, 2000),
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_serialization() {
        let json_err = serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err();
        let err = ZendeskError::Serialization(json_err);
        assert!(matches!(err.to_fcp_error(), FcpError::Internal { .. }));
    }

    #[test]
    fn from_serde_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("x").unwrap_err();
        let err: ZendeskError = json_err.into();
        assert!(matches!(err, ZendeskError::Serialization(_)));
    }

    #[test]
    fn zendesk_result_ok() {
        let r: ZendeskResult<u32> = Ok(42);
        assert!(r.is_ok());
    }

    #[test]
    fn error_trait_impl() {
        let _: &dyn std::error::Error = &ZendeskError::InvalidConfig("x".into());
    }
}
