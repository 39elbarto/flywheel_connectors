//! Microsoft 365 Graph API error types.

use std::time::Duration;

use fcp_core::FcpError;

/// Microsoft 365 Graph API error.
#[derive(Debug, thiserror::Error)]
pub enum M365Error {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Graph API error: {message}")]
    Api {
        message: String,
        status_code: Option<u16>,
        error_code: Option<String>,
    },

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Rate limited")]
    RateLimit { retry_after_ms: u64 },
}

pub type M365Result<T> = Result<T, M365Error>;

impl M365Error {
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
                service: "microsoft365".into(),
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
                        service: "microsoft365".into(),
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

    // ---- is_retryable ----

    #[test]
    fn rate_limit_is_retryable() {
        let err = M365Error::RateLimit {
            retry_after_ms: 1000,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn serialization_error_not_retryable() {
        let inner = serde_json::from_str::<serde_json::Value>("bad json").unwrap_err();
        let err = M365Error::Serialization(inner);
        assert!(!err.is_retryable());
    }

    #[test]
    fn invalid_config_not_retryable() {
        let err = M365Error::InvalidConfig("missing field".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_500_is_retryable() {
        let err = M365Error::Api {
            message: "server error".into(),
            status_code: Some(500),
            error_code: None,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_503_is_retryable() {
        let err = M365Error::Api {
            message: "service unavailable".into(),
            status_code: Some(503),
            error_code: None,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_429_is_retryable() {
        let err = M365Error::Api {
            message: "throttled".into(),
            status_code: Some(429),
            error_code: Some("TooManyRequests".into()),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_400_not_retryable() {
        let err = M365Error::Api {
            message: "bad request".into(),
            status_code: Some(400),
            error_code: None,
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_404_not_retryable() {
        let err = M365Error::Api {
            message: "not found".into(),
            status_code: Some(404),
            error_code: None,
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_no_status_not_retryable() {
        let err = M365Error::Api {
            message: "unknown".into(),
            status_code: None,
            error_code: None,
        };
        assert!(!err.is_retryable());
    }

    // ---- retry_after ----

    #[test]
    fn rate_limit_has_retry_after() {
        let err = M365Error::RateLimit {
            retry_after_ms: 5000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn non_rate_limit_errors_have_no_retry_after() {
        let err = M365Error::InvalidConfig("bad".into());
        assert_eq!(err.retry_after(), None);

        let err = M365Error::Api {
            message: "error".into(),
            status_code: Some(500),
            error_code: None,
        };
        assert_eq!(err.retry_after(), None);
    }

    // ---- to_fcp_error ----

    #[test]
    fn api_401_maps_to_unauthorized() {
        let err = M365Error::Api {
            message: "access denied".into(),
            status_code: Some(401),
            error_code: Some("Unauthorized".into()),
        };
        match err.to_fcp_error() {
            FcpError::Unauthorized { code, message } => {
                assert_eq!(code, 2001);
                assert!(message.contains("access denied"));
            }
            other => panic!("Expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn api_403_maps_to_unauthorized() {
        let err = M365Error::Api {
            message: "forbidden".into(),
            status_code: Some(403),
            error_code: None,
        };
        match err.to_fcp_error() {
            FcpError::Unauthorized { code, .. } => assert_eq!(code, 2001),
            other => panic!("Expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn api_404_maps_to_resource_not_found() {
        let err = M365Error::Api {
            message: "message not found".into(),
            status_code: Some(404),
            error_code: None,
        };
        match err.to_fcp_error() {
            FcpError::ResourceNotFound { resource } => {
                assert!(resource.contains("message not found"));
            }
            other => panic!("Expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn api_429_maps_to_rate_limited() {
        let err = M365Error::Api {
            message: "throttled".into(),
            status_code: Some(429),
            error_code: None,
        };
        match err.to_fcp_error() {
            FcpError::RateLimited { retry_after_ms, .. } => {
                assert_eq!(retry_after_ms, 60_000);
            }
            other => panic!("Expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn api_500_maps_to_external() {
        let err = M365Error::Api {
            message: "internal error".into(),
            status_code: Some(500),
            error_code: None,
        };
        match err.to_fcp_error() {
            FcpError::External {
                service, retryable, ..
            } => {
                assert_eq!(service, "microsoft365");
                assert!(retryable);
            }
            other => panic!("Expected External, got {other:?}"),
        }
    }

    #[test]
    fn serialization_error_maps_to_internal() {
        let inner = serde_json::from_str::<serde_json::Value>("invalid").unwrap_err();
        let err = M365Error::Serialization(inner);
        match err.to_fcp_error() {
            FcpError::Internal { message } => {
                assert!(message.contains("Serialization error"));
            }
            other => panic!("Expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn invalid_config_maps_to_invalid_request() {
        let err = M365Error::InvalidConfig("bad config".into());
        match err.to_fcp_error() {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1003);
                assert!(message.contains("bad config"));
            }
            other => panic!("Expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn rate_limit_maps_to_rate_limited() {
        let err = M365Error::RateLimit {
            retry_after_ms: 30_000,
        };
        match err.to_fcp_error() {
            FcpError::RateLimited {
                retry_after_ms,
                violation,
            } => {
                assert_eq!(retry_after_ms, 30_000);
                assert!(violation.is_none());
            }
            other => panic!("Expected RateLimited, got {other:?}"),
        }
    }

    // ---- Display ----

    #[test]
    fn error_display_messages() {
        assert_eq!(
            M365Error::InvalidConfig("no token".into()).to_string(),
            "Invalid configuration: no token"
        );
        assert_eq!(
            M365Error::RateLimit { retry_after_ms: 0 }.to_string(),
            "Rate limited"
        );
        let api_err = M365Error::Api {
            message: "test error".into(),
            status_code: Some(500),
            error_code: None,
        };
        assert!(api_err.to_string().contains("test error"));
    }
}
