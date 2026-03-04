//! Browser-specific error types.

use std::time::Duration;

use fcp_core::FcpError;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_api() {
        let err = BrowserError::Api {
            message: "page crashed".into(),
            status_code: Some(500),
        };
        assert!(err.to_string().contains("page crashed"));
    }

    #[test]
    fn display_invalid_config() {
        let err = BrowserError::InvalidConfig("missing endpoint".into());
        assert!(err.to_string().contains("missing endpoint"));
    }

    #[test]
    fn display_timeout() {
        let err = BrowserError::Timeout {
            message: "navigation timed out".into(),
        };
        assert!(err.to_string().contains("navigation timed out"));
    }

    #[test]
    fn is_retryable_timeout() {
        assert!(BrowserError::Timeout {
            message: "x".into()
        }
        .is_retryable());
    }

    #[test]
    fn is_retryable_api_500() {
        assert!(BrowserError::Api {
            message: "x".into(),
            status_code: Some(500),
        }
        .is_retryable());
    }

    #[test]
    fn is_retryable_api_429() {
        assert!(BrowserError::Api {
            message: "x".into(),
            status_code: Some(429),
        }
        .is_retryable());
    }

    #[test]
    fn not_retryable_api_400() {
        assert!(!BrowserError::Api {
            message: "x".into(),
            status_code: Some(400),
        }
        .is_retryable());
    }

    #[test]
    fn not_retryable_invalid_config() {
        assert!(!BrowserError::InvalidConfig("x".into()).is_retryable());
    }

    #[test]
    fn retry_after_429() {
        let err = BrowserError::Api {
            message: "x".into(),
            status_code: Some(429),
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn retry_after_other_none() {
        assert_eq!(BrowserError::InvalidConfig("x".into()).retry_after(), None);
        assert_eq!(
            BrowserError::Api {
                message: "x".into(),
                status_code: Some(500),
            }
            .retry_after(),
            None
        );
    }

    #[test]
    fn to_fcp_error_api_429() {
        let err = BrowserError::Api {
            message: "x".into(),
            status_code: Some(429),
        };
        match err.to_fcp_error() {
            FcpError::RateLimited {
                retry_after_ms, ..
            } => assert_eq!(retry_after_ms, 5_000),
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
                service, retryable, ..
            } => {
                assert_eq!(service, "browser");
                assert!(retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_invalid_config() {
        let err = BrowserError::InvalidConfig("bad url".into());
        match err.to_fcp_error() {
            FcpError::Internal { message } => assert!(message.contains("bad url")),
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
                status_code,
                retryable,
                retry_after,
                ..
            } => {
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
        assert!(matches!(err.to_fcp_error(), FcpError::Internal { .. }));
    }

    #[test]
    fn from_serde_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("x").unwrap_err();
        let err: BrowserError = json_err.into();
        assert!(matches!(err, BrowserError::Serialization(_)));
    }

    #[test]
    fn browser_result_ok() {
        let r: BrowserResult<u32> = Ok(42);
        assert!(r.is_ok());
    }

    #[test]
    fn error_trait_impl() {
        let _: &dyn std::error::Error = &BrowserError::InvalidConfig("x".into());
    }
}
