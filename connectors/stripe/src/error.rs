//! Stripe-specific error types.

use std::time::Duration;

use fcp_core::FcpError;

/// Stripe API error.
#[derive(Debug, thiserror::Error)]
pub enum StripeError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Stripe API error: {message}")]
    Api {
        message: String,
        status_code: Option<u16>,
        error_type: Option<String>,
    },

    #[error("Rate limited")]
    RateLimited { retry_after_ms: u64 },

    #[error("Unauthorized")]
    Unauthorized,

    #[error("Not found: {resource}")]
    NotFound { resource: String },
}

pub type StripeResult<T> = Result<T, StripeError>;

impl StripeError {
    /// Check if this error is retryable.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::RateLimited { .. } => true,
            Self::Api { status_code, .. } => matches!(status_code, Some(500..=599 | 429)),
            Self::Json(_) | Self::Unauthorized | Self::NotFound { .. } => false,
        }
    }

    /// Get the suggested retry delay.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after_ms } => Some(Duration::from_millis(*retry_after_ms)),
            _ => None,
        }
    }

    /// Convert to FCP error.
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Http(e) => FcpError::External {
                service: "stripe".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
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
                        service: "stripe".into(),
                        message: message.clone(),
                        status_code: *status_code,
                        retryable: self.is_retryable(),
                        retry_after: self.retry_after(),
                    }
                }
            }
            Self::RateLimited { retry_after_ms } => FcpError::RateLimited {
                retry_after_ms: *retry_after_ms,
                violation: None,
            },
            Self::Unauthorized => FcpError::Unauthorized {
                code: 2001,
                message: "Stripe API authentication failed".into(),
            },
            Self::NotFound { resource } => FcpError::ResourceNotFound {
                resource: resource.clone(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_api() {
        let err = StripeError::Api {
            message: "No such customer".into(),
            status_code: Some(404),
            error_type: Some("invalid_request_error".into()),
        };
        assert!(err.to_string().contains("No such customer"));
    }

    #[test]
    fn display_rate_limited() {
        assert!(StripeError::RateLimited {
            retry_after_ms: 1000
        }
        .to_string()
        .contains("Rate limited"));
    }

    #[test]
    fn is_retryable_rate_limited() {
        assert!(StripeError::RateLimited {
            retry_after_ms: 1000
        }
        .is_retryable());
    }

    #[test]
    fn is_retryable_api_500() {
        assert!(StripeError::Api {
            message: "x".into(),
            status_code: Some(500),
            error_type: None,
        }
        .is_retryable());
    }

    #[test]
    fn not_retryable_api_400() {
        assert!(!StripeError::Api {
            message: "x".into(),
            status_code: Some(400),
            error_type: None,
        }
        .is_retryable());
    }

    #[test]
    fn not_retryable_unauthorized() {
        assert!(!StripeError::Unauthorized.is_retryable());
    }

    #[test]
    fn not_retryable_not_found() {
        assert!(!StripeError::NotFound {
            resource: "x".into()
        }
        .is_retryable());
    }

    #[test]
    fn retry_after_rate_limited() {
        let err = StripeError::RateLimited {
            retry_after_ms: 5000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn retry_after_other_none() {
        assert_eq!(StripeError::Unauthorized.retry_after(), None);
    }

    #[test]
    fn to_fcp_error_api_401() {
        let err = StripeError::Api {
            message: "bad key".into(),
            status_code: Some(401),
            error_type: None,
        };
        assert!(matches!(err.to_fcp_error(), FcpError::Unauthorized { .. }));
    }

    #[test]
    fn to_fcp_error_api_429() {
        let err = StripeError::Api {
            message: "rate limited".into(),
            status_code: Some(429),
            error_type: None,
        };
        match err.to_fcp_error() {
            FcpError::RateLimited {
                retry_after_ms, ..
            } => assert_eq!(retry_after_ms, 60_000),
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_500_external() {
        let err = StripeError::Api {
            message: "internal".into(),
            status_code: Some(500),
            error_type: None,
        };
        match err.to_fcp_error() {
            FcpError::External {
                service, retryable, ..
            } => {
                assert_eq!(service, "stripe");
                assert!(retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_rate_limited() {
        let err = StripeError::RateLimited {
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
    fn to_fcp_error_unauthorized() {
        match StripeError::Unauthorized.to_fcp_error() {
            FcpError::Unauthorized { code, .. } => assert_eq!(code, 2001),
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_not_found() {
        let err = StripeError::NotFound {
            resource: "cus_abc".into(),
        };
        match err.to_fcp_error() {
            FcpError::ResourceNotFound { resource } => assert_eq!(resource, "cus_abc"),
            other => panic!("expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_json_internal() {
        let json_err = serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err();
        let err = StripeError::Json(json_err);
        assert!(matches!(err.to_fcp_error(), FcpError::Internal { .. }));
    }

    #[test]
    fn from_serde_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("x").unwrap_err();
        let err: StripeError = json_err.into();
        assert!(matches!(err, StripeError::Json(_)));
    }

    #[test]
    fn stripe_result_ok() {
        let r: StripeResult<u32> = Ok(42);
        assert!(r.is_ok());
    }

    #[test]
    fn error_trait_impl() {
        let _: &dyn std::error::Error = &StripeError::Unauthorized;
    }
}
