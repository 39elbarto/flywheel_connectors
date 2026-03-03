//! Twilio-specific error types.

use std::time::Duration;

use fcp_core::FcpError;

/// Twilio API error.
#[derive(Debug, thiserror::Error)]
pub enum TwilioError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Twilio API error: {message}")]
    Api {
        message: String,
        status_code: Option<u16>,
        error_code: Option<String>,
    },

    #[error("Rate limited")]
    RateLimited { retry_after_ms: u64 },

    #[error("Unauthorized")]
    Unauthorized,

    #[error("Not found: {resource}")]
    NotFound { resource: String },
}

pub type TwilioResult<T> = Result<T, TwilioError>;

impl TwilioError {
    /// Check if this error is retryable.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
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
                service: "twilio".into(),
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
                        service: "twilio".into(),
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
                message: "Twilio API authentication failed".into(),
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
    use fcp_core::FcpError;

    #[test]
    fn test_api_401_maps_to_unauthorized() {
        let err = TwilioError::Api {
            message: "bad creds".into(),
            status_code: Some(401),
            error_code: None,
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::Unauthorized { code: 2001, .. }));
    }

    #[test]
    fn test_api_403_maps_to_unauthorized() {
        let err = TwilioError::Api {
            message: "forbidden".into(),
            status_code: Some(403),
            error_code: None,
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::Unauthorized { code: 2001, .. }));
    }

    #[test]
    fn test_api_429_maps_to_rate_limited() {
        let err = TwilioError::Api {
            message: "rate limited".into(),
            status_code: Some(429),
            error_code: None,
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(
            fcp,
            FcpError::RateLimited {
                retry_after_ms: 60_000,
                ..
            }
        ));
    }

    #[test]
    fn test_api_500_maps_to_retryable_external() {
        let err = TwilioError::Api {
            message: "server error".into(),
            status_code: Some(500),
            error_code: None,
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(
            fcp,
            FcpError::External {
                retryable: true,
                ..
            }
        ));
    }

    #[test]
    fn test_api_502_503_are_retryable() {
        for code in [502, 503] {
            let err = TwilioError::Api {
                message: format!("error {code}"),
                status_code: Some(code),
                error_code: None,
            };
            assert!(err.is_retryable(), "API {code} should be retryable");
            let fcp = err.to_fcp_error();
            assert!(
                matches!(
                    fcp,
                    FcpError::External {
                        retryable: true,
                        ..
                    }
                ),
                "API {code} should map to retryable External"
            );
        }
    }

    #[test]
    fn test_rate_limited_variant_maps_correctly() {
        let err = TwilioError::RateLimited {
            retry_after_ms: 5000,
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
    fn test_unauthorized_variant_maps_to_fcp_unauthorized() {
        let err = TwilioError::Unauthorized;
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::Unauthorized { code: 2001, .. }));
    }

    #[test]
    fn test_not_found_maps_to_resource_not_found() {
        let err = TwilioError::NotFound {
            resource: "message:SM123".into(),
        };
        let fcp = err.to_fcp_error();
        assert!(
            matches!(fcp, FcpError::ResourceNotFound { resource } if resource.contains("SM123"))
        );
    }

    #[test]
    fn test_json_error_maps_to_internal() {
        let json_err: serde_json::Error =
            serde_json::from_str::<serde_json::Value>("invalid").unwrap_err();
        let err = TwilioError::Json(json_err);
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::Internal { message } if message.contains("JSON error")));
    }

    #[test]
    fn test_retryable_checks() {
        // Retryable
        assert!(TwilioError::RateLimited { retry_after_ms: 1 }.is_retryable());
        assert!(
            TwilioError::Api {
                message: String::new(),
                status_code: Some(429),
                error_code: None,
            }
            .is_retryable()
        );
        assert!(
            TwilioError::Api {
                message: String::new(),
                status_code: Some(500),
                error_code: None,
            }
            .is_retryable()
        );
        assert!(
            TwilioError::Api {
                message: String::new(),
                status_code: Some(503),
                error_code: None,
            }
            .is_retryable()
        );

        // Not retryable
        assert!(!TwilioError::Unauthorized.is_retryable());
        assert!(
            !TwilioError::NotFound {
                resource: "x".into()
            }
            .is_retryable()
        );
        assert!(
            !TwilioError::Api {
                message: String::new(),
                status_code: Some(401),
                error_code: None,
            }
            .is_retryable()
        );
        assert!(
            !TwilioError::Api {
                message: String::new(),
                status_code: Some(404),
                error_code: None,
            }
            .is_retryable()
        );
    }

    #[test]
    fn test_retry_after_extraction() {
        assert_eq!(
            TwilioError::RateLimited {
                retry_after_ms: 3000
            }
            .retry_after()
            .map(|d| d.as_millis()),
            Some(3000)
        );
        assert!(TwilioError::Unauthorized.retry_after().is_none());
        assert!(
            TwilioError::Api {
                message: String::new(),
                status_code: Some(429),
                error_code: None,
            }
            .retry_after()
            .is_none()
        );
    }

    #[test]
    fn test_api_no_status_maps_to_external() {
        let err = TwilioError::Api {
            message: "unknown".into(),
            status_code: None,
            error_code: Some("20003".into()),
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::External { .. }));
    }
}
