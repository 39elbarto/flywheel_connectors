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
        assert!(
            StripeError::RateLimited {
                retry_after_ms: 1000
            }
            .to_string()
            .contains("Rate limited")
        );
    }

    #[test]
    fn is_retryable_rate_limited() {
        assert!(
            StripeError::RateLimited {
                retry_after_ms: 1000
            }
            .is_retryable()
        );
    }

    #[test]
    fn is_retryable_api_500() {
        assert!(
            StripeError::Api {
                message: "x".into(),
                status_code: Some(500),
                error_type: None,
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_api_400() {
        assert!(
            !StripeError::Api {
                message: "x".into(),
                status_code: Some(400),
                error_type: None,
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_unauthorized() {
        assert!(!StripeError::Unauthorized.is_retryable());
    }

    #[test]
    fn not_retryable_not_found() {
        assert!(
            !StripeError::NotFound {
                resource: "x".into()
            }
            .is_retryable()
        );
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
            FcpError::RateLimited { retry_after_ms, .. } => assert_eq!(retry_after_ms, 60_000),
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
            FcpError::RateLimited { retry_after_ms, .. } => assert_eq!(retry_after_ms, 2000),
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

    // --- Display for remaining variants ---

    #[test]
    fn display_unauthorized() {
        let err = StripeError::Unauthorized;
        assert_eq!(err.to_string(), "Unauthorized");
    }

    #[test]
    fn display_not_found() {
        let err = StripeError::NotFound {
            resource: "cus_abc".into(),
        };
        let display = err.to_string();
        assert!(display.contains("Not found"));
        assert!(display.contains("cus_abc"));
    }

    #[test]
    fn display_json() {
        let json_err = serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err();
        let err = StripeError::Json(json_err);
        let display = err.to_string();
        assert!(display.contains("JSON error"));
    }

    // --- is_retryable additional cases ---

    #[test]
    fn is_retryable_api_429() {
        assert!(
            StripeError::Api {
                message: "too many requests".into(),
                status_code: Some(429),
                error_type: None,
            }
            .is_retryable()
        );
    }

    #[test]
    fn is_retryable_api_502() {
        assert!(
            StripeError::Api {
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
            StripeError::Api {
                message: "service unavailable".into(),
                status_code: Some(503),
                error_type: None,
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_json() {
        let json_err = serde_json::from_str::<serde_json::Value>("x").unwrap_err();
        let err = StripeError::Json(json_err);
        assert!(!err.is_retryable());
    }

    // --- retry_after additional cases ---

    #[test]
    fn retry_after_api_none() {
        let err = StripeError::Api {
            message: "error".into(),
            status_code: Some(500),
            error_type: None,
        };
        assert_eq!(err.retry_after(), None);
    }

    #[test]
    fn retry_after_not_found_none() {
        let err = StripeError::NotFound {
            resource: "sub_123".into(),
        };
        assert_eq!(err.retry_after(), None);
    }

    #[test]
    fn retry_after_json_none() {
        let json_err = serde_json::from_str::<serde_json::Value>("x").unwrap_err();
        let err = StripeError::Json(json_err);
        assert_eq!(err.retry_after(), None);
    }

    // --- to_fcp_error additional cases ---

    #[test]
    fn to_fcp_error_api_403_maps_to_unauthorized() {
        let err = StripeError::Api {
            message: "forbidden".into(),
            status_code: Some(403),
            error_type: None,
        };
        match err.to_fcp_error() {
            FcpError::Unauthorized { code, message } => {
                assert_eq!(code, 2001);
                assert_eq!(message, "forbidden");
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_400_maps_to_external() {
        let err = StripeError::Api {
            message: "bad request".into(),
            status_code: Some(400),
            error_type: Some("invalid_request_error".into()),
        };
        match err.to_fcp_error() {
            FcpError::External {
                service,
                message,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "stripe");
                assert_eq!(message, "bad request");
                assert_eq!(status_code, Some(400));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_no_status_code() {
        let err = StripeError::Api {
            message: "unknown".into(),
            status_code: None,
            error_type: None,
        };
        match err.to_fcp_error() {
            FcpError::External {
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(status_code, None);
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    // --- Debug format assertions ---

    #[test]
    fn debug_api() {
        let err = StripeError::Api {
            message: "bad".into(),
            status_code: Some(422),
            error_type: Some("card_error".into()),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Api"));
        assert!(dbg.contains("bad"));
        assert!(dbg.contains("422"));
        assert!(dbg.contains("card_error"));
    }

    #[test]
    fn debug_rate_limited() {
        let err = StripeError::RateLimited {
            retry_after_ms: 3000,
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("RateLimited"));
        assert!(dbg.contains("3000"));
    }

    #[test]
    fn debug_unauthorized() {
        let dbg = format!("{:?}", StripeError::Unauthorized);
        assert!(dbg.contains("Unauthorized"));
    }

    #[test]
    fn debug_not_found() {
        let err = StripeError::NotFound {
            resource: "inv_xyz".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("NotFound"));
        assert!(dbg.contains("inv_xyz"));
    }

    #[test]
    fn debug_json() {
        let json_err = serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err();
        let err = StripeError::Json(json_err);
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Json"));
    }

    // --- Source chain for Json variant ---

    #[test]
    fn source_json_variant() {
        let json_err = serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err();
        let err = StripeError::Json(json_err);
        let source = std::error::Error::source(&err);
        assert!(source.is_some(), "Json variant should have a source");
    }

    #[test]
    fn source_unauthorized_none() {
        let err = StripeError::Unauthorized;
        let source = std::error::Error::source(&err);
        assert!(source.is_none());
    }

    #[test]
    fn source_not_found_none() {
        let err = StripeError::NotFound {
            resource: "x".into(),
        };
        let source = std::error::Error::source(&err);
        assert!(source.is_none());
    }

    #[test]
    fn source_api_none() {
        let err = StripeError::Api {
            message: "x".into(),
            status_code: None,
            error_type: None,
        };
        let source = std::error::Error::source(&err);
        assert!(source.is_none());
    }

    #[test]
    fn source_rate_limited_none() {
        let err = StripeError::RateLimited {
            retry_after_ms: 100,
        };
        let source = std::error::Error::source(&err);
        assert!(source.is_none());
    }

    // --- StripeResult with Err ---

    #[test]
    fn stripe_result_err() {
        let r: StripeResult<u32> = Err(StripeError::Unauthorized);
        assert!(r.is_err());
        assert!(matches!(r.unwrap_err(), StripeError::Unauthorized));
    }

    // --- Api with error_type preserved ---

    #[test]
    fn api_error_type_preserved() {
        let err = StripeError::Api {
            message: "card declined".into(),
            status_code: Some(402),
            error_type: Some("card_error".into()),
        };
        if let StripeError::Api {
            error_type,
            message,
            status_code,
        } = &err
        {
            assert_eq!(error_type.as_deref(), Some("card_error"));
            assert_eq!(message, "card declined");
            assert_eq!(*status_code, Some(402));
        } else {
            panic!("expected Api variant");
        }
    }

    #[test]
    fn api_none_status_code_not_retryable() {
        let err = StripeError::Api {
            message: "x".into(),
            status_code: None,
            error_type: None,
        };
        assert!(!err.is_retryable());
    }

    // --- Retry-after zero ---

    #[test]
    fn retry_after_zero_ms() {
        let err = StripeError::RateLimited {
            retry_after_ms: 0,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_millis(0)));
    }

    // --- to_fcp_error preserves message for Unauthorized ---

    #[test]
    fn to_fcp_error_unauthorized_message() {
        match StripeError::Unauthorized.to_fcp_error() {
            FcpError::Unauthorized { message, .. } => {
                assert!(message.contains("Stripe API authentication failed"));
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    // --- to_fcp_error for Json includes original message ---

    #[test]
    fn to_fcp_error_json_message_contains_detail() {
        let json_err = serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err();
        let err = StripeError::Json(json_err);
        match err.to_fcp_error() {
            FcpError::Internal { message } => {
                assert!(message.starts_with("JSON error:"));
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }
}
