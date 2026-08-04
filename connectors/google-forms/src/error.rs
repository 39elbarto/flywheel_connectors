//! Google Forms-specific error types.

use std::time::Duration;

use fcp_prelude::FcpError;
use thiserror::Error;

/// Google Forms-specific errors.
#[derive(Error, Debug)]
pub enum FormsError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Google Forms API returned an error
    #[error("Forms API error ({status_code}): {message}")]
    Api { status_code: u16, message: String },

    /// Rate limited
    #[error("Rate limited, retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },

    /// Invalid or expired token
    #[error("Invalid or expired Google Forms credentials")]
    Unauthorized,

    /// Form not found
    #[error("Form not found: {form_id}")]
    FormNotFound { form_id: String },

    /// Insufficient permissions
    #[error("Insufficient Forms permissions: {message}")]
    Forbidden { message: String },
}

impl FormsError {
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::RateLimited { .. } => true,
            Self::Api { status_code, .. } => matches!(status_code, 500..=599 | 429),
            _ => false,
        }
    }

    /// Whether replaying the request that produced this error cannot duplicate
    /// a side effect (br-kxd3e).
    ///
    /// Distinct from [`Self::is_retryable`]: a rate limit was refused WITHOUT
    /// applying anything, so replaying is safe; a 5xx means Google received
    /// the request and a `batchUpdate` may already have applied the form change.
    #[must_use]
    pub fn replay_is_safe(&self) -> bool {
        match self {
            Self::RateLimited { .. } => true,
            Self::Api { status_code, .. } => *status_code == 429,
            Self::Http(e) => !fcp_sdk::migration::transport_error_reached_service(e),
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
                service: "google_forms".into(),
                message: "Google Forms transport request failed".into(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Json(_) => FcpError::Internal {
                message: "Google Forms response could not be decoded".into(),
            },
            Self::Api {
                status_code: 401 | 403,
                message: _,
            } => FcpError::Unauthorized {
                code: 2001,
                message: "Google Forms authorization failed".into(),
            },
            Self::Api {
                status_code: 404,
                message: _,
            } => FcpError::ResourceNotFound {
                resource: "google_forms_form".into(),
            },
            Self::Api {
                status_code: 429, ..
            } => FcpError::RateLimited {
                retry_after_ms: 60_000,
                violation: None,
            },
            Self::Api {
                status_code,
                message: _,
            } => FcpError::External {
                service: "google_forms".into(),
                message: "Google Forms provider rejected the request".into(),
                status_code: Some(*status_code),
                retryable: self.is_retryable(),
                retry_after: None,
            },
            Self::RateLimited { retry_after_ms } => FcpError::RateLimited {
                retry_after_ms: *retry_after_ms,
                violation: None,
            },
            Self::Unauthorized => FcpError::Unauthorized {
                code: 2001,
                message: "Invalid or expired Google Forms credentials".into(),
            },
            Self::FormNotFound { .. } => FcpError::ResourceNotFound {
                resource: "google_forms_form".into(),
            },
            Self::Forbidden { .. } => FcpError::Unauthorized {
                code: 2001,
                message: "Google Forms permission denied".into(),
            },
        }
    }
}

impl fcp_sdk::ConnectorErrorMapping for FormsError {
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

/// Result type for Forms operations.
pub type FormsResult<T> = Result<T, FormsError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unauthorized_not_retryable() {
        assert!(!FormsError::Unauthorized.is_retryable());
    }

    #[test]
    fn rate_limited_is_retryable() {
        assert!(
            FormsError::RateLimited {
                retry_after_ms: 5000
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_500_is_retryable() {
        assert!(
            FormsError::Api {
                status_code: 500,
                message: "err".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_400_not_retryable() {
        assert!(
            !FormsError::Api {
                status_code: 400,
                message: "bad".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn retry_after_for_rate_limited() {
        let err = FormsError::RateLimited {
            retry_after_ms: 30_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn retry_after_none_for_unauthorized() {
        assert_eq!(FormsError::Unauthorized.retry_after(), None);
    }

    #[test]
    fn to_fcp_error_unauthorized() {
        assert!(matches!(
            FormsError::Unauthorized.to_fcp_error(),
            FcpError::Unauthorized { code: 2001, .. }
        ));
    }

    #[test]
    fn to_fcp_error_form_not_found() {
        let err = FormsError::FormNotFound {
            form_id: "abc".into(),
        };
        assert!(matches!(
            err.to_fcp_error(),
            FcpError::ResourceNotFound { resource } if resource == "google_forms_form"
        ));
    }

    #[test]
    fn to_fcp_error_api_429() {
        let err = FormsError::Api {
            status_code: 429,
            message: "rate limited".into(),
        };
        assert!(matches!(err.to_fcp_error(), FcpError::RateLimited { .. }));
    }

    #[test]
    fn to_fcp_error_json() {
        let json_err = serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err();
        assert!(matches!(
            FormsError::Json(json_err).to_fcp_error(),
            FcpError::Internal { message } if message == "Google Forms response could not be decoded"
        ));
    }

    #[test]
    fn to_fcp_error_api_401() {
        let err = FormsError::Api {
            status_code: 401,
            message: "bad token".into(),
        };
        assert!(matches!(err.to_fcp_error(), FcpError::Unauthorized { .. }));
    }

    #[test]
    fn to_fcp_error_api_500() {
        let err = FormsError::Api {
            status_code: 500,
            message: "internal".into(),
        };
        assert!(matches!(
            err.to_fcp_error(),
            FcpError::External {
                service,
                retryable: true,
                ..
            } if service == "google_forms"
        ));
    }

    #[test]
    fn display_all_variants() {
        let _ = FormsError::Unauthorized.to_string();
        let _ = FormsError::RateLimited {
            retry_after_ms: 5000,
        }
        .to_string();
        let _ = FormsError::FormNotFound {
            form_id: "x".into(),
        }
        .to_string();
        let _ = FormsError::Forbidden {
            message: "no".into(),
        }
        .to_string();
        let _ = FormsError::Api {
            status_code: 500,
            message: "err".into(),
        }
        .to_string();
    }

    // ── ConnectorErrorMapping ────────────────────────────────────────

    #[test]
    fn connector_error_mapping_timeout() {
        use fcp_async_core::AsyncError;
        use fcp_sdk::ConnectorErrorMapping;
        let err = FormsError::from_async_error(AsyncError::Timeout { timeout_ms: 3000 });
        assert!(matches!(
            err,
            FormsError::Api {
                status_code: 408,
                ..
            }
        ));
    }

    #[test]
    fn connector_error_mapping_cancelled() {
        use fcp_async_core::AsyncError;
        use fcp_sdk::ConnectorErrorMapping;
        let err = FormsError::from_async_error(AsyncError::Cancelled);
        assert!(matches!(err, FormsError::Api { status_code: 0, .. }));
    }

    #[test]
    fn connector_error_mapping_to_fcp_delegates() {
        use fcp_sdk::ConnectorErrorMapping;
        let err = FormsError::Unauthorized;
        let fcp = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp, FcpError::Unauthorized { .. }));
    }

    #[test]
    fn connector_error_mapping_is_retryable_delegates() {
        use fcp_sdk::ConnectorErrorMapping;
        let err = FormsError::RateLimited {
            retry_after_ms: 5000,
        };
        assert!(ConnectorErrorMapping::is_retryable(&err));
    }

    #[test]
    fn connector_error_mapping_retry_after_delegates() {
        use fcp_sdk::ConnectorErrorMapping;
        let err = FormsError::RateLimited {
            retry_after_ms: 60_000,
        };
        assert_eq!(
            ConnectorErrorMapping::retry_after(&err),
            Some(Duration::from_secs(60))
        );
    }
}
