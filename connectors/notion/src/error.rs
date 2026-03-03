//! Notion-specific error types.

use std::time::Duration;

use fcp_core::FcpError;

/// Notion API error.
#[derive(Debug, thiserror::Error)]
pub enum NotionError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Notion API error: {message}")]
    Api {
        message: String,
        status_code: Option<u16>,
    },

    #[error("Rate limited")]
    RateLimited { retry_after_ms: u64 },

    #[error("Unauthorized")]
    Unauthorized,

    #[error("Not found: {resource}")]
    NotFound { resource: String },

    #[error("Validation error: {message}")]
    Validation { message: String },
}

pub type NotionResult<T> = Result<T, NotionError>;

impl NotionError {
    /// Check if this error is retryable.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::RateLimited { .. } => true,
            Self::Api { status_code, .. } => matches!(status_code, Some(500..=599 | 429)),
            Self::Json(_)
            | Self::Unauthorized
            | Self::NotFound { .. }
            | Self::Validation { .. } => false,
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
                service: "notion".into(),
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
                        service: "notion".into(),
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
                message: "Notion API authentication failed".into(),
            },
            Self::NotFound { resource } => FcpError::ResourceNotFound {
                resource: resource.clone(),
            },
            Self::Validation { message } => FcpError::InvalidRequest {
                code: 1003,
                message: message.clone(),
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
        let err = NotionError::Api {
            message: "bad token".into(),
            status_code: Some(401),
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::Unauthorized { code: 2001, .. }));
    }

    #[test]
    fn test_api_403_maps_to_unauthorized() {
        let err = NotionError::Api {
            message: "forbidden".into(),
            status_code: Some(403),
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::Unauthorized { code: 2001, .. }));
    }

    #[test]
    fn test_api_429_maps_to_rate_limited() {
        let err = NotionError::Api {
            message: "rate limited".into(),
            status_code: Some(429),
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
        let err = NotionError::Api {
            message: "server error".into(),
            status_code: Some(500),
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
    fn test_rate_limited_variant_maps_correctly() {
        let err = NotionError::RateLimited {
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
        let err = NotionError::Unauthorized;
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::Unauthorized { code: 2001, .. }));
    }

    #[test]
    fn test_not_found_maps_to_resource_not_found() {
        let err = NotionError::NotFound {
            resource: "page:abc123".into(),
        };
        let fcp = err.to_fcp_error();
        assert!(
            matches!(fcp, FcpError::ResourceNotFound { resource } if resource.contains("abc123"))
        );
    }

    #[test]
    fn test_validation_maps_to_invalid_request() {
        let err = NotionError::Validation {
            message: "bad input".into(),
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::InvalidRequest { code: 1003, .. }));
    }

    #[test]
    fn test_json_error_maps_to_internal() {
        let json_err: serde_json::Error =
            serde_json::from_str::<serde_json::Value>("invalid").unwrap_err();
        let err = NotionError::Json(json_err);
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::Internal { message } if message.contains("JSON error")));
    }

    #[test]
    fn test_retryable_checks() {
        assert!(NotionError::RateLimited { retry_after_ms: 1 }.is_retryable());
        assert!(
            NotionError::Api {
                message: String::new(),
                status_code: Some(500),
            }
            .is_retryable()
        );
        assert!(
            NotionError::Api {
                message: String::new(),
                status_code: Some(502),
            }
            .is_retryable()
        );
        assert!(
            NotionError::Api {
                message: String::new(),
                status_code: Some(503),
            }
            .is_retryable()
        );
        assert!(
            NotionError::Api {
                message: String::new(),
                status_code: Some(429),
            }
            .is_retryable()
        );

        assert!(!NotionError::Unauthorized.is_retryable());
        assert!(
            !NotionError::NotFound {
                resource: "x".into()
            }
            .is_retryable()
        );
        assert!(
            !NotionError::Validation {
                message: "x".into()
            }
            .is_retryable()
        );
        assert!(
            !NotionError::Api {
                message: String::new(),
                status_code: Some(401),
            }
            .is_retryable()
        );
        assert!(
            !NotionError::Api {
                message: String::new(),
                status_code: Some(404),
            }
            .is_retryable()
        );
    }

    #[test]
    fn test_retry_after_extraction() {
        assert_eq!(
            NotionError::RateLimited {
                retry_after_ms: 3000
            }
            .retry_after()
            .map(|d| d.as_millis()),
            Some(3000)
        );
        assert!(NotionError::Unauthorized.retry_after().is_none());
        assert!(
            NotionError::Api {
                message: String::new(),
                status_code: Some(429),
            }
            .retry_after()
            .is_none()
        );
    }
}
