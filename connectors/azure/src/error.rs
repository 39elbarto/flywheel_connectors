use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_core::FcpError;
use fcp_sdk::migration::ConnectorErrorMapping;

pub type AzureResult<T> = Result<T, AzureError>;

#[derive(Debug, thiserror::Error)]
pub enum AzureError {
    #[error("HTTP transport error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Azure API error: {message} (status {status_code:?}, code {code:?})")]
    Api {
        message: String,
        status_code: Option<u16>,
        code: Option<String>,
    },

    #[error("Rate limited (retry after {retry_after_ms}ms)")]
    RateLimited { retry_after_ms: u64 },

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    #[error("Async error: {0}")]
    Async(String),
}

impl AzureError {
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::RateLimited { .. } => true,
            Self::Api { status_code, .. } => matches!(status_code, Some(429 | 500..=599)),
            Self::Json(_)
            | Self::Unauthorized(_)
            | Self::NotFound(_)
            | Self::Validation(_)
            | Self::Config(_)
            | Self::InvalidResponse(_)
            | Self::Async(_) => false,
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
            Self::Http(error) => FcpError::External {
                service: "azure".into(),
                message: error.to_string(),
                status_code: error.status().map(|status| status.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Json(error) => FcpError::Internal {
                message: format!("JSON parse error: {error}"),
            },
            Self::Api {
                message,
                status_code,
                ..
            } => FcpError::External {
                service: "azure".into(),
                message: message.clone(),
                status_code: *status_code,
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::RateLimited { retry_after_ms } => FcpError::RateLimited {
                retry_after_ms: *retry_after_ms,
                violation: None,
            },
            Self::Unauthorized(message) => FcpError::Unauthorized {
                code: 2001,
                message: message.clone(),
            },
            Self::NotFound(resource) => FcpError::ResourceNotFound {
                resource: resource.clone(),
            },
            Self::Validation(message) => FcpError::InvalidRequest {
                code: 1003,
                message: message.clone(),
            },
            Self::Config(message) => FcpError::InvalidRequest {
                code: 1001,
                message: message.clone(),
            },
            Self::InvalidResponse(message) | Self::Async(message) => FcpError::Internal {
                message: message.clone(),
            },
        }
    }
}

impl ConnectorErrorMapping for AzureError {
    fn from_async_error(error: AsyncError) -> Self {
        match error {
            AsyncError::Timeout { timeout_ms } => {
                Self::Async(format!("request deadline exceeded after {timeout_ms}ms"))
            }
            AsyncError::Cancelled => Self::Async("operation cancelled".into()),
            other => Self::Async(other.to_string()),
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
        let err = AzureError::RateLimited {
            retry_after_ms: 5_000,
        };
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn unauthorized_maps_to_fcp_unauthorized() {
        let err = AzureError::Unauthorized("bad token".into());
        match err.to_fcp_error() {
            FcpError::Unauthorized { code, message } => {
                assert_eq!(code, 2001);
                assert_eq!(message, "bad token");
            }
            other => panic!("expected unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn validation_maps_to_invalid_request() {
        let err = AzureError::Validation("subscription_id is required".into());
        match err.to_fcp_error() {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1003);
                assert_eq!(message, "subscription_id is required");
            }
            other => panic!("expected invalid request, got {other:?}"),
        }
    }

    #[test]
    fn config_maps_to_invalid_request_1001() {
        let err = AzureError::Config("missing bearer token".into());
        match err.to_fcp_error() {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1001);
                assert_eq!(message, "missing bearer token");
            }
            other => panic!("expected invalid request, got {other:?}"),
        }
    }

    #[test]
    fn not_found_maps_to_resource_not_found() {
        let err = AzureError::NotFound("resource group rg-1".into());
        match err.to_fcp_error() {
            FcpError::ResourceNotFound { resource } => {
                assert_eq!(resource, "resource group rg-1");
            }
            other => panic!("expected resource not found, got {other:?}"),
        }
    }

    #[test]
    fn json_error_is_not_retryable() {
        let err = AzureError::Json(serde_json::from_str::<String>("invalid").unwrap_err());
        assert!(!err.is_retryable());
        assert!(err.retry_after().is_none());
    }

    #[test]
    fn api_error_5xx_is_retryable() {
        let err = AzureError::Api {
            message: "internal".into(),
            status_code: Some(503),
            code: None,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_error_4xx_not_retryable() {
        let err = AzureError::Api {
            message: "bad".into(),
            status_code: Some(400),
            code: None,
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn async_timeout_is_preserved() {
        let err = AzureError::from_async_error(AsyncError::Timeout { timeout_ms: 3_000 });
        assert_eq!(
            err.to_string(),
            "Async error: request deadline exceeded after 3000ms"
        );
    }

    #[test]
    fn async_cancelled_is_preserved() {
        let err = AzureError::from_async_error(AsyncError::Cancelled);
        assert_eq!(err.to_string(), "Async error: operation cancelled");
    }

    #[test]
    fn invalid_response_maps_to_internal() {
        let err = AzureError::InvalidResponse("unexpected XML".into());
        match err.to_fcp_error() {
            FcpError::Internal { message } => {
                assert_eq!(message, "unexpected XML");
            }
            other => panic!("expected internal, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_maps_to_fcp_rate_limited() {
        let err = AzureError::RateLimited {
            retry_after_ms: 2_000,
        };
        match err.to_fcp_error() {
            FcpError::RateLimited {
                retry_after_ms,
                violation,
            } => {
                assert_eq!(retry_after_ms, 2_000);
                assert!(violation.is_none());
            }
            other => panic!("expected rate limited, got {other:?}"),
        }
    }
}
