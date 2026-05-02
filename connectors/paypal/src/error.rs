use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_sdk::migration::ConnectorErrorMapping;

pub type PayPalResult<T> = Result<T, PayPalError>;

#[derive(Debug, thiserror::Error)]
pub enum PayPalError {
    #[error("HTTP transport error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("PayPal API error {code}: {message}")]
    Api { code: u32, message: String },

    #[error("Rate limited (retry after {retry_after_ms}ms)")]
    RateLimited { retry_after_ms: u64 },

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Async error: {0}")]
    Async(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("OAuth error: {0}")]
    OAuth(String),
}

impl PayPalError {
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http(error) => error.is_timeout() || error.is_connect(),
            Self::RateLimited { .. } => true,
            Self::Api { code, .. } => matches!(code, 500 | 502 | 503 | 504),
            Self::Json(_)
            | Self::Unauthorized(_)
            | Self::NotFound(_)
            | Self::Async(_)
            | Self::Config(_)
            | Self::InvalidInput(_)
            | Self::OAuth(_) => false,
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
                service: "paypal".into(),
                message: error.to_string(),
                status_code: error.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Json(error) => FcpError::Internal {
                message: format!("JSON parse error: {error}"),
            },
            Self::Api { code, message } => FcpError::External {
                service: "paypal".into(),
                message: format!("PayPal API error {code}: {message}"),
                status_code: u16::try_from(*code).ok(),
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
            Self::Async(message) => FcpError::Internal {
                message: format!("Async error: {message}"),
            },
            Self::Config(message) => FcpError::InvalidRequest {
                code: 1001,
                message: format!("Configuration error: {message}"),
            },
            Self::InvalidInput(message) => FcpError::InvalidRequest {
                code: 1005,
                message: message.clone(),
            },
            Self::OAuth(message) => FcpError::Unauthorized {
                code: 2002,
                message: format!("OAuth error: {message}"),
            },
        }
    }
}

impl ConnectorErrorMapping for PayPalError {
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
        let err = PayPalError::RateLimited {
            retry_after_ms: 5_000,
        };
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn unauthorized_is_not_retryable() {
        let err = PayPalError::Unauthorized("bad credentials".into());
        assert!(!err.is_retryable());
        assert!(err.retry_after().is_none());
    }

    #[test]
    fn not_found_maps_to_resource_not_found() {
        let err = PayPalError::NotFound("order 123".into());
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::ResourceNotFound { resource } => assert_eq!(resource, "order 123"),
            other => panic!("Expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn api_error_retryable_for_server_errors() {
        let retryable = PayPalError::Api {
            code: 500,
            message: "Internal".into(),
        };
        assert!(retryable.is_retryable());

        let terminal = PayPalError::Api {
            code: 400,
            message: "Bad request".into(),
        };
        assert!(!terminal.is_retryable());
    }

    #[test]
    fn config_error_maps_to_invalid_request() {
        let err = PayPalError::Config("missing client_id".into());
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1001);
                assert!(message.contains("missing client_id"));
            }
            other => panic!("Expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_maps_to_fcp_rate_limited() {
        let err = PayPalError::RateLimited {
            retry_after_ms: 3_000,
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::RateLimited {
                retry_after_ms,
                violation,
            } => {
                assert_eq!(retry_after_ms, 3_000);
                assert!(violation.is_none());
            }
            other => panic!("Expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn oauth_error_maps_to_unauthorized() {
        let err = PayPalError::OAuth("token exchange failed".into());
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::Unauthorized { code, message } => {
                assert_eq!(code, 2002);
                assert!(message.contains("token exchange"));
            }
            other => panic!("Expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn async_error_mapping_preserves_timeout() {
        let err = PayPalError::from_async_error(AsyncError::Timeout { timeout_ms: 1_500 });
        assert_eq!(
            err.to_string(),
            "Async error: request deadline exceeded after 1500ms"
        );
    }

    #[test]
    fn async_error_mapping_cancelled() {
        let err = PayPalError::from_async_error(AsyncError::Cancelled);
        assert!(err.to_string().contains("cancelled"));
    }

    #[test]
    fn invalid_input_maps_correctly() {
        let err = PayPalError::InvalidInput("order_id required".into());
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1005);
                assert_eq!(message, "order_id required");
            }
            other => panic!("Expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn api_502_is_retryable() {
        let err = PayPalError::Api {
            code: 502,
            message: "Bad gateway".into(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_422_is_not_retryable() {
        let err = PayPalError::Api {
            code: 422,
            message: "Unprocessable".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn oauth_is_not_retryable() {
        let err = PayPalError::OAuth("invalid_client".into());
        assert!(!err.is_retryable());
    }
}
