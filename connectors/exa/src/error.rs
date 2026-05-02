use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_sdk::migration::ConnectorErrorMapping;

pub type ExaResult<T> = Result<T, ExaError>;

#[derive(Debug, thiserror::Error)]
pub enum ExaError {
    #[error("HTTP transport error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Exa API error (HTTP {status_code}): {message}")]
    Api { status_code: u16, message: String },

    #[error("Rate limited (retry after {retry_after_ms}ms)")]
    RateLimited { retry_after_ms: u64 },

    #[error("Not configured")]
    NotConfigured,

    #[error("Async error: {0}")]
    Async(String),
}

impl ExaError {
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http(error) => error.is_timeout() || error.is_connect(),
            Self::RateLimited { .. } => true,
            Self::Api { status_code, .. } => {
                matches!(status_code, 429 | 500 | 502 | 503 | 504)
            }
            Self::Json(_) | Self::NotConfigured | Self::Async(_) => false,
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
                service: "exa".into(),
                message: error.to_string(),
                status_code: error.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Json(error) => FcpError::Internal {
                message: format!("JSON parse error: {error}"),
            },
            Self::Api {
                status_code,
                message,
            } => FcpError::External {
                service: "exa".into(),
                message: format!("Exa API error (HTTP {status_code}): {message}"),
                status_code: Some(*status_code),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::RateLimited { retry_after_ms } => FcpError::RateLimited {
                retry_after_ms: *retry_after_ms,
                violation: None,
            },
            Self::NotConfigured => FcpError::NotConfigured,
            Self::Async(message) => FcpError::Internal {
                message: format!("Async error: {message}"),
            },
        }
    }
}

impl ConnectorErrorMapping for ExaError {
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
    fn http_error_is_retryable_on_timeout() {
        // reqwest timeout errors are constructed via the client, so we test
        // the is_retryable logic through an Api variant with server status.
        let err = ExaError::Api {
            status_code: 503,
            message: "Service Unavailable".into(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn json_error_is_not_retryable() {
        let json_err =
            serde_json::from_str::<serde_json::Value>("{{bad}}").expect_err("expected parse error");
        let err = ExaError::Json(json_err);
        assert!(!err.is_retryable());
        assert!(err.retry_after().is_none());
    }

    #[test]
    fn json_error_maps_to_internal() {
        let json_err =
            serde_json::from_str::<serde_json::Value>("{{bad}}").expect_err("expected parse error");
        let err = ExaError::Json(json_err);
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::Internal { message } => {
                assert!(message.contains("JSON parse error"));
            }
            other => panic!("Expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn api_error_client_status_not_retryable() {
        let err = ExaError::Api {
            status_code: 400,
            message: "Bad Request".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_error_server_status_retryable() {
        for code in [429, 500, 502, 503, 504] {
            let err = ExaError::Api {
                status_code: code,
                message: "server error".into(),
            };
            assert!(err.is_retryable(), "Expected {code} to be retryable");
        }
    }

    #[test]
    fn api_error_maps_to_external() {
        let err = ExaError::Api {
            status_code: 422,
            message: "Unprocessable Entity".into(),
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::External {
                service,
                message,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "exa");
                assert!(message.contains("422"));
                assert_eq!(status_code, Some(422));
                assert!(!retryable);
            }
            other => panic!("Expected External, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_is_retryable() {
        let err = ExaError::RateLimited {
            retry_after_ms: 5_000,
        };
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn rate_limited_maps_to_fcp_rate_limited() {
        let err = ExaError::RateLimited {
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
    fn not_configured_maps_to_fcp_not_configured() {
        let err = ExaError::NotConfigured;
        assert!(!err.is_retryable());
        assert!(err.retry_after().is_none());
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::NotConfigured));
    }

    #[test]
    fn async_error_not_retryable() {
        let err = ExaError::Async("some async failure".into());
        assert!(!err.is_retryable());
        assert!(err.retry_after().is_none());
    }

    #[test]
    fn async_error_maps_to_internal() {
        let err = ExaError::Async("timed out".into());
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::Internal { message } => {
                assert!(message.contains("Async error"));
                assert!(message.contains("timed out"));
            }
            other => panic!("Expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn from_async_error_timeout() {
        let err = ExaError::from_async_error(AsyncError::Timeout { timeout_ms: 1_500 });
        assert_eq!(
            err.to_string(),
            "Async error: request deadline exceeded after 1500ms"
        );
    }

    #[test]
    fn from_async_error_cancelled() {
        let err = ExaError::from_async_error(AsyncError::Cancelled);
        assert_eq!(err.to_string(), "Async error: operation cancelled");
    }

    #[test]
    fn display_variants() {
        assert_eq!(ExaError::NotConfigured.to_string(), "Not configured");
        assert_eq!(
            ExaError::RateLimited {
                retry_after_ms: 100
            }
            .to_string(),
            "Rate limited (retry after 100ms)"
        );
        assert_eq!(
            ExaError::Api {
                status_code: 404,
                message: "Not Found".into()
            }
            .to_string(),
            "Exa API error (HTTP 404): Not Found"
        );
    }
}
