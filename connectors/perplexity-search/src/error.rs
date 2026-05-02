use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_sdk::migration::ConnectorErrorMapping;

pub type PerplexityResult<T> = Result<T, PerplexityError>;

#[derive(Debug, thiserror::Error)]
pub enum PerplexityError {
    #[error("HTTP transport error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Perplexity API error: {message}")]
    Api {
        status: u16,
        message: String,
        error_type: Option<String>,
    },

    #[error("Rate limited (retry after {retry_after_ms}ms)")]
    RateLimited { retry_after_ms: u64 },

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Async error: {0}")]
    Async(String),
}

impl PerplexityError {
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http(error) => error.is_timeout() || error.is_connect(),
            Self::RateLimited { .. } => true,
            Self::Api { status, .. } => matches!(status, 500 | 502 | 503 | 504 | 529),
            Self::Json(_) | Self::Unauthorized(_) | Self::InvalidInput(_) | Self::Async(_) => false,
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
                service: "perplexity".into(),
                message: error.to_string(),
                status_code: error.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Json(error) => FcpError::Internal {
                message: format!("JSON parse error: {error}"),
            },
            Self::Api {
                status,
                message,
                error_type,
            } => FcpError::External {
                service: "perplexity".into(),
                message: format!(
                    "Perplexity API error (HTTP {status}{}): {message}",
                    error_type
                        .as_ref()
                        .map(|t| format!(", type={t}"))
                        .unwrap_or_default()
                ),
                status_code: Some(*status),
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
            Self::InvalidInput(message) => FcpError::InvalidRequest {
                code: 1005,
                message: message.clone(),
            },
            Self::Async(message) => FcpError::Internal {
                message: format!("Async error: {message}"),
            },
        }
    }
}

impl ConnectorErrorMapping for PerplexityError {
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
        let err = PerplexityError::RateLimited {
            retry_after_ms: 5_000,
        };
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn unauthorized_is_not_retryable() {
        let err = PerplexityError::Unauthorized("bad key".into());
        assert!(!err.is_retryable());
        assert!(err.retry_after().is_none());
    }

    #[test]
    fn api_error_retryable_for_server_errors() {
        let retryable = PerplexityError::Api {
            status: 500,
            message: "Internal Server Error".into(),
            error_type: None,
        };
        assert!(retryable.is_retryable());

        let terminal = PerplexityError::Api {
            status: 400,
            message: "Bad Request".into(),
            error_type: None,
        };
        assert!(!terminal.is_retryable());
    }

    #[test]
    fn invalid_input_maps_to_invalid_request() -> Result<(), String> {
        let err = PerplexityError::InvalidInput("missing query".into());
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1005);
                assert!(message.contains("missing query"));
                Ok(())
            }
            other => Err(format!("Expected InvalidRequest, got {other:?}")),
        }
    }

    #[test]
    fn rate_limited_maps_to_fcp_rate_limited() -> Result<(), String> {
        let err = PerplexityError::RateLimited {
            retry_after_ms: 2_000,
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::RateLimited {
                retry_after_ms,
                violation,
            } => {
                assert_eq!(retry_after_ms, 2_000);
                assert!(violation.is_none());
                Ok(())
            }
            other => Err(format!("Expected RateLimited, got {other:?}")),
        }
    }

    #[test]
    fn unauthorized_maps_to_fcp_unauthorized() -> Result<(), String> {
        let err = PerplexityError::Unauthorized("Invalid API key".into());
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::Unauthorized { code, message } => {
                assert_eq!(code, 2001);
                assert!(message.contains("Invalid API key"));
                Ok(())
            }
            other => Err(format!("Expected Unauthorized, got {other:?}")),
        }
    }

    #[test]
    fn api_error_includes_error_type_in_message() -> Result<(), String> {
        let err = PerplexityError::Api {
            status: 422,
            message: "Model not found".into(),
            error_type: Some("invalid_request_error".into()),
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::External { message, .. } => {
                assert!(message.contains("422"));
                assert!(message.contains("invalid_request_error"));
                assert!(message.contains("Model not found"));
                Ok(())
            }
            other => Err(format!("Expected External, got {other:?}")),
        }
    }

    #[test]
    fn async_error_mapping_preserves_timeout() {
        let err = PerplexityError::from_async_error(AsyncError::Timeout { timeout_ms: 3_000 });
        assert_eq!(
            err.to_string(),
            "Async error: request deadline exceeded after 3000ms"
        );
    }

    #[test]
    fn json_error_is_not_retryable() {
        let err: PerplexityError = serde_json::from_str::<serde_json::Value>("not valid json")
            .unwrap_err()
            .into();
        assert!(!err.is_retryable());
    }

    #[test]
    fn http_529_is_retryable() {
        let err = PerplexityError::Api {
            status: 529,
            message: "Overloaded".into(),
            error_type: None,
        };
        assert!(err.is_retryable());
    }
}
