//! Matrix connector error types.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_core::FcpError;
use fcp_sdk::migration::ConnectorErrorMapping;
use thiserror::Error;

/// Matrix connector errors.
#[derive(Error, Debug)]
pub enum MatrixError {
    /// HTTP transport error.
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Matrix API error.
    #[error("Matrix error ({errcode}): {message}")]
    Api {
        errcode: String,
        message: String,
        status_code: u16,
    },

    /// Rate limited.
    #[error("Rate limited, retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },

    /// Authentication failure.
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    /// Forbidden.
    #[error("Forbidden: {0}")]
    Forbidden(String),

    /// Not found.
    #[error("Not found: {0}")]
    NotFound(String),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(String),

    /// Runtime error.
    #[error("Runtime error: {0}")]
    Runtime(String),

    /// Cancelled.
    #[error("Operation cancelled")]
    Cancelled,
}

impl MatrixError {
    /// Whether this error is retryable.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::RateLimited { .. } | Self::Runtime(_) => true,
            Self::Api { status_code, .. } => matches!(*status_code, 429 | 500 | 502 | 503 | 504),
            Self::Json(_)
            | Self::Unauthorized(_)
            | Self::Forbidden(_)
            | Self::NotFound(_)
            | Self::Config(_)
            | Self::Cancelled => false,
        }
    }

    /// Retry-after delay.
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
                service: "matrix".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
            Self::Api {
                errcode,
                message,
                status_code,
            } => FcpError::External {
                service: "matrix".into(),
                message: format!("{errcode}: {message}"),
                status_code: Some(*status_code),
                retryable: self.is_retryable(),
                retry_after: None,
            },
            Self::RateLimited { retry_after_ms } => FcpError::RateLimited {
                retry_after_ms: *retry_after_ms,
                violation: None,
            },
            Self::Unauthorized(msg) => FcpError::Unauthorized {
                code: 2001,
                message: msg.clone(),
            },
            Self::Forbidden(msg) => FcpError::Unauthorized {
                code: 2003,
                message: format!("Forbidden: {msg}"),
            },
            Self::NotFound(msg) => FcpError::InvalidRequest {
                code: 1004,
                message: format!("Not found: {msg}"),
            },
            Self::Config(msg) => FcpError::InvalidRequest {
                code: 1001,
                message: format!("Configuration error: {msg}"),
            },
            Self::Runtime(msg) => FcpError::Internal {
                message: format!("Runtime error: {msg}"),
            },
            Self::Cancelled => FcpError::Internal {
                message: "Operation cancelled".into(),
            },
        }
    }

    /// Create from Matrix error response.
    #[must_use]
    pub fn from_matrix_response(status: u16, body: &str) -> Self {
        if let Ok(err) = serde_json::from_str::<crate::types::MatrixErrorResponse>(body) {
            let message = err.error.unwrap_or_default();
            match err.errcode.as_str() {
                "M_UNKNOWN_TOKEN" | "M_MISSING_TOKEN" => Self::Unauthorized(message),
                "M_FORBIDDEN" => Self::Forbidden(message),
                "M_NOT_FOUND" => Self::NotFound(message),
                "M_LIMIT_EXCEEDED" => Self::RateLimited {
                    retry_after_ms: 30_000,
                },
                _ => Self::Api {
                    errcode: err.errcode,
                    message,
                    status_code: status,
                },
            }
        } else {
            match status {
                401 => Self::Unauthorized(body.to_string()),
                403 => Self::Forbidden(body.to_string()),
                404 => Self::NotFound(body.to_string()),
                429 => Self::RateLimited {
                    retry_after_ms: 30_000,
                },
                _ => Self::Api {
                    errcode: format!("HTTP_{status}"),
                    message: body.to_string(),
                    status_code: status,
                },
            }
        }
    }
}

impl ConnectorErrorMapping for MatrixError {
    fn from_async_error(error: AsyncError) -> Self {
        match error {
            AsyncError::Timeout { timeout_ms } => {
                Self::Runtime(format!("request deadline exceeded after {timeout_ms}ms"))
            }
            AsyncError::Cancelled => Self::Cancelled,
            other => Self::Runtime(other.to_string()),
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

pub type MatrixResult<T> = Result<T, MatrixError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_error_retryable() {
        let err = MatrixError::Http(
            reqwest::Client::new()
                .get("://invalid")
                .build()
                .unwrap_err(),
        );
        assert!(err.is_retryable());
    }

    #[test]
    fn rate_limited_retryable() {
        let err = MatrixError::RateLimited {
            retry_after_ms: 5000,
        };
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn unauthorized_not_retryable() {
        let err = MatrixError::Unauthorized("bad token".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn from_matrix_response_unknown_token() {
        let body = r#"{"errcode":"M_UNKNOWN_TOKEN","error":"Unrecognised access token."}"#;
        let err = MatrixError::from_matrix_response(401, body);
        assert!(matches!(err, MatrixError::Unauthorized(_)));
    }

    #[test]
    fn from_matrix_response_forbidden() {
        let body = r#"{"errcode":"M_FORBIDDEN","error":"You are not invited."}"#;
        let err = MatrixError::from_matrix_response(403, body);
        assert!(matches!(err, MatrixError::Forbidden(_)));
    }

    #[test]
    fn from_matrix_response_not_found() {
        let body = r#"{"errcode":"M_NOT_FOUND","error":"Room not found."}"#;
        let err = MatrixError::from_matrix_response(404, body);
        assert!(matches!(err, MatrixError::NotFound(_)));
    }

    #[test]
    fn from_matrix_response_rate_limited() {
        let body = r#"{"errcode":"M_LIMIT_EXCEEDED","error":"Too many requests."}"#;
        let err = MatrixError::from_matrix_response(429, body);
        assert!(matches!(err, MatrixError::RateLimited { .. }));
    }

    #[test]
    fn from_matrix_response_generic() {
        let body = r#"{"errcode":"M_BAD_JSON","error":"Bad JSON."}"#;
        let err = MatrixError::from_matrix_response(400, body);
        assert!(matches!(err, MatrixError::Api { .. }));
    }

    #[test]
    fn from_matrix_response_malformed() {
        let err = MatrixError::from_matrix_response(500, "not json");
        assert!(matches!(err, MatrixError::Api { status_code: 500, .. }));
    }

    #[test]
    fn unauthorized_maps_to_fcp() {
        let err = MatrixError::Unauthorized("expired".into());
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::Unauthorized { .. }));
    }

    #[test]
    fn config_maps_to_invalid_request() {
        let err = MatrixError::Config("missing url".into());
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn from_async_timeout() {
        let err = MatrixError::from_async_error(AsyncError::Timeout { timeout_ms: 5000 });
        assert!(matches!(err, MatrixError::Runtime(_)));
        assert!(err.is_retryable());
    }

    #[test]
    fn from_async_cancelled() {
        let err = MatrixError::from_async_error(AsyncError::Cancelled);
        assert!(matches!(err, MatrixError::Cancelled));
        assert!(!err.is_retryable());
    }

    #[test]
    fn error_display() {
        let err = MatrixError::Api {
            errcode: "M_BAD_JSON".into(),
            message: "Bad JSON".into(),
            status_code: 400,
        };
        assert!(format!("{err}").contains("M_BAD_JSON"));
    }

    #[test]
    fn api_500_retryable() {
        let err = MatrixError::Api {
            errcode: "M_UNKNOWN".into(),
            message: "Internal".into(),
            status_code: 500,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_400_not_retryable() {
        let err = MatrixError::Api {
            errcode: "M_BAD_JSON".into(),
            message: "Bad".into(),
            status_code: 400,
        };
        assert!(!err.is_retryable());
    }
}
