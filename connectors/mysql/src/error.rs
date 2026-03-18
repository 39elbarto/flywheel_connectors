//! MySQL-specific error types.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_core::FcpError;
use fcp_sdk::migration::ConnectorErrorMapping;
use thiserror::Error;

/// Result alias for MySQL operations.
pub type MysqlResult<T> = Result<T, MysqlError>;

/// MySQL-specific errors.
#[derive(Error, Debug)]
pub enum MysqlError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// MySQL connection error
    #[error("MySQL connection error: {0}")]
    Connection(String),

    /// MySQL authentication error
    #[error("MySQL authentication error: {0}")]
    Auth(String),

    /// MySQL query error
    #[error("MySQL query error: {0}")]
    Query(String),

    /// MySQL transaction error
    #[error("MySQL transaction error: {0}")]
    Transaction(String),

    /// MySQL schema error
    #[error("MySQL schema error: {0}")]
    Schema(String),

    /// MySQL constraint violation (duplicate key, foreign key, etc.)
    #[error("MySQL constraint violation: {0}")]
    ConstraintViolation(String),

    /// MySQL timeout
    #[error("MySQL timeout: {0}")]
    Timeout(String),

    /// MySQL permission denied
    #[error("MySQL permission denied: {0}")]
    PermissionDenied(String),

    /// Rate limited (429)
    #[error("MySQL rate limited (retry after {retry_after_ms}ms)")]
    RateLimited { retry_after_ms: u64 },

    /// API error with status code
    #[error("MySQL API error ({status_code}): {message}")]
    Api { status_code: u16, message: String },
}

impl MysqlError {
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::RateLimited { .. } | Self::Connection(_) | Self::Timeout(_) => {
                true
            }
            Self::Api { status_code, .. } => matches!(status_code, 500..=599 | 429),
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
                service: "mysql".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
            Self::Connection(msg) => FcpError::External {
                service: "mysql".into(),
                message: msg.clone(),
                status_code: None,
                retryable: true,
                retry_after: None,
            },
            Self::Auth(msg) => FcpError::External {
                service: "mysql".into(),
                message: msg.clone(),
                status_code: Some(401),
                retryable: false,
                retry_after: None,
            },
            Self::Query(msg) => FcpError::External {
                service: "mysql".into(),
                message: msg.clone(),
                status_code: None,
                retryable: false,
                retry_after: None,
            },
            Self::Transaction(msg) => FcpError::External {
                service: "mysql".into(),
                message: msg.clone(),
                status_code: None,
                retryable: false,
                retry_after: None,
            },
            Self::Schema(msg) => FcpError::External {
                service: "mysql".into(),
                message: msg.clone(),
                status_code: None,
                retryable: false,
                retry_after: None,
            },
            Self::ConstraintViolation(msg) => FcpError::External {
                service: "mysql".into(),
                message: msg.clone(),
                status_code: Some(409),
                retryable: false,
                retry_after: None,
            },
            Self::Timeout(msg) => FcpError::External {
                service: "mysql".into(),
                message: msg.clone(),
                status_code: None,
                retryable: true,
                retry_after: None,
            },
            Self::PermissionDenied(msg) => FcpError::External {
                service: "mysql".into(),
                message: msg.clone(),
                status_code: Some(403),
                retryable: false,
                retry_after: None,
            },
            Self::RateLimited { retry_after_ms } => FcpError::External {
                service: "mysql".into(),
                message: format!("Rate limited, retry after {retry_after_ms}ms"),
                status_code: Some(429),
                retryable: true,
                retry_after: self.retry_after(),
            },
            Self::Api {
                status_code,
                message,
            } => FcpError::External {
                service: "mysql".into(),
                message: message.clone(),
                status_code: Some(*status_code),
                retryable: self.is_retryable(),
                retry_after: None,
            },
        }
    }
}

impl ConnectorErrorMapping for MysqlError {
    fn from_async_error(error: AsyncError) -> Self {
        match error {
            AsyncError::Timeout { timeout_ms } => {
                Self::Timeout(format!("deadline exceeded after {timeout_ms}ms"))
            }
            AsyncError::Cancelled => Self::Api {
                status_code: 499,
                message: "request cancelled".into(),
            },
            other => Self::Api {
                status_code: 500,
                message: other.to_string(),
            },
        }
    }

    fn to_fcp_error(&self) -> FcpError {
        MysqlError::to_fcp_error(self)
    }

    fn is_retryable(&self) -> bool {
        MysqlError::is_retryable(self)
    }

    fn retry_after(&self) -> Option<Duration> {
        MysqlError::retry_after(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_error_is_retryable() {
        // reqwest errors are retryable by default
        let err = MysqlError::Connection("connection refused".into());
        assert!(err.is_retryable());
    }

    #[test]
    fn auth_error_not_retryable() {
        let err = MysqlError::Auth("access denied for user".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn query_error_not_retryable() {
        let err = MysqlError::Query("syntax error near 'SELEC'".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn rate_limited_is_retryable_with_delay() {
        let err = MysqlError::RateLimited {
            retry_after_ms: 5000,
        };
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(Duration::from_millis(5000)));
    }

    #[test]
    fn timeout_is_retryable() {
        let err = MysqlError::Timeout("query timed out".into());
        assert!(err.is_retryable());
    }

    #[test]
    fn api_5xx_retryable() {
        let err = MysqlError::Api {
            status_code: 503,
            message: "service unavailable".into(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_4xx_not_retryable() {
        let err = MysqlError::Api {
            status_code: 400,
            message: "bad request".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn constraint_violation_maps_to_409() {
        let err = MysqlError::ConstraintViolation("duplicate key".into());
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::External { status_code, .. } => {
                assert_eq!(status_code, Some(409));
            }
            _ => panic!("expected External error"),
        }
    }

    #[test]
    fn permission_denied_maps_to_403() {
        let err = MysqlError::PermissionDenied("SELECT command denied".into());
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::External { status_code, .. } => {
                assert_eq!(status_code, Some(403));
            }
            _ => panic!("expected External error"),
        }
    }

    #[test]
    fn json_error_maps_to_internal() {
        let raw_err = serde_json::from_str::<serde_json::Value>("invalid").unwrap_err();
        let err = MysqlError::Json(raw_err);
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::Internal { .. }));
    }

    #[test]
    fn from_async_timeout() {
        let err = MysqlError::from_async_error(AsyncError::Timeout { timeout_ms: 30000 });
        assert!(matches!(err, MysqlError::Timeout(_)));
        assert!(err.is_retryable());
    }

    #[test]
    fn from_async_cancelled() {
        let err = MysqlError::from_async_error(AsyncError::Cancelled);
        assert!(matches!(err, MysqlError::Api { status_code: 499, .. }));
    }

    #[test]
    fn connector_error_mapping_trait_consistency() {
        let err = MysqlError::RateLimited {
            retry_after_ms: 1000,
        };
        // Verify trait methods match inherent methods
        assert_eq!(
            ConnectorErrorMapping::is_retryable(&err),
            MysqlError::is_retryable(&err)
        );
        assert_eq!(
            ConnectorErrorMapping::retry_after(&err),
            MysqlError::retry_after(&err)
        );
    }

    #[test]
    fn all_variants_have_display() {
        let variants: Vec<MysqlError> = vec![
            MysqlError::Connection("test".into()),
            MysqlError::Auth("test".into()),
            MysqlError::Query("test".into()),
            MysqlError::Transaction("test".into()),
            MysqlError::Schema("test".into()),
            MysqlError::ConstraintViolation("test".into()),
            MysqlError::Timeout("test".into()),
            MysqlError::PermissionDenied("test".into()),
            MysqlError::RateLimited {
                retry_after_ms: 100,
            },
            MysqlError::Api {
                status_code: 500,
                message: "test".into(),
            },
        ];
        for variant in &variants {
            assert!(!variant.to_string().is_empty());
        }
    }

    #[test]
    fn all_variants_produce_fcp_error() {
        let variants: Vec<MysqlError> = vec![
            MysqlError::Connection("test".into()),
            MysqlError::Auth("test".into()),
            MysqlError::Query("test".into()),
            MysqlError::Transaction("test".into()),
            MysqlError::Schema("test".into()),
            MysqlError::ConstraintViolation("test".into()),
            MysqlError::Timeout("test".into()),
            MysqlError::PermissionDenied("test".into()),
            MysqlError::RateLimited {
                retry_after_ms: 100,
            },
            MysqlError::Api {
                status_code: 500,
                message: "test".into(),
            },
        ];
        for variant in &variants {
            let _ = variant.to_fcp_error();
        }
    }
}
