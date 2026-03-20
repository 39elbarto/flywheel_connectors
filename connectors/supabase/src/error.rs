use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_core::FcpError;
use fcp_sdk::migration::ConnectorErrorMapping;

pub type SupabaseResult<T> = Result<T, SupabaseError>;

#[derive(Debug, thiserror::Error)]
pub enum SupabaseError {
    #[error("HTTP transport error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Supabase authentication error: {0}")]
    Auth(String),

    #[error("Supabase permission denied: {0}")]
    PermissionDenied(String),

    #[error("Supabase resource not found: {0}")]
    NotFound(String),

    #[error("Supabase conflict: {0}")]
    Conflict(String),

    #[error("Supabase timeout: {0}")]
    Timeout(String),

    #[error("Rate limited (retry after {retry_after_ms}ms)")]
    RateLimited { retry_after_ms: u64 },

    #[error("Supabase API error ({status_code}): {message}")]
    Api { status_code: u16, message: String },

    #[error("Async error: {0}")]
    Async(String),

    #[error("Configuration error: {0}")]
    Config(String),
}

impl SupabaseError {
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http(error) => error.is_timeout() || error.is_connect(),
            Self::Timeout(_) | Self::RateLimited { .. } => true,
            Self::Api { status_code, .. } => matches!(status_code, 408 | 425 | 429 | 500..=599),
            Self::Json(_)
            | Self::Base64(_)
            | Self::InvalidInput(_)
            | Self::Auth(_)
            | Self::PermissionDenied(_)
            | Self::NotFound(_)
            | Self::Conflict(_)
            | Self::Async(_)
            | Self::Config(_) => false,
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
                service: "supabase".into(),
                message: error.to_string(),
                status_code: error.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Json(error) => FcpError::Internal {
                message: format!("JSON parse error: {error}"),
            },
            Self::Base64(error) => FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid base64 payload: {error}"),
            },
            Self::InvalidInput(message) => FcpError::InvalidRequest {
                code: 1003,
                message: message.clone(),
            },
            Self::Auth(message) => FcpError::Unauthorized {
                code: 2001,
                message: message.clone(),
            },
            Self::PermissionDenied(message) => FcpError::External {
                service: "supabase".into(),
                message: message.clone(),
                status_code: Some(403),
                retryable: false,
                retry_after: None,
            },
            Self::NotFound(resource) => FcpError::ResourceNotFound {
                resource: resource.clone(),
            },
            Self::Conflict(message) => FcpError::External {
                service: "supabase".into(),
                message: message.clone(),
                status_code: Some(409),
                retryable: false,
                retry_after: None,
            },
            Self::Timeout(message) => FcpError::External {
                service: "supabase".into(),
                message: message.clone(),
                status_code: Some(408),
                retryable: true,
                retry_after: None,
            },
            Self::RateLimited { retry_after_ms } => FcpError::RateLimited {
                retry_after_ms: *retry_after_ms,
                violation: None,
            },
            Self::Api {
                status_code,
                message,
            } => FcpError::External {
                service: "supabase".into(),
                message: message.clone(),
                status_code: Some(*status_code),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Async(message) => FcpError::Internal {
                message: format!("Async error: {message}"),
            },
            Self::Config(message) => FcpError::InvalidRequest {
                code: 1001,
                message: format!("Configuration error: {message}"),
            },
        }
    }
}

impl ConnectorErrorMapping for SupabaseError {
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
        let err = SupabaseError::RateLimited {
            retry_after_ms: 5_000,
        };
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(Duration::from_millis(5_000)));
    }

    #[test]
    fn unauthorized_is_not_retryable() {
        let err = SupabaseError::Auth("bad token".into());
        assert!(!err.is_retryable());
        assert!(err.retry_after().is_none());
    }

    #[test]
    fn not_found_maps_to_resource_not_found() {
        let err = SupabaseError::NotFound("table xyz".into());
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::ResourceNotFound { resource } => assert_eq!(resource, "table xyz"),
            other => panic!("Expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn api_error_retryable_for_server_errors() {
        let retryable = SupabaseError::Api {
            status_code: 500,
            message: "Internal".into(),
        };
        assert!(retryable.is_retryable());

        let terminal = SupabaseError::Api {
            status_code: 400,
            message: "Bad request".into(),
        };
        assert!(!terminal.is_retryable());
    }

    #[test]
    fn config_error_maps_to_invalid_request() {
        let err = SupabaseError::Config("missing api_key".into());
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1001);
                assert!(message.contains("missing api_key"));
            }
            other => panic!("Expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn invalid_input_maps_to_invalid_request() {
        let err = SupabaseError::InvalidInput("missing table".into());
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1003);
                assert_eq!(message, "missing table");
            }
            other => panic!("Expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_maps_to_fcp_rate_limited() {
        let err = SupabaseError::RateLimited {
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
    fn async_error_mapping_preserves_timeout() {
        let err = SupabaseError::from_async_error(AsyncError::Timeout { timeout_ms: 1_500 });
        assert_eq!(
            err.to_string(),
            "Async error: request deadline exceeded after 1500ms"
        );
    }

    #[test]
    fn async_error_mapping_cancelled() {
        let err = SupabaseError::from_async_error(AsyncError::Cancelled);
        assert_eq!(err.to_string(), "Async error: operation cancelled");
    }

    #[test]
    fn conflict_maps_to_external() {
        let err = SupabaseError::Conflict("duplicate key".into());
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::External { status_code, .. } => {
                assert_eq!(status_code, Some(409));
            }
            other => panic!("Expected External, got {other:?}"),
        }
    }

    #[test]
    fn timeout_is_retryable() {
        let err = SupabaseError::Timeout("deadline exceeded".into());
        assert!(err.is_retryable());
    }

    #[test]
    fn json_error_not_retryable() {
        let err = SupabaseError::Json(serde_json::from_str::<String>("bad").unwrap_err());
        assert!(!err.is_retryable());
    }

    #[test]
    fn permission_denied_not_retryable() {
        let err = SupabaseError::PermissionDenied("RLS block".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn auth_maps_to_unauthorized() {
        let err = SupabaseError::Auth("invalid JWT".into());
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::Unauthorized { code, message } => {
                assert_eq!(code, 2001);
                assert_eq!(message, "invalid JWT");
            }
            other => panic!("Expected Unauthorized, got {other:?}"),
        }
    }
}
