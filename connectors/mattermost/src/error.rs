//! Mattermost connector error taxonomy.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_sdk::migration::ConnectorErrorMapping;
use fcp_sdk::prelude::FcpError;

/// Mattermost-specific errors.
#[derive(Debug, thiserror::Error)]
pub enum MattermostError {
    /// HTTP transport error.
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Mattermost API error.
    #[error("Mattermost API error ({status_code}): {message}")]
    Api {
        status_code: u16,
        message: String,
        request_id: Option<String>,
    },

    /// Authentication failure (invalid or expired token).
    #[error("authentication failed: {0}")]
    Unauthorized(String),

    /// Insufficient permissions for the requested operation.
    #[error("permission denied: {0}")]
    Forbidden(String),

    /// Resource not found.
    #[error("not found: {0}")]
    NotFound(String),

    /// Rate limited by the Mattermost server.
    #[error("rate limited, retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },

    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(String),

    /// Runtime / deadline error (retryable, e.g. timeout).
    #[error("runtime error: {0}")]
    Runtime(String),

    /// Request was intentionally cancelled (not retryable).
    #[error("request cancelled")]
    Cancelled,
}

pub type MattermostResult<T> = Result<T, MattermostError>;

impl MattermostError {
    /// Whether this error should be retried.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Http(_) | Self::RateLimited { .. } | Self::Runtime(_)
        )
        // Note: Cancelled is intentionally NOT retryable
    }

    /// Suggested retry delay.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after_ms } => Some(Duration::from_millis(*retry_after_ms)),
            _ => None,
        }
    }

    /// Convert to a structured FCP error.
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Http(e) => FcpError::External {
                service: "mattermost".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: true,
                retry_after: None,
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
            Self::Api {
                status_code,
                message,
                ..
            } => FcpError::External {
                service: "mattermost".into(),
                message: message.clone(),
                status_code: Some(*status_code),
                retryable: *status_code >= 500,
                retry_after: None,
            },
            Self::Unauthorized(msg) => FcpError::Unauthorized {
                code: 2001,
                message: msg.clone(),
            },
            Self::Forbidden(msg) => FcpError::Unauthorized {
                code: 2003,
                message: format!("permission denied: {msg}"),
            },
            Self::NotFound(msg) => FcpError::ResourceNotFound {
                resource: msg.clone(),
            },
            Self::RateLimited { retry_after_ms } => FcpError::RateLimited {
                retry_after_ms: *retry_after_ms,
                violation: None,
            },
            Self::Config(msg) => FcpError::InvalidRequest {
                code: 5001,
                message: msg.clone(),
            },
            Self::Runtime(msg) => FcpError::Internal {
                message: msg.clone(),
            },
            Self::Cancelled => FcpError::Internal {
                message: "request cancelled".into(),
            },
        }
    }

    /// Classify an HTTP status code into the appropriate error variant.
    #[must_use]
    pub fn from_api_response(status: u16, body: &str, request_id: Option<String>) -> Self {
        let message = extract_error_message(body).unwrap_or_else(|| body.to_string());
        match status {
            401 => Self::Unauthorized(message),
            403 => Self::Forbidden(message),
            404 => Self::NotFound(message),
            429 => {
                let retry_after_ms = extract_retry_after(body).unwrap_or(5000);
                Self::RateLimited { retry_after_ms }
            }
            _ => Self::Api {
                status_code: status,
                message,
                request_id,
            },
        }
    }
}

impl ConnectorErrorMapping for MattermostError {
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

/// Extract error message from Mattermost API error response.
fn extract_error_message(body: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    value
        .get("message")
        .and_then(|v| v.as_str())
        .map(String::from)
}

/// Extract retry-after hint from rate-limit response.
fn extract_retry_after(body: &str) -> Option<u64> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    value
        .get("retry_after_ms")
        .and_then(serde_json::Value::as_u64)
        .or(Some(5000))
}

// Display is auto-generated by thiserror via #[error(...)] annotations.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_error_is_retryable() {
        // Construct a reqwest error by trying an invalid URL scheme
        let err = MattermostError::Http(
            reqwest::Client::new()
                .get("://invalid")
                .build()
                .unwrap_err(),
        );
        assert!(err.is_retryable());
    }

    #[test]
    fn rate_limited_is_retryable() {
        let err = MattermostError::RateLimited {
            retry_after_ms: 2000,
        };
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(Duration::from_secs(2)));
    }

    #[test]
    fn unauthorized_not_retryable() {
        let err = MattermostError::Unauthorized("bad token".into());
        assert!(!err.is_retryable());
        assert!(err.retry_after().is_none());
    }

    #[test]
    fn forbidden_not_retryable() {
        let err = MattermostError::Forbidden("no access".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn not_found_not_retryable() {
        let err = MattermostError::NotFound("channel abc".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn config_error_not_retryable() {
        let err = MattermostError::Config("missing base_url".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_error_5xx_retryable_via_fcp() -> Result<(), String> {
        let err = MattermostError::Api {
            status_code: 502,
            message: "bad gateway".into(),
            request_id: None,
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::External { retryable, .. } => assert!(retryable),
            other => return Err(format!("expected External, got {other:?}")),
        }
        Ok(())
    }

    #[test]
    fn api_error_4xx_not_retryable_via_fcp() -> Result<(), String> {
        let err = MattermostError::Api {
            status_code: 400,
            message: "bad request".into(),
            request_id: Some("req_123".into()),
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::External { retryable, .. } => assert!(!retryable),
            other => return Err(format!("expected External, got {other:?}")),
        }
        Ok(())
    }

    #[test]
    fn unauthorized_maps_to_fcp_unauthorized() {
        let err = MattermostError::Unauthorized("expired".into());
        assert!(matches!(err.to_fcp_error(), FcpError::Unauthorized { .. }));
    }

    #[test]
    fn forbidden_maps_to_fcp_unauthorized() {
        let err = MattermostError::Forbidden("no perm".into());
        assert!(matches!(err.to_fcp_error(), FcpError::Unauthorized { .. }));
    }

    #[test]
    fn not_found_maps_to_fcp_resource_not_found() {
        let err = MattermostError::NotFound("channel".into());
        assert!(matches!(
            err.to_fcp_error(),
            FcpError::ResourceNotFound { .. }
        ));
    }

    #[test]
    fn rate_limited_maps_to_fcp_rate_limited() -> Result<(), String> {
        let err = MattermostError::RateLimited {
            retry_after_ms: 3000,
        };
        match err.to_fcp_error() {
            FcpError::RateLimited { retry_after_ms, .. } => assert_eq!(retry_after_ms, 3000),
            other => return Err(format!("expected RateLimited, got {other:?}")),
        }
        Ok(())
    }

    #[test]
    fn config_maps_to_fcp_invalid_request() {
        let err = MattermostError::Config("bad".into());
        assert!(matches!(
            err.to_fcp_error(),
            FcpError::InvalidRequest { .. }
        ));
    }

    #[test]
    fn runtime_maps_to_fcp_internal() {
        let err = MattermostError::Runtime("timeout".into());
        assert!(matches!(err.to_fcp_error(), FcpError::Internal { .. }));
    }

    #[test]
    fn from_async_timeout() {
        let err = MattermostError::from_async_error(AsyncError::Timeout { timeout_ms: 5000 });
        assert!(err.is_retryable());
        assert!(matches!(err, MattermostError::Runtime(_)));
    }

    #[test]
    fn from_async_cancelled() {
        let err = MattermostError::from_async_error(AsyncError::Cancelled);
        assert!(matches!(err, MattermostError::Cancelled));
        assert!(!err.is_retryable());
    }

    #[test]
    fn from_api_response_401() {
        let err = MattermostError::from_api_response(
            401,
            r#"{"message":"Invalid or expired session"}"#,
            None,
        );
        assert!(matches!(err, MattermostError::Unauthorized(_)));
    }

    #[test]
    fn from_api_response_403() {
        let err = MattermostError::from_api_response(
            403,
            r#"{"message":"You do not have the appropriate permissions"}"#,
            None,
        );
        assert!(matches!(err, MattermostError::Forbidden(_)));
    }

    #[test]
    fn from_api_response_404() {
        let err =
            MattermostError::from_api_response(404, r#"{"message":"Resource not found"}"#, None);
        assert!(matches!(err, MattermostError::NotFound(_)));
    }

    #[test]
    fn from_api_response_429() -> Result<(), String> {
        let err = MattermostError::from_api_response(
            429,
            r#"{"message":"Too many requests","retry_after_ms":3000}"#,
            None,
        );
        match err {
            MattermostError::RateLimited { retry_after_ms } => {
                assert_eq!(retry_after_ms, 3000);
            }
            other => return Err(format!("expected RateLimited, got {other:?}")),
        }
        Ok(())
    }

    #[test]
    fn from_api_response_500() -> Result<(), String> {
        let err = MattermostError::from_api_response(
            500,
            r#"{"message":"Internal server error"}"#,
            Some("req_abc".into()),
        );
        match err {
            MattermostError::Api {
                status_code,
                request_id,
                ..
            } => {
                assert_eq!(status_code, 500);
                assert_eq!(request_id.as_deref(), Some("req_abc"));
            }
            other => return Err(format!("expected Api, got {other:?}")),
        }
        Ok(())
    }

    #[test]
    fn extract_error_message_parses_json() {
        let msg = extract_error_message(r#"{"message":"test error","status_code":400}"#);
        assert_eq!(msg.as_deref(), Some("test error"));
    }

    #[test]
    fn extract_error_message_returns_none_for_invalid() {
        assert!(extract_error_message("not json").is_none());
    }

    #[test]
    fn json_error_not_retryable() {
        let err: MattermostError = serde_json::from_str::<serde_json::Value>("not json")
            .unwrap_err()
            .into();
        assert!(!err.is_retryable());
        assert!(matches!(err.to_fcp_error(), FcpError::Internal { .. }));
    }

    #[test]
    fn connector_error_mapping_trait_consistency() {
        let err = MattermostError::RateLimited {
            retry_after_ms: 1000,
        };
        // Trait methods should match inherent methods
        assert_eq!(
            ConnectorErrorMapping::is_retryable(&err),
            MattermostError::is_retryable(&err)
        );
        assert_eq!(
            ConnectorErrorMapping::retry_after(&err),
            MattermostError::retry_after(&err)
        );
    }

    #[test]
    fn display_formats_correctly() {
        let err = MattermostError::Api {
            status_code: 500,
            message: "internal error".into(),
            request_id: None,
        };
        let display = format!("{err}");
        assert!(display.contains("500"));
        assert!(display.contains("internal error"));
    }

    #[test]
    fn display_rate_limited() {
        let err = MattermostError::RateLimited {
            retry_after_ms: 5000,
        };
        let display = format!("{err}");
        assert!(display.contains("5000"));
    }
}
