//! Teams connector error types.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_core::FcpError;
use fcp_sdk::migration::ConnectorErrorMapping;
use thiserror::Error;

/// Teams connector errors.
#[derive(Error, Debug)]
pub enum TeamsError {
    /// HTTP transport error.
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Microsoft Graph API error.
    #[error("Graph API error ({code}): {message}")]
    Graph {
        code: String,
        message: String,
        status_code: u16,
    },

    /// Rate limited by Graph API.
    #[error("Rate limited, retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },

    /// Authentication failure.
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    /// Insufficient permissions.
    #[error("Forbidden: {0}")]
    Forbidden(String),

    /// Resource not found.
    #[error("Not found: {0}")]
    NotFound(String),

    /// Token acquisition failure.
    #[error("Token error: {0}")]
    TokenError(String),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(String),

    /// Runtime/async error.
    #[error("Runtime error: {0}")]
    Runtime(String),

    /// Operation cancelled.
    #[error("Operation cancelled")]
    Cancelled,
}

impl TeamsError {
    /// Whether this error is retryable.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::RateLimited { .. } | Self::Runtime(_) => true,
            // Graph transient codes
            Self::Graph { status_code, .. } => matches!(*status_code, 429 | 500 | 502 | 503 | 504),
            Self::Json(_)
            | Self::Unauthorized(_)
            | Self::Forbidden(_)
            | Self::NotFound(_)
            | Self::TokenError(_)
            | Self::Config(_)
            | Self::Cancelled => false,
        }
    }

    /// Suggested retry-after delay.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after_ms } => Some(Duration::from_millis(*retry_after_ms)),
            _ => None,
        }
    }

    /// Convert to FCP error taxonomy.
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Http(e) => FcpError::External {
                service: "teams".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
            Self::Graph {
                code,
                message,
                status_code,
            } => FcpError::External {
                service: "teams".into(),
                message: format!("Graph {code}: {message}"),
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
            Self::TokenError(msg) => FcpError::Unauthorized {
                code: 2002,
                message: format!("Token error: {msg}"),
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

    /// Create from Graph API error response body and HTTP status.
    #[must_use]
    pub fn from_graph_response(status: u16, body: &str) -> Self {
        if let Ok(err_resp) = serde_json::from_str::<crate::types::GraphErrorResponse>(body) {
            match status {
                401 => Self::Unauthorized(err_resp.error.message),
                403 => Self::Forbidden(err_resp.error.message),
                404 => Self::NotFound(err_resp.error.message),
                429 => Self::RateLimited {
                    retry_after_ms: 30_000,
                },
                _ => Self::Graph {
                    code: err_resp.error.code,
                    message: err_resp.error.message,
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
                _ => Self::Graph {
                    code: format!("HTTP_{status}"),
                    message: body.to_string(),
                    status_code: status,
                },
            }
        }
    }
}

impl ConnectorErrorMapping for TeamsError {
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

pub type TeamsResult<T> = Result<T, TeamsError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_error_is_retryable() {
        let err = TeamsError::Http(
            reqwest::Client::new()
                .get("://invalid")
                .build()
                .unwrap_err(),
        );
        assert!(err.is_retryable());
    }

    #[test]
    fn rate_limited_is_retryable() {
        let err = TeamsError::RateLimited {
            retry_after_ms: 5000,
        };
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn unauthorized_not_retryable() {
        let err = TeamsError::Unauthorized("bad token".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn forbidden_not_retryable() {
        let err = TeamsError::Forbidden("insufficient scope".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn not_found_not_retryable() {
        let err = TeamsError::NotFound("team not found".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn graph_500_is_retryable() {
        let err = TeamsError::Graph {
            code: "InternalServerError".into(),
            message: "Something went wrong".into(),
            status_code: 500,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn graph_400_not_retryable() {
        let err = TeamsError::Graph {
            code: "BadRequest".into(),
            message: "Invalid filter".into(),
            status_code: 400,
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn graph_429_is_retryable() {
        let err = TeamsError::Graph {
            code: "TooManyRequests".into(),
            message: "Rate limit exceeded".into(),
            status_code: 429,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn from_graph_response_401() {
        let body = r#"{"error":{"code":"InvalidAuthenticationToken","message":"Access token has expired."}}"#;
        let err = TeamsError::from_graph_response(401, body);
        assert!(matches!(err, TeamsError::Unauthorized(_)));
    }

    #[test]
    fn from_graph_response_403() {
        let body = r#"{"error":{"code":"Forbidden","message":"Insufficient privileges."}}"#;
        let err = TeamsError::from_graph_response(403, body);
        assert!(matches!(err, TeamsError::Forbidden(_)));
    }

    #[test]
    fn from_graph_response_404() {
        let body = r#"{"error":{"code":"NotFound","message":"Resource not found."}}"#;
        let err = TeamsError::from_graph_response(404, body);
        assert!(matches!(err, TeamsError::NotFound(_)));
    }

    #[test]
    fn from_graph_response_429() {
        let body = r#"{"error":{"code":"TooManyRequests","message":"Rate limit."}}"#;
        let err = TeamsError::from_graph_response(429, body);
        assert!(matches!(err, TeamsError::RateLimited { .. }));
    }

    #[test]
    fn from_graph_response_500_generic() {
        let body = r#"{"error":{"code":"InternalServerError","message":"Oops."}}"#;
        let err = TeamsError::from_graph_response(500, body);
        assert!(matches!(err, TeamsError::Graph { status_code: 500, .. }));
    }

    #[test]
    fn from_graph_response_malformed_body() {
        let err = TeamsError::from_graph_response(500, "not json");
        assert!(matches!(err, TeamsError::Graph { .. }));
    }

    #[test]
    fn graph_maps_to_fcp_external() {
        let err = TeamsError::Graph {
            code: "BadRequest".into(),
            message: "Invalid".into(),
            status_code: 400,
        };
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::External { .. }));
    }

    #[test]
    fn unauthorized_maps_to_fcp() {
        let err = TeamsError::Unauthorized("expired".into());
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::Unauthorized { .. }));
    }

    #[test]
    fn config_maps_to_invalid_request() {
        let err = TeamsError::Config("missing client_id".into());
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn from_async_timeout() {
        let err = TeamsError::from_async_error(AsyncError::Timeout { timeout_ms: 5000 });
        assert!(matches!(err, TeamsError::Runtime(_)));
        assert!(err.is_retryable());
    }

    #[test]
    fn from_async_cancelled() {
        let err = TeamsError::from_async_error(AsyncError::Cancelled);
        assert!(matches!(err, TeamsError::Cancelled));
        assert!(!err.is_retryable());
    }

    #[test]
    fn from_async_channel_closed() {
        let err = TeamsError::from_async_error(AsyncError::ChannelClosed);
        assert!(matches!(err, TeamsError::Runtime(_)));
    }

    #[test]
    fn error_display_graph() {
        let err = TeamsError::Graph {
            code: "NotFound".into(),
            message: "Team not found".into(),
            status_code: 404,
        };
        let display = format!("{err}");
        assert!(display.contains("NotFound"));
        assert!(display.contains("Team not found"));
    }

    #[test]
    fn error_display_rate_limited() {
        let err = TeamsError::RateLimited {
            retry_after_ms: 10000,
        };
        let display = format!("{err}");
        assert!(display.contains("10000"));
    }

    #[test]
    fn token_error_maps_to_unauthorized() {
        let err = TeamsError::TokenError("invalid grant".into());
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::Unauthorized { .. }));
    }
}
