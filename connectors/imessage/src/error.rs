//! `BlueBubbles` connector error types.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_sdk::migration::ConnectorErrorMapping;
use thiserror::Error;

/// `BlueBubbles` connector errors.
#[derive(Error, Debug)]
pub enum BlueBubblesError {
    /// HTTP transport error.
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// `BlueBubbles` server is unreachable.
    #[error("BlueBubbles server unreachable")]
    ServerUnreachable,

    /// Authentication failed (invalid password).
    #[error("Unauthorized: {message}")]
    Unauthorized { message: String },

    /// API returned a non-success status.
    #[error("API error (HTTP {status_code}): {message}")]
    Api { status_code: u16, message: String },

    /// Rate limited by the server.
    #[error("Rate limited, retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },

    /// Feature requires the Private API to be enabled.
    #[error("Private API required for: {feature}")]
    PrivateApiRequired { feature: String },

    /// Action is unavailable even though the API is reachable.
    #[error("Unsupported BlueBubbles action {action}: {reason}")]
    UnsupportedAction { action: String, reason: String },

    /// Attachment exceeds size limit.
    #[error("Attachment too large: {size_bytes} bytes (max {max_bytes})")]
    AttachmentTooLarge { size_bytes: u64, max_bytes: u64 },

    /// Chat not found by GUID.
    #[error("Chat not found: {guid}")]
    ChatNotFound { guid: String },

    /// Attachment not found by GUID.
    #[error("Attachment not found: {guid}")]
    AttachmentNotFound { guid: String },

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(String),

    /// Input validation error.
    #[error("Validation error: {0}")]
    Validation(String),

    /// Runtime/async error.
    #[error("Async runtime error: {0}")]
    Async(String),
}

impl BlueBubblesError {
    /// Whether this error is retryable.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::ServerUnreachable | Self::RateLimited { .. } | Self::Async(_) => {
                true
            }
            Self::Json(_)
            | Self::Unauthorized { .. }
            | Self::AttachmentNotFound { .. }
            | Self::PrivateApiRequired { .. }
            | Self::UnsupportedAction { .. }
            | Self::AttachmentTooLarge { .. }
            | Self::ChatNotFound { .. }
            | Self::Config(_)
            | Self::Validation(_) => false,
            Self::Api { status_code, .. } => is_retryable_status(*status_code),
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
                service: "bluebubbles".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: true,
                retry_after: None,
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
            Self::ServerUnreachable => FcpError::External {
                service: "bluebubbles".into(),
                message: "BlueBubbles server is unreachable".into(),
                status_code: None,
                retryable: true,
                retry_after: None,
            },
            Self::Unauthorized { message } => FcpError::Unauthorized {
                code: 2001,
                message: message.clone(),
            },
            Self::Api {
                status_code,
                message,
            } => FcpError::External {
                service: "bluebubbles".into(),
                message: format!("HTTP {status_code}: {message}"),
                status_code: Some(*status_code),
                retryable: is_retryable_status(*status_code),
                retry_after: None,
            },
            Self::RateLimited { retry_after_ms } => FcpError::RateLimited {
                retry_after_ms: *retry_after_ms,
                violation: None,
            },
            Self::PrivateApiRequired { feature } => FcpError::InvalidRequest {
                code: 1010,
                message: format!("Private API required for: {feature}"),
            },
            Self::UnsupportedAction { action, reason } => FcpError::InvalidRequest {
                code: 1011,
                message: format!("Unsupported BlueBubbles action {action}: {reason}"),
            },
            Self::AttachmentTooLarge {
                size_bytes,
                max_bytes,
            } => FcpError::InvalidRequest {
                code: 1006,
                message: format!("Attachment too large: {size_bytes} bytes (max {max_bytes})"),
            },
            Self::ChatNotFound { guid } => FcpError::InvalidRequest {
                code: 1004,
                message: format!("Chat not found: {guid}"),
            },
            Self::AttachmentNotFound { guid } => FcpError::InvalidRequest {
                code: 1007,
                message: format!("Attachment not found: {guid}"),
            },
            Self::Config(msg) => FcpError::InvalidRequest {
                code: 1001,
                message: format!("Configuration error: {msg}"),
            },
            Self::Validation(msg) => FcpError::InvalidRequest {
                code: 1005,
                message: msg.clone(),
            },
            Self::Async(msg) => FcpError::Internal {
                message: format!("Async runtime error: {msg}"),
            },
        }
    }

    /// Create from `BlueBubbles` API error response and HTTP status.
    #[must_use]
    pub fn from_api_response(status: u16, body: &str) -> Self {
        match status {
            401 | 403 => Self::Unauthorized {
                message: body.to_string(),
            },
            404 => Self::ChatNotFound {
                guid: body.to_string(),
            },
            429 => Self::RateLimited {
                retry_after_ms: 30_000,
            },
            _ => {
                if let Ok(err_resp) = serde_json::from_str::<crate::types::ApiErrorResponse>(body) {
                    Self::Api {
                        status_code: status,
                        message: err_resp
                            .error
                            .or(err_resp.message)
                            .unwrap_or_else(|| format!("HTTP {status}")),
                    }
                } else {
                    Self::Api {
                        status_code: status,
                        message: format!("HTTP {status}: {body}"),
                    }
                }
            }
        }
    }

    /// Normalize reqwest transport failures into connector-specific failures.
    #[must_use]
    pub fn from_transport_error(error: reqwest::Error) -> Self {
        if error.is_connect() || error.is_timeout() {
            Self::ServerUnreachable
        } else {
            Self::Http(error)
        }
    }
}

impl ConnectorErrorMapping for BlueBubblesError {
    fn from_async_error(error: AsyncError) -> Self {
        match error {
            AsyncError::Timeout { .. } => Self::ServerUnreachable,
            AsyncError::Cancelled => Self::Async("Operation cancelled".into()),
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

pub type BlueBubblesResult<T> = Result<T, BlueBubblesError>;

const fn is_retryable_status(status_code: u16) -> bool {
    matches!(status_code, 408 | 425) || status_code >= 500
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_error_is_retryable() {
        let err = BlueBubblesError::Http(
            reqwest::Client::new()
                .get("://invalid")
                .build()
                .unwrap_err(),
        );
        assert!(err.is_retryable());
    }

    #[test]
    fn json_error_not_retryable() {
        let err = BlueBubblesError::Json(
            serde_json::from_str::<serde_json::Value>("{{bad}}").unwrap_err(),
        );
        assert!(!err.is_retryable());
    }

    #[test]
    fn server_unreachable_is_retryable() {
        let err = BlueBubblesError::ServerUnreachable;
        assert!(err.is_retryable());
        assert!(err.retry_after().is_none());
    }

    #[test]
    fn unauthorized_not_retryable() {
        let err = BlueBubblesError::Unauthorized {
            message: "bad password".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_error_5xx_is_retryable() {
        let err = BlueBubblesError::Api {
            status_code: 500,
            message: "internal error".into(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_error_4xx_not_retryable() {
        let err = BlueBubblesError::Api {
            status_code: 422,
            message: "unprocessable".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn rate_limited_is_retryable() {
        let err = BlueBubblesError::RateLimited {
            retry_after_ms: 5000,
        };
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn private_api_required_not_retryable() {
        let err = BlueBubblesError::PrivateApiRequired {
            feature: "typing indicators".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn attachment_too_large_not_retryable() {
        let err = BlueBubblesError::AttachmentTooLarge {
            size_bytes: 200_000_000,
            max_bytes: 100_000_000,
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn chat_not_found_not_retryable() {
        let err = BlueBubblesError::ChatNotFound {
            guid: "iMessage;-;+15551234567".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn attachment_not_found_not_retryable() {
        let err = BlueBubblesError::AttachmentNotFound {
            guid: "attachment-123".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn config_not_retryable() {
        let err = BlueBubblesError::Config("missing password".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn async_error_is_retryable() {
        let err = BlueBubblesError::Async("runtime shut down".into());
        assert!(err.is_retryable());
    }

    // FCP error mapping tests

    #[test]
    fn rate_limited_maps_to_fcp() {
        let err = BlueBubblesError::RateLimited {
            retry_after_ms: 10_000,
        };
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::RateLimited { .. }));
    }

    #[test]
    fn unauthorized_maps_to_fcp() {
        let err = BlueBubblesError::Unauthorized {
            message: "denied".into(),
        };
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::Unauthorized { .. }));
    }

    #[test]
    fn attachment_not_found_maps_to_fcp() {
        let err = BlueBubblesError::AttachmentNotFound {
            guid: "attachment-123".into(),
        };
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn config_maps_to_invalid_request() {
        let err = BlueBubblesError::Config("missing field".into());
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn json_maps_to_internal() {
        let err = BlueBubblesError::Json(
            serde_json::from_str::<serde_json::Value>("{{bad}}").unwrap_err(),
        );
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::Internal { .. }));
    }

    #[test]
    fn http_maps_to_external() {
        let err = BlueBubblesError::Http(
            reqwest::Client::new()
                .get("://invalid")
                .build()
                .unwrap_err(),
        );
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::External { .. }));
    }

    #[test]
    fn server_unreachable_maps_to_external() {
        let err = BlueBubblesError::ServerUnreachable;
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::External { .. }));
    }

    #[test]
    fn chat_not_found_maps_to_invalid_request() {
        let err = BlueBubblesError::ChatNotFound { guid: "g1".into() };
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn attachment_too_large_maps_to_invalid_request() {
        let err = BlueBubblesError::AttachmentTooLarge {
            size_bytes: 200,
            max_bytes: 100,
        };
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn private_api_maps_to_invalid_request() {
        let err = BlueBubblesError::PrivateApiRequired {
            feature: "typing".into(),
        };
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::InvalidRequest { .. }));
    }

    // from_async_error tests

    #[test]
    fn from_async_timeout() {
        let err = BlueBubblesError::from_async_error(AsyncError::Timeout { timeout_ms: 5000 });
        assert!(matches!(err, BlueBubblesError::ServerUnreachable));
        assert!(err.is_retryable());
    }

    #[test]
    fn from_async_cancelled() {
        let err = BlueBubblesError::from_async_error(AsyncError::Cancelled);
        assert!(matches!(err, BlueBubblesError::Async(_)));
    }

    #[test]
    fn from_async_channel_closed() {
        let err = BlueBubblesError::from_async_error(AsyncError::ChannelClosed);
        assert!(matches!(err, BlueBubblesError::Async(_)));
    }

    // from_api_response tests

    #[test]
    fn from_api_response_401() {
        let err = BlueBubblesError::from_api_response(401, "unauthorized");
        assert!(matches!(err, BlueBubblesError::Unauthorized { .. }));
    }

    #[test]
    fn from_api_response_403() {
        let err = BlueBubblesError::from_api_response(403, "forbidden");
        assert!(matches!(err, BlueBubblesError::Unauthorized { .. }));
    }

    #[test]
    fn from_api_response_404() {
        let err = BlueBubblesError::from_api_response(404, "chat not found");
        assert!(matches!(err, BlueBubblesError::ChatNotFound { .. }));
    }

    #[test]
    fn from_api_response_429() {
        let err = BlueBubblesError::from_api_response(429, "too many requests");
        assert!(matches!(err, BlueBubblesError::RateLimited { .. }));
    }

    #[test]
    fn from_api_response_500() {
        let err = BlueBubblesError::from_api_response(500, "internal error");
        assert!(matches!(err, BlueBubblesError::Api { .. }));
    }

    #[test]
    fn error_display_rate_limited() {
        let err = BlueBubblesError::RateLimited {
            retry_after_ms: 10_000,
        };
        let display = format!("{err}");
        assert!(display.contains("10000"));
    }

    #[test]
    fn error_display_attachment_too_large() {
        let err = BlueBubblesError::AttachmentTooLarge {
            size_bytes: 200,
            max_bytes: 100,
        };
        let display = format!("{err}");
        assert!(display.contains("200"));
        assert!(display.contains("100"));
    }

    #[test]
    fn error_display_api() {
        let err = BlueBubblesError::Api {
            status_code: 503,
            message: "service unavailable".into(),
        };
        let display = format!("{err}");
        assert!(display.contains("503"));
        assert!(display.contains("service unavailable"));
    }

    #[test]
    fn api_error_maps_to_external() {
        let err = BlueBubblesError::Api {
            status_code: 502,
            message: "bad gateway".into(),
        };
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::External { .. }));
    }
}
