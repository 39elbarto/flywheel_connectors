//! Nextcloud Talk connector error taxonomy.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_sdk::migration::ConnectorErrorMapping;
use thiserror::Error;

use crate::types::OcsEnvelope;

/// Nextcloud Talk connector errors.
#[derive(Debug, Error)]
pub enum NextcloudTalkError {
    /// Caller input failed connector-side validation before any network request.
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// HTTP transport error.
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON encoding or decoding error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// API-level error from Nextcloud or Talk.
    #[error("Nextcloud Talk API error (HTTP {status_code}): {message}")]
    Api {
        status_code: u16,
        ocs_status_code: Option<i64>,
        message: String,
        request_id: Option<String>,
    },

    /// Authentication failure.
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    /// Permission failure.
    #[error("Forbidden: {0}")]
    Forbidden(String),

    /// Resource lookup failure.
    #[error("Not found: {0}")]
    NotFound(String),

    /// Concurrent state conflict.
    #[error("Conflict: {0}")]
    Conflict(String),

    /// Request rejected because a lobby or similar precondition is active.
    #[error("Precondition failed: {0}")]
    PreconditionFailed(String),

    /// Request payload was too large for the configured server policy.
    #[error("Payload too large: {0}")]
    PayloadTooLarge(String),

    /// Rate limit applied by Nextcloud or an upstream proxy.
    #[error("Rate limited, retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },

    /// Long-poll chat request had no changes.
    #[error("Not modified")]
    NotModified,

    /// Static configuration problem.
    #[error("Configuration error: {0}")]
    Config(String),

    /// Runtime or timeout issue.
    #[error("Runtime error: {0}")]
    Runtime(String),

    /// Request was intentionally cancelled.
    #[error("Request cancelled")]
    Cancelled,
}

/// Shorthand result alias for the connector.
pub type NextcloudTalkResult<T> = Result<T, NextcloudTalkError>;

impl NextcloudTalkError {
    /// Whether this error should be retried.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::RateLimited { .. } | Self::Runtime(_) | Self::NotModified => true,
            Self::Api { status_code, .. } => *status_code >= 500,
            Self::InvalidInput(_)
            | Self::Json(_)
            | Self::Unauthorized(_)
            | Self::Forbidden(_)
            | Self::NotFound(_)
            | Self::Conflict(_)
            | Self::PreconditionFailed(_)
            | Self::PayloadTooLarge(_)
            | Self::Config(_)
            | Self::Cancelled => false,
        }
    }

    /// Suggested retry delay.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after_ms } => Some(Duration::from_millis(*retry_after_ms)),
            _ => None,
        }
    }

    /// Convert into the shared FCP error taxonomy.
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::InvalidInput(message) => FcpError::InvalidRequest {
                code: 1005,
                message: message.clone(),
            },
            Self::Http(error) => FcpError::External {
                service: "nextcloud-talk".into(),
                message: error.to_string(),
                status_code: error.status().map(|status| status.as_u16()),
                retryable: true,
                retry_after: None,
            },
            Self::Json(error) => FcpError::Internal {
                message: format!("JSON error: {error}"),
            },
            Self::Api {
                status_code,
                message,
                ..
            } => FcpError::External {
                service: "nextcloud-talk".into(),
                message: message.clone(),
                status_code: Some(*status_code),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Unauthorized(message) => FcpError::Unauthorized {
                code: 2001,
                message: message.clone(),
            },
            Self::Forbidden(message) => FcpError::Unauthorized {
                code: 2003,
                message: format!("permission denied: {message}"),
            },
            Self::NotFound(message) => FcpError::ResourceNotFound {
                resource: message.clone(),
            },
            Self::Conflict(message) => FcpError::InvalidRequest {
                code: 1009,
                message: message.clone(),
            },
            Self::PreconditionFailed(message) => FcpError::InvalidRequest {
                code: 1012,
                message: message.clone(),
            },
            Self::PayloadTooLarge(message) => FcpError::InvalidRequest {
                code: 1006,
                message: message.clone(),
            },
            Self::RateLimited { retry_after_ms } => FcpError::RateLimited {
                retry_after_ms: *retry_after_ms,
                violation: None,
            },
            Self::NotModified => FcpError::External {
                service: "nextcloud-talk".into(),
                message: "No new data available".into(),
                status_code: Some(304),
                retryable: true,
                retry_after: None,
            },
            Self::Config(message) => FcpError::InvalidRequest {
                code: 1001,
                message: message.clone(),
            },
            Self::Runtime(message) => FcpError::Internal {
                message: message.clone(),
            },
            Self::Cancelled => FcpError::Internal {
                message: "request cancelled".into(),
            },
        }
    }

    /// Classify an HTTP response body into a structured connector error.
    #[must_use]
    pub fn from_api_response(
        status: u16,
        body: &str,
        request_id: Option<String>,
        retry_after_ms: Option<u64>,
    ) -> Self {
        if status == 304 {
            return Self::NotModified;
        }
        if status == 429 {
            return Self::RateLimited {
                retry_after_ms: retry_after_ms.unwrap_or(5_000),
            };
        }

        let (message, ocs_status_code) = extract_ocs_error(body)
            .or_else(|| extract_json_error(body))
            .unwrap_or_else(|| (body.trim().to_string(), None));

        match status {
            401 => Self::Unauthorized(message),
            403 => Self::Forbidden(message),
            404 => Self::NotFound(message),
            409 => Self::Conflict(message),
            412 => Self::PreconditionFailed(message),
            413 => Self::PayloadTooLarge(message),
            _ => Self::Api {
                status_code: status,
                ocs_status_code,
                message,
                request_id,
            },
        }
    }
}

impl ConnectorErrorMapping for NextcloudTalkError {
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

fn extract_ocs_error(body: &str) -> Option<(String, Option<i64>)> {
    let envelope: OcsEnvelope<serde_json::Value> = serde_json::from_str(body).ok()?;
    Some((
        envelope.ocs.meta.message.clone(),
        Some(envelope.ocs.meta.statuscode),
    ))
}

fn extract_json_error(body: &str) -> Option<(String, Option<i64>)> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let message = value
        .get("message")
        .or_else(|| value.get("error"))
        .and_then(serde_json::Value::as_str)?;
    Some((message.to_string(), None))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limit_is_retryable() {
        let error = NextcloudTalkError::RateLimited {
            retry_after_ms: 2_500,
        };
        assert!(error.is_retryable());
        assert_eq!(error.retry_after(), Some(Duration::from_millis(2_500)));
    }

    #[test]
    fn parse_ocs_error_message() {
        let error = NextcloudTalkError::from_api_response(
            412,
            r#"{"ocs":{"meta":{"status":"failure","statuscode":412,"message":"Lobby is active"},"data":[]}}"#,
            Some("req-1".into()),
            None,
        );

        assert!(matches!(error, NextcloudTalkError::PreconditionFailed(_)));
        assert_eq!(error.to_string(), "Precondition failed: Lobby is active");
    }

    #[test]
    fn map_unauthorized_to_fcp() {
        let error = NextcloudTalkError::Unauthorized("invalid app password".into());
        let fcp_error = ConnectorErrorMapping::to_fcp_error(&error);
        assert!(matches!(fcp_error, FcpError::Unauthorized { .. }));
    }

    #[test]
    fn map_invalid_input_to_fcp() {
        let error = NextcloudTalkError::InvalidInput("message must not be empty".into());
        let fcp_error = ConnectorErrorMapping::to_fcp_error(&error);
        assert!(matches!(
            fcp_error,
            FcpError::InvalidRequest { code: 1005, .. }
        ));
    }
}
