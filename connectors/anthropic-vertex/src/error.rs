use std::time::Duration;

use bytes::Bytes;
use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_sdk::migration::ConnectorErrorMapping;
use reqwest::{Response, StatusCode};
use serde::Deserialize;

pub type VertexResult<T> = Result<T, VertexError>;

#[derive(Debug, thiserror::Error)]
pub enum VertexError {
    #[error("HTTP transport error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Vertex API error {status}: {kind}: {message}")]
    Api {
        status: u16,
        kind: String,
        message: String,
        retry_after_ms: Option<u64>,
    },

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
}

impl VertexError {
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http(error) => error.is_timeout() || error.is_connect(),
            Self::RateLimited { .. } => true,
            Self::Api { status, kind, .. } => {
                *status == 408
                    || *status == 429
                    || matches!(*status, 500 | 502 | 503 | 504)
                    || matches!(
                        kind.as_str(),
                        "RESOURCE_EXHAUSTED"
                            | "UNAVAILABLE"
                            | "DEADLINE_EXCEEDED"
                            | "overloaded_error"
                            | "rate_limit_error"
                    )
            }
            Self::Json(_)
            | Self::Unauthorized(_)
            | Self::NotFound(_)
            | Self::Async(_)
            | Self::Config(_)
            | Self::InvalidInput(_) => false,
        }
    }

    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after_ms }
            | Self::Api {
                retry_after_ms: Some(retry_after_ms),
                ..
            } => Some(Duration::from_millis(*retry_after_ms)),
            _ => None,
        }
    }

    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Http(error) => FcpError::External {
                service: "anthropic-vertex".into(),
                message: http_error_message(error),
                status_code: error.status().map(|status| status.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Json(error) => FcpError::Internal {
                message: format!("JSON parse error: {error}"),
            },
            Self::Api {
                status,
                kind,
                message,
                ..
            } => FcpError::External {
                service: "anthropic-vertex".into(),
                message: format!("{kind}: {message}"),
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
        }
    }
}

fn http_error_message(error: &reqwest::Error) -> String {
    if error.is_timeout() {
        format!("request timeout: {error}")
    } else if error.is_connect() {
        format!("connection error: {error}")
    } else {
        error.to_string()
    }
}

impl ConnectorErrorMapping for VertexError {
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

const MAX_RETRY_AFTER_MS: u64 = 60 * 60 * 1000;

pub(crate) fn parse_retry_after_header_value(value: &str) -> Option<u64> {
    value
        .trim()
        .parse::<u64>()
        .ok()
        .map(|secs| secs.saturating_mul(1000).min(MAX_RETRY_AFTER_MS))
}

pub(crate) fn extract_retry_after(response: &Response) -> Option<u64> {
    response
        .headers()
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .and_then(parse_retry_after_header_value)
}

#[derive(Debug, Deserialize)]
struct GoogleErrorWrapper {
    error: GoogleErrorBody,
}

#[derive(Debug, Deserialize)]
struct GoogleErrorBody {
    code: Option<u16>,
    message: Option<String>,
    status: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AnthropicErrorWrapper {
    error: AnthropicErrorBody,
}

#[derive(Debug, Deserialize)]
struct AnthropicErrorBody {
    #[serde(rename = "type")]
    error_type: Option<String>,
    message: Option<String>,
}

pub fn vertex_error_from_status(
    status: StatusCode,
    bytes: &Bytes,
    retry_after_ms: Option<u64>,
) -> VertexError {
    if status == StatusCode::TOO_MANY_REQUESTS {
        return VertexError::RateLimited {
            retry_after_ms: retry_after_ms.unwrap_or(30_000),
        };
    }

    if let Ok(wrapper) = serde_json::from_slice::<GoogleErrorWrapper>(bytes) {
        let error = wrapper.error;
        let status_code = error.code.unwrap_or(status.as_u16());
        let kind = error
            .status
            .unwrap_or_else(|| format!("HTTP {status_code}"));
        let message = error
            .message
            .unwrap_or_else(|| String::from_utf8_lossy(bytes).into_owned());
        return match status {
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => VertexError::Unauthorized(message),
            StatusCode::NOT_FOUND => VertexError::NotFound(message),
            _ => VertexError::Api {
                status: status_code,
                kind,
                message,
                retry_after_ms,
            },
        };
    }

    if let Ok(wrapper) = serde_json::from_slice::<AnthropicErrorWrapper>(bytes) {
        let error = wrapper.error;
        let kind = error
            .error_type
            .unwrap_or_else(|| format!("HTTP {}", status.as_u16()));
        let message = error
            .message
            .unwrap_or_else(|| String::from_utf8_lossy(bytes).into_owned());
        return match status {
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => VertexError::Unauthorized(message),
            StatusCode::NOT_FOUND => VertexError::NotFound(message),
            _ => VertexError::Api {
                status: status.as_u16(),
                kind,
                message,
                retry_after_ms,
            },
        };
    }

    VertexError::Api {
        status: status.as_u16(),
        kind: format!("HTTP {}", status.as_u16()),
        message: String::from_utf8_lossy(bytes).into_owned(),
        retry_after_ms,
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use reqwest::StatusCode;

    use super::{VertexError, parse_retry_after_header_value, vertex_error_from_status};

    #[test]
    fn retry_after_is_capped_and_seconds_based() {
        assert_eq!(parse_retry_after_header_value("2"), Some(2_000));
        assert_eq!(parse_retry_after_header_value("999999"), Some(3_600_000));
        assert_eq!(parse_retry_after_header_value("soon"), None);
    }

    #[test]
    fn google_error_body_maps_auth_denial() {
        let error = vertex_error_from_status(
            StatusCode::FORBIDDEN,
            &Bytes::from_static(
                br#"{"error":{"code":403,"status":"PERMISSION_DENIED","message":"no quota"}}"#,
            ),
            None,
        );
        assert!(matches!(error, VertexError::Unauthorized(message) if message == "no quota"));
    }
}
