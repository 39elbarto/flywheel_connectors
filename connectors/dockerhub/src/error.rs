use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_sdk::migration::ConnectorErrorMapping;

pub type DockerHubResult<T> = Result<T, DockerHubError>;

#[derive(Debug, thiserror::Error)]
pub enum DockerHubError {
    #[error("HTTP transport error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Docker Hub API error {status}: {message}")]
    Api { status: u16, message: String },

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

impl DockerHubError {
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http(error) => error.is_timeout() || error.is_connect(),
            Self::RateLimited { .. } => true,
            Self::Api { status, .. } => matches!(status, 500 | 502 | 503 | 504 | 520 | 522),
            Self::Json(_)
            | Self::Unauthorized(_)
            | Self::NotFound(_)
            | Self::Async(_)
            | Self::Config(_)
            | Self::InvalidInput(_) => false,
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
                service: "dockerhub".into(),
                message: error.to_string(),
                status_code: error.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Json(error) => FcpError::Internal {
                message: format!("JSON parse error: {error}"),
            },
            Self::Api { status, message } => FcpError::External {
                service: "dockerhub".into(),
                message: format!("Docker Hub API error {status}: {message}"),
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

impl ConnectorErrorMapping for DockerHubError {
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
        let err = DockerHubError::RateLimited {
            retry_after_ms: 5_000,
        };
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn unauthorized_is_not_retryable() {
        let err = DockerHubError::Unauthorized("bad token".into());
        assert!(!err.is_retryable());
        assert!(err.retry_after().is_none());
    }

    #[test]
    fn not_found_maps_to_resource_not_found() {
        let err = DockerHubError::NotFound("repo myuser/myrepo".into());
        let fcp = err.to_fcp_error();
        assert!(matches!(
            fcp,
            FcpError::ResourceNotFound { ref resource } if resource == "repo myuser/myrepo"
        ));
    }

    #[test]
    fn api_error_retryable_for_server_errors() {
        let retryable = DockerHubError::Api {
            status: 502,
            message: "Bad Gateway".into(),
        };
        assert!(retryable.is_retryable());

        let terminal = DockerHubError::Api {
            status: 400,
            message: "Bad request".into(),
        };
        assert!(!terminal.is_retryable());
    }

    #[test]
    fn config_error_maps_to_invalid_request() {
        let err = DockerHubError::Config("missing credentials".into());
        let fcp = err.to_fcp_error();
        assert!(matches!(
            fcp,
            FcpError::InvalidRequest { code: 1001, ref message }
                if message.contains("missing credentials")
        ));
    }

    #[test]
    fn rate_limited_maps_to_fcp_rate_limited() {
        let err = DockerHubError::RateLimited {
            retry_after_ms: 3_000,
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(
            fcp,
            FcpError::RateLimited {
                retry_after_ms: 3_000,
                violation: None,
            }
        ));
    }

    #[test]
    fn async_error_mapping_preserves_timeout() {
        let err = DockerHubError::from_async_error(AsyncError::Timeout { timeout_ms: 1_500 });
        assert_eq!(
            err.to_string(),
            "Async error: request deadline exceeded after 1500ms"
        );
    }

    #[test]
    fn async_error_cancelled() {
        let err = DockerHubError::from_async_error(AsyncError::Cancelled);
        assert_eq!(err.to_string(), "Async error: operation cancelled");
    }

    #[test]
    fn invalid_input_maps_correctly() {
        let err = DockerHubError::InvalidInput("namespace required".into());
        let fcp = err.to_fcp_error();
        assert!(matches!(
            fcp,
            FcpError::InvalidRequest { code: 1005, ref message }
                if message == "namespace required"
        ));
    }

    #[test]
    fn json_error_is_not_retryable() {
        let raw_err = serde_json::from_str::<serde_json::Value>("not json").unwrap_err();
        let err = DockerHubError::Json(raw_err);
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_500_is_retryable() {
        let err = DockerHubError::Api {
            status: 500,
            message: "Internal".into(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_503_is_retryable() {
        let err = DockerHubError::Api {
            status: 503,
            message: "Service Unavailable".into(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_422_is_not_retryable() {
        let err = DockerHubError::Api {
            status: 422,
            message: "Unprocessable".into(),
        };
        assert!(!err.is_retryable());
    }
}
