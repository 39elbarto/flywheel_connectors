//! Error types for the `Sonos` connector.

use fcp_core::FcpError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SonosError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("api error: status={status}, message={message}")]
    Api { status: u16, message: String },

    #[error("parse error: {0}")]
    Parse(String),
}

pub type SonosResult<T> = Result<T, SonosError>;

impl SonosError {
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Config(message) => FcpError::InvalidRequest {
                code: 1003,
                message: message.clone(),
            },
            Self::Http(error) if error.is_timeout() => FcpError::UpstreamTimeout {
                service: "sonos".into(),
            },
            Self::Http(error) => FcpError::External {
                service: "sonos".into(),
                message: error.to_string(),
                status_code: None,
                retryable: error.is_connect() || error.is_timeout(),
                retry_after: None,
            },
            Self::Api { status, message } => FcpError::External {
                service: "sonos".into(),
                message: message.clone(),
                status_code: Some(*status),
                retryable: matches!(status, 408 | 429 | 500 | 502 | 503 | 504),
                retry_after: None,
            },
            Self::Parse(message) => FcpError::Internal {
                message: message.clone(),
            },
        }
    }

    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http(error) => error.is_connect() || error.is_timeout(),
            Self::Api { status, .. } => matches!(status, 408 | 429 | 500 | 502 | 503 | 504),
            Self::Config(_) | Self::Parse(_) => false,
        }
    }
}

impl fcp_sdk::migration::ConnectorErrorMapping for SonosError {
    fn from_async_error(error: fcp_async_core::AsyncError) -> Self {
        match error {
            fcp_async_core::AsyncError::Timeout { timeout_ms } => Self::Api {
                status: 408,
                message: format!("deadline exceeded after {timeout_ms}ms"),
            },
            fcp_async_core::AsyncError::Cancelled => Self::Api {
                status: 0,
                message: "request cancelled".into(),
            },
            other => Self::Api {
                status: 0,
                message: other.to_string(),
            },
        }
    }

    fn to_fcp_error(&self) -> FcpError {
        self.to_fcp_error()
    }

    fn is_retryable(&self) -> bool {
        self.is_retryable()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_error_maps_to_invalid_request() {
        let err = SonosError::Config("bad".into());
        assert!(matches!(
            err.to_fcp_error(),
            FcpError::InvalidRequest { .. }
        ));
    }

    #[test]
    fn api_500_maps_to_retryable_external() {
        let err = SonosError::Api {
            status: 500,
            message: "internal".into(),
        };
        match err.to_fcp_error() {
            FcpError::External {
                retryable,
                status_code,
                ..
            } => {
                assert!(retryable);
                assert_eq!(status_code, Some(500));
            }
            other => assert!(matches!(other, FcpError::External { .. })),
        }
    }

    #[test]
    fn api_404_maps_to_non_retryable_external() {
        let err = SonosError::Api {
            status: 404,
            message: "not found".into(),
        };
        match err.to_fcp_error() {
            FcpError::External { retryable, .. } => assert!(!retryable),
            other => assert!(matches!(other, FcpError::External { .. })),
        }
    }

    #[test]
    fn parse_error_maps_to_internal() {
        let err = SonosError::Parse("bad xml".into());
        assert!(matches!(err.to_fcp_error(), FcpError::Internal { .. }));
    }

    #[test]
    fn api_429_is_retryable() {
        let err = SonosError::Api {
            status: 429,
            message: "rate limited".into(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_400_is_not_retryable() {
        let err = SonosError::Api {
            status: 400,
            message: "bad request".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn config_error_is_not_retryable() {
        let err = SonosError::Config("bad".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn parse_error_is_not_retryable() {
        let err = SonosError::Parse("bad xml".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn error_display_config() {
        let err = SonosError::Config("missing url".into());
        assert_eq!(err.to_string(), "configuration error: missing url");
    }

    #[test]
    fn error_display_api() {
        let err = SonosError::Api {
            status: 503,
            message: "unavailable".into(),
        };
        assert_eq!(
            err.to_string(),
            "api error: status=503, message=unavailable"
        );
    }

    #[test]
    fn error_display_parse() {
        let err = SonosError::Parse("expected closing tag".into());
        assert_eq!(err.to_string(), "parse error: expected closing tag");
    }

    #[test]
    fn connector_error_mapping_from_timeout() {
        use fcp_sdk::migration::ConnectorErrorMapping;
        let err =
            SonosError::from_async_error(fcp_async_core::AsyncError::Timeout { timeout_ms: 3000 });
        assert!(matches!(err, SonosError::Api { status: 408, .. }));
        assert!(err.is_retryable(), "timeout should remain retryable");
        match err.to_fcp_error() {
            FcpError::External { retryable, .. } => assert!(retryable),
            other => assert!(matches!(other, FcpError::External { .. })),
        }
    }

    #[test]
    fn connector_error_mapping_from_cancelled() {
        use fcp_sdk::migration::ConnectorErrorMapping;
        let err = SonosError::from_async_error(fcp_async_core::AsyncError::Cancelled);
        assert!(matches!(err, SonosError::Api { .. }));
        assert!(err.to_string().contains("cancelled"));
    }
}
