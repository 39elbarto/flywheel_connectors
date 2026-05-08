use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_sdk::migration::ConnectorErrorMapping;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AzureSpeechError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Azure Speech API error ({status_code}): {message}")]
    Api { status_code: u16, message: String },

    #[error("Rate limited, retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },

    #[error("Connector not configured")]
    NotConfigured,
}

impl ConnectorErrorMapping for AzureSpeechError {
    fn from_async_error(error: AsyncError) -> Self {
        match error {
            AsyncError::Timeout { timeout_ms } => Self::Api {
                status_code: 408,
                message: format!("deadline exceeded after {timeout_ms}ms"),
            },
            AsyncError::Cancelled => Self::Api {
                status_code: 0,
                message: "request cancelled".into(),
            },
            other => Self::Api {
                status_code: 0,
                message: other.to_string(),
            },
        }
    }

    fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Http(error) => {
                if error.is_timeout() {
                    FcpError::UpstreamTimeout {
                        service: "azure-speech".into(),
                    }
                } else {
                    FcpError::External {
                        service: "azure-speech".into(),
                        message: error.to_string(),
                        status_code: error.status().map(|status| status.as_u16()),
                        retryable: self.is_retryable(),
                        retry_after: None,
                    }
                }
            }
            Self::Json(error) => FcpError::Internal {
                message: format!("JSON error: {error}"),
            },
            Self::Api {
                status_code,
                message,
            } => {
                if *status_code == 429 {
                    FcpError::RateLimited {
                        retry_after_ms: 30_000,
                        violation: None,
                    }
                } else {
                    FcpError::External {
                        service: "azure-speech".into(),
                        message: message.clone(),
                        status_code: Some(*status_code),
                        retryable: self.is_retryable(),
                        retry_after: self.retry_after(),
                    }
                }
            }
            Self::RateLimited { retry_after_ms } => FcpError::RateLimited {
                retry_after_ms: *retry_after_ms,
                violation: None,
            },
            Self::NotConfigured => FcpError::NotConfigured,
        }
    }

    fn is_retryable(&self) -> bool {
        match self {
            Self::Http(error) => error.is_connect() || error.is_timeout(),
            Self::RateLimited { .. } => true,
            Self::Api { status_code, .. } => matches!(status_code, 408 | 429 | 500..=599),
            _ => false,
        }
    }

    fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after_ms } => Some(Duration::from_millis(*retry_after_ms)),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retryability_matches_azure_status_classes() {
        assert!(
            AzureSpeechError::Api {
                status_code: 500,
                message: "upstream".into(),
            }
            .is_retryable()
        );
        assert!(
            !AzureSpeechError::Api {
                status_code: 400,
                message: "bad request".into(),
            }
            .is_retryable()
        );
    }

    #[test]
    fn rate_limit_maps_to_fcp_rate_limited() {
        let error = AzureSpeechError::RateLimited {
            retry_after_ms: 5_000,
        };
        assert!(matches!(error.to_fcp_error(), FcpError::RateLimited { .. }));
        assert_eq!(error.retry_after(), Some(Duration::from_secs(5)));
    }
}
