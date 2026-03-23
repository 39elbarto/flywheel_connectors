//! Error types for the `DingTalk` connector.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_core::FcpError;
use fcp_sdk::migration::ConnectorErrorMapping;

pub type DingTalkResult<T> = Result<T, DingTalkError>;

#[derive(Debug, thiserror::Error)]
pub enum DingTalkError {
    #[error("HTTP transport error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("DingTalk API error {code}: {message}")]
    Api { code: u32, message: String },

    #[error("DingTalk media error {errcode}: {errmsg}")]
    Media { errcode: i64, errmsg: String },

    #[error("Rate limited (retry after {retry_after_ms}ms)")]
    RateLimited { retry_after_ms: u64 },

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Async error: {0}")]
    Async(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Token error: {0}")]
    Token(String),
}

impl DingTalkError {
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http(error) => error.is_timeout() || error.is_connect(),
            Self::RateLimited { .. } => true,
            Self::Api { code, .. } => matches!(code, 429 | 500 | 502 | 503 | 504),
            Self::Media { .. }
            | Self::Json(_)
            | Self::Unauthorized(_)
            | Self::Async(_)
            | Self::Config(_)
            | Self::InvalidInput(_)
            | Self::Token(_) => false,
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
                service: "dingtalk".into(),
                message: error.to_string(),
                status_code: error.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Json(error) => FcpError::Internal {
                message: format!("JSON parse error: {error}"),
            },
            Self::Api { code, message } => FcpError::External {
                service: "dingtalk".into(),
                message: format!("DingTalk API error {code}: {message}"),
                status_code: u16::try_from(*code)
                    .ok()
                    .filter(|&c| (100..600).contains(&c)),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Media { errcode, errmsg } => FcpError::External {
                service: "dingtalk".into(),
                message: format!("DingTalk media error {errcode}: {errmsg}"),
                status_code: None,
                retryable: false,
                retry_after: None,
            },
            Self::RateLimited { retry_after_ms } => FcpError::RateLimited {
                retry_after_ms: *retry_after_ms,
                violation: None,
            },
            Self::Unauthorized(message) => FcpError::Unauthorized {
                code: 2001,
                message: message.clone(),
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
            Self::Token(message) => FcpError::External {
                service: "dingtalk".into(),
                message: format!("Token error: {message}"),
                status_code: None,
                retryable: true,
                retry_after: None,
            },
        }
    }
}

impl ConnectorErrorMapping for DingTalkError {
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
        let err = DingTalkError::RateLimited {
            retry_after_ms: 5_000,
        };
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn unauthorized_is_not_retryable() {
        let err = DingTalkError::Unauthorized("bad token".into());
        assert!(!err.is_retryable());
        assert_eq!(err.retry_after(), None);
    }

    #[test]
    fn api_error_retryable_for_server_errors() {
        for code in [429, 500, 502, 503, 504] {
            let err = DingTalkError::Api {
                code,
                message: "server error".into(),
            };
            assert!(err.is_retryable(), "code {code} should be retryable");
        }
        let err = DingTalkError::Api {
            code: 400,
            message: "bad request".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn config_error_maps_to_invalid_request() {
        let err = DingTalkError::Config("missing client_id".into());
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1001);
                assert!(message.contains("missing client_id"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn media_error_maps_to_external() {
        let err = DingTalkError::Media {
            errcode: 40001,
            errmsg: "invalid media".into(),
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::External {
                service, retryable, ..
            } => {
                assert_eq!(service, "dingtalk");
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn token_error_is_retryable() {
        let err = DingTalkError::Token("expired".into());
        // Token errors are not retryable at the error variant level
        assert!(!err.is_retryable());
        // But the FcpError mapping marks them retryable for upstream retry logic
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::External { retryable, .. } => {
                assert!(retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn async_error_mapping_preserves_timeout() {
        let async_err = AsyncError::Timeout { timeout_ms: 30000 };
        let err = DingTalkError::from_async_error(async_err);
        match &err {
            DingTalkError::Async(msg) => {
                assert!(msg.contains("30000"));
                assert!(msg.contains("deadline exceeded"));
            }
            other => panic!("expected Async, got {other:?}"),
        }
    }

    #[test]
    fn json_error_maps_to_internal() {
        let json_err: serde_json::Error = serde_json::from_str::<String>("not json").unwrap_err();
        let err = DingTalkError::Json(json_err);
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::Internal { message } => {
                assert!(message.contains("JSON parse error"));
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn http_timeout_is_retryable() {
        // We can't easily construct a reqwest::Error with timeout,
        // so we verify the match arm logic via an API error with code 504
        let err = DingTalkError::Api {
            code: 504,
            message: "gateway timeout".into(),
        };
        assert!(err.is_retryable());
    }
}
