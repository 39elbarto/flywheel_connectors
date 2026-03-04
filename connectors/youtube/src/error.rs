//! YouTube-specific error types.

use std::time::Duration;

use fcp_core::FcpError;
use thiserror::Error;

/// YouTube-specific errors.
#[derive(Error, Debug)]
pub enum YouTubeError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// YouTube API returned an error
    #[error("YouTube API error: {message} (status {status_code:?})")]
    Api {
        message: String,
        status_code: Option<u16>,
    },

    /// Rate limited / quota exceeded
    #[error("Rate limited, retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },

    /// Quota exceeded (daily limit)
    #[error("YouTube API quota exceeded")]
    QuotaExceeded,

    /// Invalid or expired API key / OAuth token
    #[error("Invalid or expired YouTube credentials")]
    Unauthorized,

    /// Resource not found (404)
    #[error("Resource not found: {resource}")]
    NotFound { resource: String },

    /// Forbidden (comments disabled, etc.)
    #[error("Forbidden: {message}")]
    Forbidden { message: String },
}

impl YouTubeError {
    /// Check if this error is retryable.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) => true,
            Self::RateLimited { .. } => true,
            Self::Api { status_code, .. } => matches!(status_code, Some(500..=599 | 429)),
            _ => false,
        }
    }

    /// Get the suggested retry delay.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after_ms } => Some(Duration::from_millis(*retry_after_ms)),
            _ => None,
        }
    }

    /// Convert to FCP error.
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Http(e) => FcpError::External {
                service: "youtube".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Api {
                message,
                status_code,
            } => {
                if *status_code == Some(401) {
                    FcpError::Unauthorized {
                        code: 2001,
                        message: "Invalid or expired YouTube credentials".into(),
                    }
                } else if *status_code == Some(403) {
                    FcpError::Unauthorized {
                        code: 2001,
                        message: message.clone(),
                    }
                } else if *status_code == Some(429) {
                    FcpError::RateLimited {
                        retry_after_ms: 60_000,
                        violation: None,
                    }
                } else {
                    FcpError::External {
                        service: "youtube".into(),
                        message: message.clone(),
                        status_code: *status_code,
                        retryable: self.is_retryable(),
                        retry_after: self.retry_after(),
                    }
                }
            }
            Self::RateLimited { retry_after_ms } => FcpError::RateLimited {
                retry_after_ms: *retry_after_ms,
                violation: None,
            },
            Self::QuotaExceeded => FcpError::RateLimited {
                retry_after_ms: 86_400_000, // 24 hours
                violation: None,
            },
            Self::Unauthorized => FcpError::Unauthorized {
                code: 2001,
                message: "Invalid or expired YouTube credentials".into(),
            },
            Self::NotFound { resource } => FcpError::ResourceNotFound {
                resource: resource.clone(),
            },
            Self::Forbidden { message } => FcpError::Unauthorized {
                code: 2002,
                message: message.clone(),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
        }
    }
}

/// Result type for YouTube operations.
pub type YouTubeResult<T> = Result<T, YouTubeError>;

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Display messages ----

    #[test]
    fn display_api_error() {
        let err = YouTubeError::Api {
            message: "videoNotFound".into(),
            status_code: Some(404),
        };
        assert!(err.to_string().contains("videoNotFound"));
        assert!(err.to_string().contains("404"));
    }

    #[test]
    fn display_rate_limited() {
        let err = YouTubeError::RateLimited {
            retry_after_ms: 5000,
        };
        assert!(err.to_string().contains("5000ms"));
    }

    #[test]
    fn display_quota_exceeded() {
        let err = YouTubeError::QuotaExceeded;
        assert!(err.to_string().contains("quota exceeded"));
    }

    #[test]
    fn display_unauthorized() {
        let err = YouTubeError::Unauthorized;
        assert!(err.to_string().contains("credentials"));
    }

    #[test]
    fn display_not_found() {
        let err = YouTubeError::NotFound {
            resource: "video:abc".into(),
        };
        assert!(err.to_string().contains("video:abc"));
    }

    #[test]
    fn display_forbidden() {
        let err = YouTubeError::Forbidden {
            message: "comments disabled".into(),
        };
        assert!(err.to_string().contains("comments disabled"));
    }

    #[test]
    fn display_json() {
        let json_err = serde_json::from_str::<serde_json::Value>("bad").unwrap_err();
        let err = YouTubeError::Json(json_err);
        assert!(err.to_string().contains("JSON error"));
    }

    // ---- is_retryable ----

    #[test]
    fn is_retryable_rate_limited() {
        let err = YouTubeError::RateLimited {
            retry_after_ms: 1000,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn is_retryable_api_500() {
        let err = YouTubeError::Api {
            message: "internal".into(),
            status_code: Some(500),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn is_retryable_api_503() {
        let err = YouTubeError::Api {
            message: "unavailable".into(),
            status_code: Some(503),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn is_retryable_api_429() {
        let err = YouTubeError::Api {
            message: "too many".into(),
            status_code: Some(429),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn not_retryable_api_400() {
        let err = YouTubeError::Api {
            message: "bad request".into(),
            status_code: Some(400),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn not_retryable_api_no_status() {
        let err = YouTubeError::Api {
            message: "unknown".into(),
            status_code: None,
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn not_retryable_quota_exceeded() {
        let err = YouTubeError::QuotaExceeded;
        assert!(!err.is_retryable());
    }

    #[test]
    fn not_retryable_unauthorized() {
        let err = YouTubeError::Unauthorized;
        assert!(!err.is_retryable());
    }

    #[test]
    fn not_retryable_not_found() {
        let err = YouTubeError::NotFound {
            resource: "x".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn not_retryable_forbidden() {
        let err = YouTubeError::Forbidden {
            message: "x".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn not_retryable_json() {
        let json_err = serde_json::from_str::<serde_json::Value>("x").unwrap_err();
        let err = YouTubeError::Json(json_err);
        assert!(!err.is_retryable());
    }

    // ---- retry_after ----

    #[test]
    fn retry_after_rate_limited() {
        let err = YouTubeError::RateLimited {
            retry_after_ms: 5000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn retry_after_other_variants_none() {
        assert_eq!(
            YouTubeError::Api {
                message: "x".into(),
                status_code: Some(500)
            }
            .retry_after(),
            None
        );
        assert_eq!(YouTubeError::QuotaExceeded.retry_after(), None);
        assert_eq!(YouTubeError::Unauthorized.retry_after(), None);
    }

    // ---- to_fcp_error ----

    #[test]
    fn to_fcp_error_api_401_unauthorized() {
        let err = YouTubeError::Api {
            message: "bad key".into(),
            status_code: Some(401),
        };
        match err.to_fcp_error() {
            FcpError::Unauthorized { code, message } => {
                assert_eq!(code, 2001);
                assert!(message.contains("credentials"));
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_403_unauthorized() {
        let err = YouTubeError::Api {
            message: "forbidden action".into(),
            status_code: Some(403),
        };
        match err.to_fcp_error() {
            FcpError::Unauthorized { code, message } => {
                assert_eq!(code, 2001);
                assert!(message.contains("forbidden action"));
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_429_rate_limited() {
        let err = YouTubeError::Api {
            message: "too many".into(),
            status_code: Some(429),
        };
        match err.to_fcp_error() {
            FcpError::RateLimited {
                retry_after_ms, ..
            } => {
                assert_eq!(retry_after_ms, 60_000);
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_500_external() {
        let err = YouTubeError::Api {
            message: "server error".into(),
            status_code: Some(500),
        };
        match err.to_fcp_error() {
            FcpError::External {
                service,
                retryable,
                status_code,
                ..
            } => {
                assert_eq!(service, "youtube");
                assert!(retryable);
                assert_eq!(status_code, Some(500));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_no_status() {
        let err = YouTubeError::Api {
            message: "unknown".into(),
            status_code: None,
        };
        match err.to_fcp_error() {
            FcpError::External {
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(status_code, None);
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_rate_limited() {
        let err = YouTubeError::RateLimited {
            retry_after_ms: 2500,
        };
        match err.to_fcp_error() {
            FcpError::RateLimited {
                retry_after_ms,
                violation,
            } => {
                assert_eq!(retry_after_ms, 2500);
                assert!(violation.is_none());
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_quota_exceeded_24h() {
        let err = YouTubeError::QuotaExceeded;
        match err.to_fcp_error() {
            FcpError::RateLimited {
                retry_after_ms, ..
            } => {
                assert_eq!(retry_after_ms, 86_400_000);
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_unauthorized() {
        let err = YouTubeError::Unauthorized;
        match err.to_fcp_error() {
            FcpError::Unauthorized { code, .. } => assert_eq!(code, 2001),
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_not_found() {
        let err = YouTubeError::NotFound {
            resource: "video:xyz".into(),
        };
        match err.to_fcp_error() {
            FcpError::ResourceNotFound { resource } => {
                assert_eq!(resource, "video:xyz");
            }
            other => panic!("expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_forbidden() {
        let err = YouTubeError::Forbidden {
            message: "comments disabled".into(),
        };
        match err.to_fcp_error() {
            FcpError::Unauthorized { code, message } => {
                assert_eq!(code, 2002);
                assert!(message.contains("comments disabled"));
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_json_internal() {
        let json_err = serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err();
        let err = YouTubeError::Json(json_err);
        match err.to_fcp_error() {
            FcpError::Internal { message } => {
                assert!(message.contains("JSON error"));
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    // ---- YouTubeResult alias ----

    #[test]
    fn youtube_result_ok() {
        let r: YouTubeResult<u32> = Ok(42);
        assert!(r.is_ok());
    }

    #[test]
    fn youtube_result_err() {
        let r: YouTubeResult<u32> = Err(YouTubeError::QuotaExceeded);
        assert!(r.is_err());
    }

    // ---- From impls ----

    #[test]
    fn from_serde_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("nope").unwrap_err();
        let err: YouTubeError = json_err.into();
        assert!(matches!(err, YouTubeError::Json(_)));
    }

    // ---- std::error::Error trait ----

    #[test]
    fn error_trait_impl() {
        let err = YouTubeError::QuotaExceeded;
        let _: &dyn std::error::Error = &err;
    }
}
