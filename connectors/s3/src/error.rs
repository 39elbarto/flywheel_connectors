//! S3-specific error types.

use std::time::Duration;

use fcp_core::FcpError;
use thiserror::Error;

/// S3-specific errors.
#[derive(Error, Debug)]
pub enum S3Error {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// S3 API returned an error
    #[error("S3 API error: {message} (code: {code})")]
    Api {
        code: String,
        message: String,
        status_code: Option<u16>,
    },

    /// Rate limited
    #[error("Rate limited")]
    RateLimited { retry_after_ms: u64 },

    /// Unauthorized (invalid credentials)
    #[error("Unauthorized")]
    Unauthorized,

    /// Object not found
    #[error("Object not found: {key}")]
    NotFound { key: String },

    /// Bucket not found
    #[error("Bucket not found: {bucket}")]
    BucketNotFound { bucket: String },
}

impl S3Error {
    /// Check if this error is retryable.
    ///
    /// Note: not `const fn` because we match on string error codes in `Api`.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) => true,
            Self::RateLimited { .. } => true,
            Self::Api { status_code, .. } => {
                matches!(status_code, Some(500..=599 | 429))
            }
            Self::Unauthorized | Self::NotFound { .. } | Self::BucketNotFound { .. } => false,
            Self::Json(_) => false,
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
                service: "s3".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Api {
                code,
                message,
                status_code,
            } => {
                if *status_code == Some(401) || *status_code == Some(403) {
                    FcpError::Unauthorized {
                        code: 2001,
                        message: "Invalid S3 credentials".into(),
                    }
                } else if *status_code == Some(429) {
                    FcpError::RateLimited {
                        retry_after_ms: 30_000,
                        violation: None,
                    }
                } else if *status_code == Some(404) {
                    FcpError::ResourceNotFound {
                        resource: message.clone(),
                    }
                } else {
                    FcpError::External {
                        service: "s3".into(),
                        message: format!("{code}: {message}"),
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
            Self::Unauthorized => FcpError::Unauthorized {
                code: 2001,
                message: "Invalid S3 credentials".into(),
            },
            Self::NotFound { key } => FcpError::ResourceNotFound {
                resource: format!("object:{key}"),
            },
            Self::BucketNotFound { bucket } => FcpError::ResourceNotFound {
                resource: format!("bucket:{bucket}"),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
        }
    }
}

/// Result type for S3 operations.
pub type S3Result<T> = Result<T, S3Error>;

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Display ----

    #[test]
    fn display_api_error() {
        let err = S3Error::Api {
            code: "NoSuchKey".into(),
            message: "The specified key does not exist.".into(),
            status_code: Some(404),
        };
        let s = err.to_string();
        assert!(s.contains("NoSuchKey"));
        assert!(s.contains("does not exist"));
    }

    #[test]
    fn display_rate_limited() {
        let err = S3Error::RateLimited {
            retry_after_ms: 5000,
        };
        assert!(err.to_string().contains("Rate limited"));
    }

    #[test]
    fn display_unauthorized() {
        let err = S3Error::Unauthorized;
        assert!(err.to_string().contains("Unauthorized"));
    }

    #[test]
    fn display_not_found() {
        let err = S3Error::NotFound {
            key: "my-object.txt".into(),
        };
        assert!(err.to_string().contains("my-object.txt"));
    }

    #[test]
    fn display_bucket_not_found() {
        let err = S3Error::BucketNotFound {
            bucket: "my-bucket".into(),
        };
        assert!(err.to_string().contains("my-bucket"));
    }

    // ---- is_retryable ----

    #[test]
    fn is_retryable_rate_limited() {
        assert!(
            S3Error::RateLimited {
                retry_after_ms: 1000
            }
            .is_retryable()
        );
    }

    #[test]
    fn is_retryable_api_500() {
        assert!(
            S3Error::Api {
                code: "InternalError".into(),
                message: "internal".into(),
                status_code: Some(500),
            }
            .is_retryable()
        );
    }

    #[test]
    fn is_retryable_api_503() {
        assert!(
            S3Error::Api {
                code: "SlowDown".into(),
                message: "slow down".into(),
                status_code: Some(503),
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_api_400() {
        assert!(
            !S3Error::Api {
                code: "InvalidArgument".into(),
                message: "bad".into(),
                status_code: Some(400),
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_unauthorized() {
        assert!(!S3Error::Unauthorized.is_retryable());
    }

    #[test]
    fn not_retryable_not_found() {
        assert!(!S3Error::NotFound { key: "x".into() }.is_retryable());
    }

    #[test]
    fn not_retryable_bucket_not_found() {
        assert!(!S3Error::BucketNotFound { bucket: "x".into() }.is_retryable());
    }

    #[test]
    fn not_retryable_json() {
        let json_err = serde_json::from_str::<serde_json::Value>("x").unwrap_err();
        assert!(!S3Error::Json(json_err).is_retryable());
    }

    // ---- retry_after ----

    #[test]
    fn retry_after_rate_limited() {
        let err = S3Error::RateLimited {
            retry_after_ms: 5000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn retry_after_other_none() {
        assert_eq!(S3Error::Unauthorized.retry_after(), None);
        assert_eq!(S3Error::NotFound { key: "x".into() }.retry_after(), None);
    }

    // ---- to_fcp_error ----

    #[test]
    fn to_fcp_error_api_401_unauthorized() {
        let err = S3Error::Api {
            code: "AccessDenied".into(),
            message: "denied".into(),
            status_code: Some(401),
        };
        match err.to_fcp_error() {
            FcpError::Unauthorized { code, message } => {
                assert_eq!(code, 2001);
                assert!(message.contains("S3 credentials"));
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_403_unauthorized() {
        let err = S3Error::Api {
            code: "AccessDenied".into(),
            message: "forbidden".into(),
            status_code: Some(403),
        };
        assert!(matches!(err.to_fcp_error(), FcpError::Unauthorized { .. }));
    }

    #[test]
    fn to_fcp_error_api_429_rate_limited() {
        let err = S3Error::Api {
            code: "SlowDown".into(),
            message: "slow down".into(),
            status_code: Some(429),
        };
        match err.to_fcp_error() {
            FcpError::RateLimited { retry_after_ms, .. } => assert_eq!(retry_after_ms, 30_000),
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_404_resource_not_found() {
        let err = S3Error::Api {
            code: "NoSuchKey".into(),
            message: "The specified key does not exist.".into(),
            status_code: Some(404),
        };
        match err.to_fcp_error() {
            FcpError::ResourceNotFound { resource } => {
                assert!(resource.contains("does not exist"));
            }
            other => panic!("expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_500_external() {
        let err = S3Error::Api {
            code: "InternalError".into(),
            message: "server error".into(),
            status_code: Some(500),
        };
        match err.to_fcp_error() {
            FcpError::External {
                service, retryable, ..
            } => {
                assert_eq!(service, "s3");
                assert!(retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_rate_limited() {
        let err = S3Error::RateLimited {
            retry_after_ms: 2000,
        };
        match err.to_fcp_error() {
            FcpError::RateLimited {
                retry_after_ms,
                violation,
            } => {
                assert_eq!(retry_after_ms, 2000);
                assert!(violation.is_none());
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_unauthorized() {
        match S3Error::Unauthorized.to_fcp_error() {
            FcpError::Unauthorized { code, .. } => assert_eq!(code, 2001),
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_not_found() {
        let err = S3Error::NotFound {
            key: "data/file.csv".into(),
        };
        match err.to_fcp_error() {
            FcpError::ResourceNotFound { resource } => {
                assert!(resource.contains("object:data/file.csv"));
            }
            other => panic!("expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_bucket_not_found() {
        let err = S3Error::BucketNotFound {
            bucket: "my-bucket".into(),
        };
        match err.to_fcp_error() {
            FcpError::ResourceNotFound { resource } => {
                assert!(resource.contains("bucket:my-bucket"));
            }
            other => panic!("expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_json_internal() {
        let json_err = serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err();
        let err = S3Error::Json(json_err);
        match err.to_fcp_error() {
            FcpError::Internal { message } => assert!(message.contains("JSON error")),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    // ---- From impls ----

    #[test]
    fn from_serde_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("nope").unwrap_err();
        let err: S3Error = json_err.into();
        assert!(matches!(err, S3Error::Json(_)));
    }

    // ---- Result alias ----

    #[test]
    fn s3_result_ok() {
        let r: S3Result<u32> = Ok(42);
        assert!(r.is_ok());
    }

    #[test]
    fn s3_result_err() {
        let r: S3Result<u32> = Err(S3Error::Unauthorized);
        assert!(r.is_err());
    }

    // ---- std::error::Error trait ----

    #[test]
    fn error_trait_impl() {
        let err = S3Error::Unauthorized;
        let _: &dyn std::error::Error = &err;
    }
}
