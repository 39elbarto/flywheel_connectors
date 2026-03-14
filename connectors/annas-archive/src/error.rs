use std::time::Duration;

use fcp_core::FcpError;
use fcp_async_core::AsyncError;
use fcp_sdk::migration::ConnectorErrorMapping;

pub type AnnasArchiveResult<T> = Result<T, AnnasArchiveError>;

#[derive(Debug, thiserror::Error)]
pub enum AnnasArchiveError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("API error (status {status_code}): {message}")]
    Api { status_code: u16, message: String },

    #[error("Rate limited")]
    RateLimited { retry_after_ms: u64 },

    #[error("Not found: {resource}")]
    NotFound { resource: String },

    #[error("Service unavailable")]
    ServiceUnavailable,
}

impl AnnasArchiveError {
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::RateLimited { .. } | Self::ServiceUnavailable | Self::Http(_)
        )
    }

    #[must_use]
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after_ms } => Some(Duration::from_millis(*retry_after_ms)),
            Self::ServiceUnavailable => Some(Duration::from_secs(5)),
            _ => None,
        }
    }

    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Http(e) => FcpError::External {
                service: "annas-archive".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
            Self::Api {
                status_code,
                message,
            } => FcpError::External {
                service: "annas-archive".into(),
                message: message.clone(),
                status_code: Some(*status_code),
                retryable: self.is_retryable(),
                retry_after: None,
            },
            Self::RateLimited { retry_after_ms } => FcpError::External {
                service: "annas-archive".into(),
                message: format!("Rate limited, retry after {retry_after_ms}ms"),
                status_code: Some(429),
                retryable: true,
                retry_after: self.retry_after(),
            },
            Self::NotFound { resource } => FcpError::ResourceNotFound {
                resource: resource.clone(),
            },
            Self::ServiceUnavailable => FcpError::External {
                service: "annas-archive".into(),
                message: "Service unavailable".into(),
                status_code: Some(503),
                retryable: true,
                retry_after: self.retry_after(),
            },
        }
    }
}

impl ConnectorErrorMapping for AnnasArchiveError {
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
        let err = AnnasArchiveError::RateLimited {
            retry_after_ms: 60_000,
        };
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(Duration::from_secs(60)));
    }

    #[test]
    fn not_found_is_not_retryable() {
        let err = AnnasArchiveError::NotFound {
            resource: "md5:abc".into(),
        };
        assert!(!err.is_retryable());
        assert!(err.retry_after().is_none());
    }

    #[test]
    fn api_error_is_not_retryable() {
        let err = AnnasArchiveError::Api {
            status_code: 400,
            message: "Bad request".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn service_unavailable_is_retryable() {
        let err = AnnasArchiveError::ServiceUnavailable;
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn json_error_is_not_retryable() {
        let err: AnnasArchiveError = serde_json::from_str::<serde_json::Value>("invalid")
            .unwrap_err()
            .into();
        assert!(!err.is_retryable());
    }

    #[test]
    fn fcp_error_rate_limited() {
        let err = AnnasArchiveError::RateLimited {
            retry_after_ms: 1000,
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(
            fcp,
            FcpError::External {
                retryable: true,
                ..
            }
        ));
    }

    #[test]
    fn fcp_error_not_found() {
        let err = AnnasArchiveError::NotFound {
            resource: "isbn:123".into(),
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::ResourceNotFound { .. }));
    }

    #[test]
    fn fcp_error_api() {
        let err = AnnasArchiveError::Api {
            status_code: 500,
            message: "Internal".into(),
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::External { .. }));
    }

    #[test]
    fn fcp_error_unavailable() {
        let err = AnnasArchiveError::ServiceUnavailable;
        let fcp = err.to_fcp_error();
        assert!(matches!(
            fcp,
            FcpError::External {
                retryable: true,
                ..
            }
        ));
    }

    #[test]
    fn error_display_api() {
        let err = AnnasArchiveError::Api {
            status_code: 422,
            message: "Unprocessable".into(),
        };
        let s = err.to_string();
        assert!(s.contains("422"));
        assert!(s.contains("Unprocessable"));
    }

    #[test]
    fn error_display_not_found() {
        let err = AnnasArchiveError::NotFound {
            resource: "md5:abc123".into(),
        };
        assert!(err.to_string().contains("md5:abc123"));
    }

    #[test]
    fn error_display_rate_limited() {
        let err = AnnasArchiveError::RateLimited {
            retry_after_ms: 30_000,
        };
        assert!(err.to_string().contains("Rate limited"));
    }

    // ── Display exhaustive ──────────────────────────────────────────

    #[test]
    fn error_display_service_unavailable() {
        let err = AnnasArchiveError::ServiceUnavailable;
        assert_eq!(err.to_string(), "Service unavailable");
    }

    #[test]
    fn error_display_json() {
        let inner = serde_json::from_str::<serde_json::Value>("{{bad").unwrap_err();
        let err = AnnasArchiveError::Json(inner);
        let s = err.to_string();
        assert!(s.starts_with("JSON error:"), "got: {s}");
    }

    #[test]
    fn error_display_api_with_empty_message() {
        let err = AnnasArchiveError::Api {
            status_code: 400,
            message: String::new(),
        };
        let s = err.to_string();
        assert!(s.contains("400"));
    }

    #[test]
    fn error_display_not_found_empty_resource() {
        let err = AnnasArchiveError::NotFound {
            resource: String::new(),
        };
        assert!(err.to_string().contains("Not found:"));
    }

    // ── retry_after edge cases ──────────────────────────────────────

    #[test]
    fn retry_after_rate_limited_zero_ms() {
        let err = AnnasArchiveError::RateLimited { retry_after_ms: 0 };
        assert_eq!(err.retry_after(), Some(Duration::from_millis(0)));
    }

    #[test]
    fn retry_after_rate_limited_large_value() {
        let err = AnnasArchiveError::RateLimited {
            retry_after_ms: 3_600_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(3600)));
    }

    #[test]
    fn retry_after_json_error_is_none() {
        let inner = serde_json::from_str::<serde_json::Value>("bad").unwrap_err();
        let err = AnnasArchiveError::Json(inner);
        assert!(err.retry_after().is_none());
    }

    #[test]
    fn retry_after_api_error_is_none() {
        let err = AnnasArchiveError::Api {
            status_code: 503,
            message: "down".into(),
        };
        assert!(err.retry_after().is_none());
    }

    // ── is_retryable edge cases ─────────────────────────────────────

    #[test]
    fn api_500_is_not_retryable() {
        // Api variant is not retryable regardless of status code in this connector
        let err = AnnasArchiveError::Api {
            status_code: 500,
            message: "server error".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_503_is_not_retryable() {
        let err = AnnasArchiveError::Api {
            status_code: 503,
            message: "gateway".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_422_is_not_retryable() {
        let err = AnnasArchiveError::Api {
            status_code: 422,
            message: "unprocessable".into(),
        };
        assert!(!err.is_retryable());
    }

    // ── to_fcp_error exhaustive ─────────────────────────────────────

    #[test]
    fn fcp_error_json_is_internal() {
        let inner = serde_json::from_str::<serde_json::Value>("[bad").unwrap_err();
        let err = AnnasArchiveError::Json(inner);
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::Internal { message } => {
                assert!(message.starts_with("JSON error:"));
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn fcp_error_api_has_status_code() {
        let err = AnnasArchiveError::Api {
            status_code: 502,
            message: "bad gateway".into(),
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::External {
                service,
                status_code,
                message,
                retryable,
                retry_after,
            } => {
                assert_eq!(service, "annas-archive");
                assert_eq!(status_code, Some(502));
                assert_eq!(message, "bad gateway");
                assert!(!retryable);
                assert!(retry_after.is_none());
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn fcp_error_rate_limited_has_retry_after() {
        let err = AnnasArchiveError::RateLimited {
            retry_after_ms: 5000,
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::External {
                status_code,
                retryable,
                retry_after,
                ..
            } => {
                assert_eq!(status_code, Some(429));
                assert!(retryable);
                assert_eq!(retry_after, Some(Duration::from_secs(5)));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn fcp_error_not_found_has_resource() {
        let err = AnnasArchiveError::NotFound {
            resource: "md5:deadbeef".into(),
        };
        match err.to_fcp_error() {
            FcpError::ResourceNotFound { resource } => {
                assert_eq!(resource, "md5:deadbeef");
            }
            other => panic!("expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn fcp_error_service_unavailable_has_retry_after() {
        let err = AnnasArchiveError::ServiceUnavailable;
        match err.to_fcp_error() {
            FcpError::External {
                service,
                status_code,
                retryable,
                retry_after,
                message,
            } => {
                assert_eq!(service, "annas-archive");
                assert_eq!(status_code, Some(503));
                assert!(retryable);
                assert_eq!(retry_after, Some(Duration::from_secs(5)));
                assert_eq!(message, "Service unavailable");
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn fcp_error_api_non_retryable() {
        let err = AnnasArchiveError::Api {
            status_code: 400,
            message: "bad request".into(),
        };
        match err.to_fcp_error() {
            FcpError::External { retryable, .. } => assert!(!retryable),
            other => panic!("expected External, got {other:?}"),
        }
    }

    // ── Debug trait ─────────────────────────────────────────────────

    #[test]
    fn error_debug_api() {
        let err = AnnasArchiveError::Api {
            status_code: 404,
            message: "gone".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Api"));
        assert!(dbg.contains("404"));
    }

    #[test]
    fn error_debug_rate_limited() {
        let err = AnnasArchiveError::RateLimited {
            retry_after_ms: 10_000,
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("RateLimited"));
        assert!(dbg.contains("10000"));
    }

    #[test]
    fn error_debug_not_found() {
        let err = AnnasArchiveError::NotFound {
            resource: "isbn:abc".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("NotFound"));
        assert!(dbg.contains("isbn:abc"));
    }

    #[test]
    fn error_debug_service_unavailable() {
        let dbg = format!("{:?}", AnnasArchiveError::ServiceUnavailable);
        assert!(dbg.contains("ServiceUnavailable"));
    }

    #[test]
    fn error_debug_json() {
        let inner = serde_json::from_str::<serde_json::Value>("nope").unwrap_err();
        let err = AnnasArchiveError::Json(inner);
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Json"));
    }

    // ── From impls ──────────────────────────────────────────────────

    #[test]
    fn from_serde_json_error() {
        let inner = serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err();
        let err: AnnasArchiveError = inner.into();
        assert!(matches!(err, AnnasArchiveError::Json(_)));
    }

    // ── Boundary values ─────────────────────────────────────────────

    #[test]
    fn rate_limited_max_u64() {
        let err = AnnasArchiveError::RateLimited {
            retry_after_ms: u64::MAX,
        };
        assert!(err.is_retryable());
        // retry_after should still return Some (even if the duration is huge)
        assert!(err.retry_after().is_some());
    }

    #[test]
    fn api_error_status_code_zero() {
        let err = AnnasArchiveError::Api {
            status_code: 0,
            message: "weird".into(),
        };
        assert!(!err.is_retryable());
        let s = err.to_string();
        assert!(s.contains('0'));
    }

    #[test]
    fn api_error_status_code_max() {
        let err = AnnasArchiveError::Api {
            status_code: u16::MAX,
            message: "overflow".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn not_found_with_unicode_resource() {
        let err = AnnasArchiveError::NotFound {
            resource: "isbn:\u{1F4DA}".into(),
        };
        assert!(err.to_string().contains("\u{1F4DA}"));
        match err.to_fcp_error() {
            FcpError::ResourceNotFound { resource } => {
                assert!(resource.contains("\u{1F4DA}"));
            }
            other => panic!("expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn api_error_with_long_message() {
        let long_msg = "x".repeat(10_000);
        let err = AnnasArchiveError::Api {
            status_code: 500,
            message: long_msg.clone(),
        };
        assert!(err.to_string().contains(&long_msg));
    }

    #[test]
    fn api_error_empty_message_display() {
        let err = AnnasArchiveError::Api {
            status_code: 500,
            message: String::new(),
        };
        let s = err.to_string();
        assert!(s.contains("500"));
    }

    #[test]
    fn not_found_empty_resource_display() {
        let err = AnnasArchiveError::NotFound {
            resource: String::new(),
        };
        let s = err.to_string();
        assert!(s.contains("Not found:"));
    }

    #[test]
    fn service_unavailable_retry_after_5_seconds() {
        let err = AnnasArchiveError::ServiceUnavailable;
        let d = err.retry_after().unwrap();
        assert_eq!(d, Duration::from_secs(5));
    }

    #[test]
    fn rate_limited_retry_after_1ms() {
        let err = AnnasArchiveError::RateLimited { retry_after_ms: 1 };
        assert_eq!(err.retry_after(), Some(Duration::from_millis(1)));
    }

    #[test]
    fn fcp_error_rate_limited_service_field() {
        let err = AnnasArchiveError::RateLimited {
            retry_after_ms: 100,
        };
        match err.to_fcp_error() {
            FcpError::External { service, .. } => {
                assert_eq!(service, "annas-archive");
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn fcp_error_service_unavailable_message_content() {
        let err = AnnasArchiveError::ServiceUnavailable;
        match err.to_fcp_error() {
            FcpError::External { message, .. } => {
                assert_eq!(message, "Service unavailable");
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn from_reqwest_error_via_into() {
        let client = reqwest::Client::new();
        let err = client.get("://invalid").build();
        if let Err(e) = err {
            let ae: AnnasArchiveError = e.into();
            assert!(matches!(ae, AnnasArchiveError::Http(_)));
            assert!(ae.is_retryable());
        }
    }
}
