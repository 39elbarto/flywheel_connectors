//! Linear-specific error types.

use std::time::Duration;

use fcp_core::FcpError;
use thiserror::Error;

/// Linear-specific errors.
#[derive(Error, Debug)]
pub enum LinearError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Linear GraphQL API returned errors
    #[error("Linear API error: {message}")]
    Api {
        message: String,
        status_code: Option<u16>,
    },

    /// Rate limited
    #[error("Rate limited, retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },

    /// Invalid or expired token
    #[error("Invalid or expired Linear API key")]
    Unauthorized,

    /// Resource not found
    #[error("Resource not found: {resource}")]
    NotFound { resource: String },
}

impl LinearError {
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
                service: "linear".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Api {
                message,
                status_code,
            } => {
                if *status_code == Some(401) || *status_code == Some(403) {
                    FcpError::Unauthorized {
                        code: 2001,
                        message: "Invalid or insufficient Linear API key".into(),
                    }
                } else if *status_code == Some(429) {
                    FcpError::RateLimited {
                        retry_after_ms: 60_000,
                        violation: None,
                    }
                } else {
                    FcpError::External {
                        service: "linear".into(),
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
            Self::Unauthorized => FcpError::Unauthorized {
                code: 2001,
                message: "Invalid or expired Linear API key".into(),
            },
            Self::NotFound { resource } => FcpError::ResourceNotFound {
                resource: resource.clone(),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
        }
    }
}

/// Result type for Linear operations.
pub type LinearResult<T> = Result<T, LinearError>;

#[cfg(test)]
mod tests {
    use super::*;

    // ════════════════════════════════════════════════════════════════
    // Display messages for all variants
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn display_api_error() {
        let err = LinearError::Api {
            message: "Entity not found".into(),
            status_code: Some(404),
        };
        assert!(err.to_string().contains("Entity not found"));
    }

    #[test]
    fn display_api_error_without_status() {
        let err = LinearError::Api {
            message: "Something went wrong".into(),
            status_code: None,
        };
        let s = err.to_string();
        assert!(s.contains("Something went wrong"));
        assert!(s.starts_with("Linear API error:"));
    }

    #[test]
    fn display_rate_limited() {
        let err = LinearError::RateLimited {
            retry_after_ms: 5000,
        };
        let s = err.to_string();
        assert!(s.contains("5000ms"));
        assert!(s.contains("Rate limited"));
    }

    #[test]
    fn display_rate_limited_zero_ms() {
        let err = LinearError::RateLimited { retry_after_ms: 0 };
        assert!(err.to_string().contains("0ms"));
    }

    #[test]
    fn display_unauthorized() {
        let s = LinearError::Unauthorized.to_string();
        assert!(s.contains("Linear API key"));
        assert!(s.contains("Invalid or expired"));
    }

    #[test]
    fn display_not_found() {
        let err = LinearError::NotFound {
            resource: "issue:abc".into(),
        };
        let s = err.to_string();
        assert!(s.contains("issue:abc"));
        assert!(s.contains("not found"));
    }

    #[test]
    fn display_not_found_empty_resource() {
        let err = LinearError::NotFound {
            resource: String::new(),
        };
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn display_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("not-json").unwrap_err();
        let err = LinearError::Json(json_err);
        let s = err.to_string();
        assert!(s.starts_with("JSON error:"));
    }

    #[test]
    fn display_http_error() {
        // Build a reqwest error via an invalid URL
        let client = reqwest::Client::new();
        let rt = fcp_async_core::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let http_err = rt
            .block_on(async { client.get("http://[::0:0:0:invalid]:0/bad").send().await })
            .unwrap_err();
        let err = LinearError::Http(http_err);
        let s = err.to_string();
        assert!(s.starts_with("HTTP error:"));
    }

    // ════════════════════════════════════════════════════════════════
    // is_retryable for all variants
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn is_retryable_rate_limited() {
        assert!(
            LinearError::RateLimited {
                retry_after_ms: 1000
            }
            .is_retryable()
        );
    }

    #[test]
    fn is_retryable_http_error() {
        let client = reqwest::Client::new();
        let rt = fcp_async_core::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let http_err = rt
            .block_on(async { client.get("http://[::0:0:0:invalid]:0/bad").send().await })
            .unwrap_err();
        assert!(LinearError::Http(http_err).is_retryable());
    }

    #[test]
    fn is_retryable_api_500() {
        assert!(
            LinearError::Api {
                message: "internal".into(),
                status_code: Some(500),
            }
            .is_retryable()
        );
    }

    #[test]
    fn is_retryable_api_502() {
        assert!(
            LinearError::Api {
                message: "bad gateway".into(),
                status_code: Some(502),
            }
            .is_retryable()
        );
    }

    #[test]
    fn is_retryable_api_503() {
        assert!(
            LinearError::Api {
                message: "service unavailable".into(),
                status_code: Some(503),
            }
            .is_retryable()
        );
    }

    #[test]
    fn is_retryable_api_599() {
        assert!(
            LinearError::Api {
                message: "network error".into(),
                status_code: Some(599),
            }
            .is_retryable()
        );
    }

    #[test]
    fn is_retryable_api_429() {
        assert!(
            LinearError::Api {
                message: "rate limited".into(),
                status_code: Some(429),
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_api_400() {
        assert!(
            !LinearError::Api {
                message: "bad".into(),
                status_code: Some(400),
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_api_404() {
        assert!(
            !LinearError::Api {
                message: "not found".into(),
                status_code: Some(404),
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_api_422() {
        assert!(
            !LinearError::Api {
                message: "unprocessable".into(),
                status_code: Some(422),
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_api_no_status() {
        assert!(
            !LinearError::Api {
                message: "graphql error".into(),
                status_code: None,
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_unauthorized() {
        assert!(!LinearError::Unauthorized.is_retryable());
    }

    #[test]
    fn not_retryable_not_found() {
        assert!(
            !LinearError::NotFound {
                resource: "x".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_json() {
        let json_err = serde_json::from_str::<serde_json::Value>("x").unwrap_err();
        assert!(!LinearError::Json(json_err).is_retryable());
    }

    // ════════════════════════════════════════════════════════════════
    // retry_after
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn retry_after_rate_limited() {
        let err = LinearError::RateLimited {
            retry_after_ms: 5000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn retry_after_rate_limited_zero() {
        let err = LinearError::RateLimited { retry_after_ms: 0 };
        assert_eq!(err.retry_after(), Some(Duration::from_millis(0)));
    }

    #[test]
    fn retry_after_rate_limited_large() {
        let err = LinearError::RateLimited {
            retry_after_ms: 120_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(120)));
    }

    #[test]
    fn retry_after_unauthorized_none() {
        assert_eq!(LinearError::Unauthorized.retry_after(), None);
    }

    #[test]
    fn retry_after_not_found_none() {
        assert_eq!(
            LinearError::NotFound {
                resource: "x".into()
            }
            .retry_after(),
            None
        );
    }

    #[test]
    fn retry_after_api_none() {
        assert_eq!(
            LinearError::Api {
                message: "err".into(),
                status_code: Some(500),
            }
            .retry_after(),
            None
        );
    }

    #[test]
    fn retry_after_json_none() {
        let json_err = serde_json::from_str::<serde_json::Value>("bad").unwrap_err();
        assert_eq!(LinearError::Json(json_err).retry_after(), None);
    }

    // ════════════════════════════════════════════════════════════════
    // to_fcp_error for all error-to-FcpError mappings
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn to_fcp_error_http() {
        let client = reqwest::Client::new();
        let rt = fcp_async_core::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let http_err = rt
            .block_on(async { client.get("http://[::0:0:0:invalid]:0/bad").send().await })
            .unwrap_err();
        let err = LinearError::Http(http_err);
        match err.to_fcp_error() {
            FcpError::External {
                service,
                retryable,
                status_code,
                ..
            } => {
                assert_eq!(service, "linear");
                assert!(retryable);
                // reqwest errors from DNS/connection won't have a status code
                assert!(status_code.is_none());
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_401() {
        let err = LinearError::Api {
            message: "unauthorized".into(),
            status_code: Some(401),
        };
        match err.to_fcp_error() {
            FcpError::Unauthorized { code, message } => {
                assert_eq!(code, 2001);
                assert!(message.contains("Linear API key"));
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_403() {
        let err = LinearError::Api {
            message: "forbidden".into(),
            status_code: Some(403),
        };
        match err.to_fcp_error() {
            FcpError::Unauthorized { code, message } => {
                assert_eq!(code, 2001);
                assert!(message.contains("insufficient"));
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_429() {
        let err = LinearError::Api {
            message: "rate limited".into(),
            status_code: Some(429),
        };
        match err.to_fcp_error() {
            FcpError::RateLimited {
                retry_after_ms,
                violation,
            } => {
                assert_eq!(retry_after_ms, 60_000);
                assert!(violation.is_none());
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_500_external() {
        let err = LinearError::Api {
            message: "server error".into(),
            status_code: Some(500),
        };
        match err.to_fcp_error() {
            FcpError::External {
                service,
                message,
                status_code,
                retryable,
                retry_after,
            } => {
                assert_eq!(service, "linear");
                assert_eq!(message, "server error");
                assert_eq!(status_code, Some(500));
                assert!(retryable);
                assert!(retry_after.is_none());
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_no_status_external() {
        let err = LinearError::Api {
            message: "graphql parse error".into(),
            status_code: None,
        };
        match err.to_fcp_error() {
            FcpError::External {
                service,
                message,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "linear");
                assert_eq!(message, "graphql parse error");
                assert!(status_code.is_none());
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_200_external() {
        // Non-auth, non-rate-limit, non-5xx status goes to External fallthrough
        let err = LinearError::Api {
            message: "bad request".into(),
            status_code: Some(400),
        };
        match err.to_fcp_error() {
            FcpError::External {
                service,
                retryable,
                status_code,
                ..
            } => {
                assert_eq!(service, "linear");
                assert!(!retryable);
                assert_eq!(status_code, Some(400));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_rate_limited() {
        let err = LinearError::RateLimited {
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
    fn to_fcp_error_rate_limited_zero() {
        let err = LinearError::RateLimited { retry_after_ms: 0 };
        match err.to_fcp_error() {
            FcpError::RateLimited { retry_after_ms, .. } => assert_eq!(retry_after_ms, 0),
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_unauthorized() {
        match LinearError::Unauthorized.to_fcp_error() {
            FcpError::Unauthorized { code, message } => {
                assert_eq!(code, 2001);
                assert!(message.contains("expired"));
                assert!(message.contains("Linear API key"));
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_not_found() {
        let err = LinearError::NotFound {
            resource: "issue:abc".into(),
        };
        match err.to_fcp_error() {
            FcpError::ResourceNotFound { resource } => assert_eq!(resource, "issue:abc"),
            other => panic!("expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_not_found_empty_resource() {
        let err = LinearError::NotFound {
            resource: String::new(),
        };
        match err.to_fcp_error() {
            FcpError::ResourceNotFound { resource } => assert_eq!(resource, ""),
            other => panic!("expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_json_internal() {
        let json_err = serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err();
        let err = LinearError::Json(json_err);
        match err.to_fcp_error() {
            FcpError::Internal { message } => {
                assert!(message.starts_with("JSON error:"));
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    // ════════════════════════════════════════════════════════════════
    // Debug format
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn debug_api_error() {
        let err = LinearError::Api {
            message: "some api error".into(),
            status_code: Some(502),
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("Api"));
        assert!(debug.contains("some api error"));
        assert!(debug.contains("502"));
    }

    #[test]
    fn debug_rate_limited() {
        let err = LinearError::RateLimited {
            retry_after_ms: 3000,
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("RateLimited"));
        assert!(debug.contains("3000"));
    }

    #[test]
    fn debug_unauthorized() {
        let debug = format!("{:?}", LinearError::Unauthorized);
        assert!(debug.contains("Unauthorized"));
    }

    #[test]
    fn debug_not_found() {
        let err = LinearError::NotFound {
            resource: "team:xyz".into(),
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("NotFound"));
        assert!(debug.contains("team:xyz"));
    }

    #[test]
    fn debug_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("!!!").unwrap_err();
        let err = LinearError::Json(json_err);
        let debug = format!("{err:?}");
        assert!(debug.contains("Json"));
    }

    // ════════════════════════════════════════════════════════════════
    // std::error::Error trait
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn error_trait_impl() {
        let _: &dyn std::error::Error = &LinearError::Unauthorized;
    }

    #[test]
    fn error_trait_source_json() {
        let json_err = serde_json::from_str::<serde_json::Value>("!!!").unwrap_err();
        let err = LinearError::Json(json_err);
        // Json variant wraps serde_json::Error via #[from], so source() is Some
        let source = std::error::Error::source(&err);
        assert!(source.is_some());
    }

    #[test]
    fn error_trait_source_unauthorized_none() {
        // Unit-like variants have no source
        let source = std::error::Error::source(&LinearError::Unauthorized);
        assert!(source.is_none());
    }

    #[test]
    fn error_trait_source_api_none() {
        // Api is a struct variant, not wrapping an error via #[from]
        let err = LinearError::Api {
            message: "test".into(),
            status_code: None,
        };
        let source = std::error::Error::source(&err);
        assert!(source.is_none());
    }

    #[test]
    fn error_trait_source_not_found_none() {
        let err = LinearError::NotFound {
            resource: "x".into(),
        };
        let source = std::error::Error::source(&err);
        assert!(source.is_none());
    }

    #[test]
    fn error_trait_source_rate_limited_none() {
        let err = LinearError::RateLimited {
            retry_after_ms: 100,
        };
        let source = std::error::Error::source(&err);
        assert!(source.is_none());
    }

    // ════════════════════════════════════════════════════════════════
    // From conversions / Result type alias
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn from_serde_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("nope").unwrap_err();
        let err: LinearError = json_err.into();
        assert!(matches!(err, LinearError::Json(_)));
    }

    #[test]
    fn linear_result_ok() {
        let r: LinearResult<u32> = Ok(42);
        assert!(matches!(r, Ok(42)));
    }

    #[test]
    fn linear_result_err() {
        let r: LinearResult<u32> = Err(LinearError::Unauthorized);
        assert!(matches!(r, Err(LinearError::Unauthorized)));
    }

    #[test]
    fn linear_result_map() {
        let r: LinearResult<u32> = Ok(10);
        let mapped = r.map(|v| v * 2);
        assert_eq!(mapped.unwrap(), 20);
    }

    // ════════════════════════════════════════════════════════════════
    // Edge cases / boundary conditions
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn api_error_all_5xx_retryable() {
        for code in 500..=599 {
            let err = LinearError::Api {
                message: format!("status {code}"),
                status_code: Some(code),
            };
            assert!(
                err.is_retryable(),
                "expected Api(status={code}) to be retryable"
            );
        }
    }

    #[test]
    fn api_error_4xx_not_retryable_except_429() {
        for code in [400, 401, 403, 404, 405, 408, 409, 410, 413, 415, 422] {
            let err = LinearError::Api {
                message: format!("status {code}"),
                status_code: Some(code),
            };
            assert!(
                !err.is_retryable(),
                "expected Api(status={code}) to NOT be retryable"
            );
        }
        // 429 IS retryable
        let err429 = LinearError::Api {
            message: "throttled".into(),
            status_code: Some(429),
        };
        assert!(err429.is_retryable());
    }

    #[test]
    fn to_fcp_error_api_503_retryable_external() {
        let err = LinearError::Api {
            message: "service unavailable".into(),
            status_code: Some(503),
        };
        match err.to_fcp_error() {
            FcpError::External {
                retryable,
                status_code,
                ..
            } => {
                assert!(retryable);
                assert_eq!(status_code, Some(503));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_preserves_message_content() {
        let msg = "Complex error: field 'x' is invalid (expected String, got Number)";
        let err = LinearError::Api {
            message: msg.into(),
            status_code: Some(400),
        };
        match err.to_fcp_error() {
            FcpError::External { message, .. } => {
                assert_eq!(message, msg);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_large_value_roundtrips() {
        let err = LinearError::RateLimited {
            retry_after_ms: u64::MAX,
        };
        match err.to_fcp_error() {
            FcpError::RateLimited { retry_after_ms, .. } => {
                assert_eq!(retry_after_ms, u64::MAX);
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }
}
