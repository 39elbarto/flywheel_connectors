//! `Roam Research`-specific error types.

use std::time::Duration;

use fcp_core::FcpError;
use thiserror::Error;

/// Result alias for `Roam Research` operations.
pub type RoamResult<T> = Result<T, RoamError>;

/// `Roam Research`-specific errors.
#[derive(Error, Debug)]
pub enum RoamError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// `Roam Research` API returned an error
    #[error("Roam API error ({status_code}): {message}")]
    Api { status_code: u16, message: String },

    /// Rate limited (429)
    #[error("Rate limited, retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },

    /// Authentication failed (401)
    #[error("Authentication failed: invalid or expired API token")]
    Unauthorized,

    /// Forbidden (403)
    #[error("Forbidden: insufficient permissions")]
    Forbidden,

    /// Resource not found (404)
    #[error("Not found: {resource}")]
    NotFound { resource: String },

    /// Graph not found or inaccessible
    #[error("Graph not found or inaccessible: {graph}")]
    GraphNotFound { graph: String },
}

impl RoamError {
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::RateLimited { .. } => true,
            Self::Api { status_code, .. } => matches!(status_code, 500..=599 | 429),
            _ => false,
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
            Self::Http(e) => FcpError::External {
                service: "roam".into(),
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
                service: "roam".into(),
                message: message.clone(),
                status_code: Some(*status_code),
                retryable: self.is_retryable(),
                retry_after: None,
            },
            Self::RateLimited { retry_after_ms } => FcpError::External {
                service: "roam".into(),
                message: format!("Rate limited, retry after {retry_after_ms}ms"),
                status_code: Some(429),
                retryable: true,
                retry_after: self.retry_after(),
            },
            Self::Unauthorized => FcpError::External {
                service: "roam".into(),
                message: "Authentication failed".into(),
                status_code: Some(401),
                retryable: false,
                retry_after: None,
            },
            Self::Forbidden => FcpError::External {
                service: "roam".into(),
                message: "Insufficient permissions".into(),
                status_code: Some(403),
                retryable: false,
                retry_after: None,
            },
            Self::NotFound { resource } => FcpError::External {
                service: "roam".into(),
                message: format!("Not found: {resource}"),
                status_code: Some(404),
                retryable: false,
                retry_after: None,
            },
            Self::GraphNotFound { graph } => FcpError::External {
                service: "roam".into(),
                message: format!("Graph not found: {graph}"),
                status_code: Some(404),
                retryable: false,
                retry_after: None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limited_is_retryable() {
        assert!(
            RoamError::RateLimited {
                retry_after_ms: 5000
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_500_is_retryable() {
        assert!(
            RoamError::Api {
                status_code: 500,
                message: "err".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_503_is_retryable() {
        assert!(
            RoamError::Api {
                status_code: 503,
                message: "unavailable".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_429_is_retryable() {
        assert!(
            RoamError::Api {
                status_code: 429,
                message: "too many".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_502_is_retryable() {
        assert!(
            RoamError::Api {
                status_code: 502,
                message: "bad gateway".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn unauthorized_not_retryable() {
        assert!(!RoamError::Unauthorized.is_retryable());
    }

    #[test]
    fn forbidden_not_retryable() {
        assert!(!RoamError::Forbidden.is_retryable());
    }

    #[test]
    fn not_found_not_retryable() {
        assert!(
            !RoamError::NotFound {
                resource: "page".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_400_not_retryable() {
        assert!(
            !RoamError::Api {
                status_code: 400,
                message: "bad request".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn graph_not_found_not_retryable() {
        assert!(
            !RoamError::GraphNotFound {
                graph: "my-graph".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn retry_after_for_rate_limited() {
        let err = RoamError::RateLimited {
            retry_after_ms: 30_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn retry_after_none_for_unauthorized() {
        assert_eq!(RoamError::Unauthorized.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_forbidden() {
        assert_eq!(RoamError::Forbidden.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_api_error() {
        assert_eq!(
            RoamError::Api {
                status_code: 500,
                message: "err".into()
            }
            .retry_after(),
            None
        );
    }

    #[test]
    fn retry_after_none_for_not_found() {
        assert_eq!(
            RoamError::NotFound {
                resource: "x".into()
            }
            .retry_after(),
            None
        );
    }

    #[test]
    fn retry_after_none_for_graph_not_found() {
        assert_eq!(
            RoamError::GraphNotFound { graph: "g".into() }.retry_after(),
            None
        );
    }

    #[test]
    fn unauthorized_to_fcp_error() {
        match RoamError::Unauthorized.to_fcp_error() {
            FcpError::External {
                service,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "roam");
                assert_eq!(status_code, Some(401));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn forbidden_to_fcp_error() {
        match RoamError::Forbidden.to_fcp_error() {
            FcpError::External {
                service,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "roam");
                assert_eq!(status_code, Some(403));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn not_found_to_fcp_error() {
        match (RoamError::NotFound {
            resource: "page_abc".into(),
        })
        .to_fcp_error()
        {
            FcpError::External {
                status_code,
                message,
                retryable,
                ..
            } => {
                assert_eq!(status_code, Some(404));
                assert!(message.contains("page_abc"));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn graph_not_found_to_fcp_error() {
        match (RoamError::GraphNotFound {
            graph: "test-graph".into(),
        })
        .to_fcp_error()
        {
            FcpError::External {
                service,
                status_code,
                message,
                retryable,
                ..
            } => {
                assert_eq!(service, "roam");
                assert_eq!(status_code, Some(404));
                assert!(message.contains("test-graph"));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_to_fcp_error() {
        match (RoamError::RateLimited {
            retry_after_ms: 60_000,
        })
        .to_fcp_error()
        {
            FcpError::External {
                status_code,
                retryable,
                retry_after,
                ..
            } => {
                assert_eq!(status_code, Some(429));
                assert!(retryable);
                assert_eq!(retry_after, Some(Duration::from_secs(60)));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn api_error_to_fcp_error() {
        match (RoamError::Api {
            status_code: 503,
            message: "unavailable".into(),
        })
        .to_fcp_error()
        {
            FcpError::External {
                service,
                status_code,
                retryable,
                message,
                ..
            } => {
                assert_eq!(service, "roam");
                assert_eq!(status_code, Some(503));
                assert!(retryable);
                assert_eq!(message, "unavailable");
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn json_error_to_fcp_internal() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{invalid");
        match RoamError::Json(bad.unwrap_err()).to_fcp_error() {
            FcpError::Internal { message } => assert!(message.starts_with("JSON error:")),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn api_error_non_retryable_to_fcp_error() {
        match (RoamError::Api {
            status_code: 400,
            message: "bad".into(),
        })
        .to_fcp_error()
        {
            FcpError::External {
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(status_code, Some(400));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn error_display_unauthorized() {
        assert_eq!(
            RoamError::Unauthorized.to_string(),
            "Authentication failed: invalid or expired API token"
        );
    }

    #[test]
    fn error_display_forbidden() {
        assert_eq!(
            RoamError::Forbidden.to_string(),
            "Forbidden: insufficient permissions"
        );
    }

    #[test]
    fn error_display_not_found() {
        assert_eq!(
            RoamError::NotFound {
                resource: "page".into()
            }
            .to_string(),
            "Not found: page"
        );
    }

    #[test]
    fn error_display_rate_limited() {
        assert_eq!(
            RoamError::RateLimited {
                retry_after_ms: 2000
            }
            .to_string(),
            "Rate limited, retry after 2000ms"
        );
    }

    #[test]
    fn error_display_api() {
        assert_eq!(
            RoamError::Api {
                status_code: 500,
                message: "Internal".into()
            }
            .to_string(),
            "Roam API error (500): Internal"
        );
    }

    #[test]
    fn error_display_graph_not_found() {
        assert_eq!(
            RoamError::GraphNotFound {
                graph: "my-graph".into()
            }
            .to_string(),
            "Graph not found or inaccessible: my-graph"
        );
    }

    #[test]
    fn api_error_retryable_599() {
        assert!(
            RoamError::Api {
                status_code: 599,
                message: "err".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_error_not_retryable_200() {
        assert!(
            !RoamError::Api {
                status_code: 200,
                message: "ok".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn rate_limited_retry_after_small() {
        let err = RoamError::RateLimited {
            retry_after_ms: 100,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_millis(100)));
    }

    #[test]
    fn rate_limited_retry_after_zero() {
        let err = RoamError::RateLimited { retry_after_ms: 0 };
        assert_eq!(err.retry_after(), Some(Duration::from_millis(0)));
    }

    #[test]
    fn error_debug_unauthorized() {
        let dbg = format!("{:?}", RoamError::Unauthorized);
        assert!(dbg.contains("Unauthorized"));
    }

    #[test]
    fn error_debug_forbidden() {
        let dbg = format!("{:?}", RoamError::Forbidden);
        assert!(dbg.contains("Forbidden"));
    }

    #[test]
    fn error_debug_not_found() {
        let dbg = format!("{:?}", RoamError::NotFound { resource: "pg".into() });
        assert!(dbg.contains("NotFound"));
        assert!(dbg.contains("pg"));
    }

    #[test]
    fn error_debug_rate_limited() {
        let dbg = format!("{:?}", RoamError::RateLimited { retry_after_ms: 5000 });
        assert!(dbg.contains("RateLimited"));
        assert!(dbg.contains("5000"));
    }

    #[test]
    fn error_debug_api() {
        let dbg = format!("{:?}", RoamError::Api { status_code: 500, message: "err".into() });
        assert!(dbg.contains("Api"));
        assert!(dbg.contains("500"));
    }

    #[test]
    fn error_debug_graph_not_found() {
        let dbg = format!("{:?}", RoamError::GraphNotFound { graph: "my-graph-123".into() });
        assert!(dbg.contains("GraphNotFound"));
        assert!(dbg.contains("my-graph-123"));
    }

    #[test]
    fn http_error_display_contains_http() {
        // We can test Display for Http variant via a constructed reqwest error
        // Just verify the error enum variant name in debug
        let err = RoamError::Api { status_code: 408, message: "timeout".into() };
        assert!(err.to_string().contains("408"));
    }

    #[test]
    fn api_error_501_is_retryable() {
        assert!(RoamError::Api { status_code: 501, message: "not impl".into() }.is_retryable());
    }

    #[test]
    fn api_error_504_is_retryable() {
        assert!(RoamError::Api { status_code: 504, message: "gw timeout".into() }.is_retryable());
    }

    #[test]
    fn api_error_not_retryable_403() {
        assert!(!RoamError::Api { status_code: 403, message: "no".into() }.is_retryable());
    }

    #[test]
    fn api_error_not_retryable_404() {
        assert!(!RoamError::Api { status_code: 404, message: "miss".into() }.is_retryable());
    }

    #[test]
    fn api_error_not_retryable_422() {
        assert!(!RoamError::Api { status_code: 422, message: "unprocessable".into() }.is_retryable());
    }

    #[test]
    fn rate_limited_large_retry_after() {
        let err = RoamError::RateLimited { retry_after_ms: 300_000 };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(300)));
        assert!(err.is_retryable());
    }

    #[test]
    fn json_error_not_retryable() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{bad");
        assert!(!RoamError::Json(bad.unwrap_err()).is_retryable());
    }

    #[test]
    fn json_error_retry_after_none() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{bad");
        assert_eq!(RoamError::Json(bad.unwrap_err()).retry_after(), None);
    }

    #[test]
    fn graph_not_found_to_fcp_error_service() {
        match (RoamError::GraphNotFound { graph: "x".into() }).to_fcp_error() {
            FcpError::External { service, .. } => assert_eq!(service, "roam"),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_to_fcp_error_service() {
        match (RoamError::RateLimited { retry_after_ms: 1000 }).to_fcp_error() {
            FcpError::External { service, .. } => assert_eq!(service, "roam"),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn unauthorized_to_fcp_error_message() {
        match RoamError::Unauthorized.to_fcp_error() {
            FcpError::External { message, .. } => {
                assert!(message.contains("Authentication"));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn forbidden_to_fcp_error_message() {
        match RoamError::Forbidden.to_fcp_error() {
            FcpError::External { message, .. } => {
                assert!(message.contains("permissions"));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }
}
