//! Notion-specific error types.

use std::time::Duration;

use fcp_core::FcpError;

/// Notion API error.
#[derive(Debug, thiserror::Error)]
pub enum NotionError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Notion API error: {message}")]
    Api {
        message: String,
        status_code: Option<u16>,
    },

    #[error("Rate limited")]
    RateLimited { retry_after_ms: u64 },

    #[error("Unauthorized")]
    Unauthorized,

    #[error("Not found: {resource}")]
    NotFound { resource: String },

    #[error("Validation error: {message}")]
    Validation { message: String },
}

pub type NotionResult<T> = Result<T, NotionError>;

impl NotionError {
    /// Check if this error is retryable.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::RateLimited { .. } => true,
            Self::Api { status_code, .. } => matches!(status_code, Some(500..=599 | 429)),
            Self::Json(_)
            | Self::Unauthorized
            | Self::NotFound { .. }
            | Self::Validation { .. } => false,
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
                service: "notion".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
            Self::Api {
                message,
                status_code,
            } => {
                if *status_code == Some(401) || *status_code == Some(403) {
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
                        service: "notion".into(),
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
                message: "Notion API authentication failed".into(),
            },
            Self::NotFound { resource } => FcpError::ResourceNotFound {
                resource: resource.clone(),
            },
            Self::Validation { message } => FcpError::InvalidRequest {
                code: 1003,
                message: message.clone(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_core::FcpError;

    // ── Display messages ─────────────────────────────────────────────

    #[test]
    fn display_http_error() {
        // We cannot easily construct a reqwest::Error, so test the other
        // variants that have deterministic Display output.
        let err = NotionError::Api {
            message: "something broke".into(),
            status_code: Some(500),
        };
        assert_eq!(err.to_string(), "Notion API error: something broke");
    }

    #[test]
    fn display_json_error() {
        let json_err: serde_json::Error =
            serde_json::from_str::<serde_json::Value>("{{bad}}").unwrap_err();
        let inner_msg = json_err.to_string();
        let err = NotionError::Json(json_err);
        assert_eq!(err.to_string(), format!("JSON error: {inner_msg}"));
    }

    #[test]
    fn display_api_error() {
        let err = NotionError::Api {
            message: "page not accessible".into(),
            status_code: Some(403),
        };
        assert_eq!(err.to_string(), "Notion API error: page not accessible");
    }

    #[test]
    fn display_rate_limited() {
        let err = NotionError::RateLimited {
            retry_after_ms: 1000,
        };
        assert_eq!(err.to_string(), "Rate limited");
    }

    #[test]
    fn display_unauthorized() {
        let err = NotionError::Unauthorized;
        assert_eq!(err.to_string(), "Unauthorized");
    }

    #[test]
    fn display_not_found() {
        let err = NotionError::NotFound {
            resource: "page:abc".into(),
        };
        assert_eq!(err.to_string(), "Not found: page:abc");
    }

    #[test]
    fn display_validation() {
        let err = NotionError::Validation {
            message: "title required".into(),
        };
        assert_eq!(err.to_string(), "Validation error: title required");
    }

    // ── is_retryable ─────────────────────────────────────────────────

    #[test]
    fn retryable_rate_limited() {
        assert!(NotionError::RateLimited { retry_after_ms: 1 }.is_retryable());
    }

    #[test]
    fn retryable_api_500() {
        assert!(
            NotionError::Api {
                message: String::new(),
                status_code: Some(500),
            }
            .is_retryable()
        );
    }

    #[test]
    fn retryable_api_502() {
        assert!(
            NotionError::Api {
                message: String::new(),
                status_code: Some(502),
            }
            .is_retryable()
        );
    }

    #[test]
    fn retryable_api_503() {
        assert!(
            NotionError::Api {
                message: String::new(),
                status_code: Some(503),
            }
            .is_retryable()
        );
    }

    #[test]
    fn retryable_api_599() {
        assert!(
            NotionError::Api {
                message: String::new(),
                status_code: Some(599),
            }
            .is_retryable()
        );
    }

    #[test]
    fn retryable_api_429() {
        assert!(
            NotionError::Api {
                message: String::new(),
                status_code: Some(429),
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_unauthorized() {
        assert!(!NotionError::Unauthorized.is_retryable());
    }

    #[test]
    fn not_retryable_not_found() {
        assert!(
            !NotionError::NotFound {
                resource: "x".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_validation() {
        assert!(
            !NotionError::Validation {
                message: "x".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_api_401() {
        assert!(
            !NotionError::Api {
                message: String::new(),
                status_code: Some(401),
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_api_404() {
        assert!(
            !NotionError::Api {
                message: String::new(),
                status_code: Some(404),
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_api_400() {
        assert!(
            !NotionError::Api {
                message: String::new(),
                status_code: Some(400),
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_api_no_status() {
        // Api with None status_code is not retryable (doesn't match 500..=599 | 429)
        assert!(
            !NotionError::Api {
                message: String::new(),
                status_code: None,
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("invalid").unwrap_err();
        assert!(!NotionError::Json(json_err).is_retryable());
    }

    // ── retry_after ──────────────────────────────────────────────────

    #[test]
    fn retry_after_rate_limited() {
        assert_eq!(
            NotionError::RateLimited {
                retry_after_ms: 3000
            }
            .retry_after()
            .map(|d| d.as_millis()),
            Some(3000)
        );
    }

    #[test]
    fn retry_after_rate_limited_zero() {
        let d = NotionError::RateLimited { retry_after_ms: 0 }
            .retry_after()
            .unwrap();
        assert_eq!(d.as_millis(), 0);
    }

    #[test]
    fn retry_after_none_for_unauthorized() {
        assert!(NotionError::Unauthorized.retry_after().is_none());
    }

    #[test]
    fn retry_after_none_for_api_429() {
        // The Api variant with 429 status does NOT carry a retry_after
        // (only the RateLimited variant does).
        assert!(
            NotionError::Api {
                message: String::new(),
                status_code: Some(429),
            }
            .retry_after()
            .is_none()
        );
    }

    #[test]
    fn retry_after_none_for_not_found() {
        assert!(
            NotionError::NotFound {
                resource: "r".into()
            }
            .retry_after()
            .is_none()
        );
    }

    #[test]
    fn retry_after_none_for_validation() {
        assert!(
            NotionError::Validation {
                message: "v".into()
            }
            .retry_after()
            .is_none()
        );
    }

    #[test]
    fn retry_after_none_for_json() {
        let json_err = serde_json::from_str::<serde_json::Value>("bad").unwrap_err();
        assert!(NotionError::Json(json_err).retry_after().is_none());
    }

    // ── to_fcp_error ─────────────────────────────────────────────────

    #[test]
    fn fcp_api_401_maps_to_unauthorized() {
        let err = NotionError::Api {
            message: "bad token".into(),
            status_code: Some(401),
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::Unauthorized { code: 2001, .. }));
        if let FcpError::Unauthorized { message, .. } = &fcp {
            assert_eq!(message, "bad token");
        }
    }

    #[test]
    fn fcp_api_403_maps_to_unauthorized() {
        let err = NotionError::Api {
            message: "forbidden".into(),
            status_code: Some(403),
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::Unauthorized { code: 2001, .. }));
        if let FcpError::Unauthorized { message, .. } = &fcp {
            assert_eq!(message, "forbidden");
        }
    }

    #[test]
    fn fcp_api_429_maps_to_rate_limited() {
        let err = NotionError::Api {
            message: "rate limited".into(),
            status_code: Some(429),
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(
            fcp,
            FcpError::RateLimited {
                retry_after_ms: 60_000,
                violation: None,
            }
        ));
    }

    #[test]
    fn fcp_api_500_maps_to_retryable_external() {
        let err = NotionError::Api {
            message: "server error".into(),
            status_code: Some(500),
        };
        let fcp = err.to_fcp_error();
        match &fcp {
            FcpError::External {
                service,
                message,
                status_code,
                retryable,
                retry_after,
            } => {
                assert_eq!(service, "notion");
                assert_eq!(message, "server error");
                assert_eq!(*status_code, Some(500));
                assert!(*retryable);
                assert!(retry_after.is_none());
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn fcp_api_502_maps_to_retryable_external() {
        let err = NotionError::Api {
            message: "bad gateway".into(),
            status_code: Some(502),
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
    fn fcp_api_404_maps_to_non_retryable_external() {
        let err = NotionError::Api {
            message: "not found".into(),
            status_code: Some(404),
        };
        let fcp = err.to_fcp_error();
        match &fcp {
            FcpError::External {
                retryable,
                status_code,
                ..
            } => {
                assert!(!retryable);
                assert_eq!(*status_code, Some(404));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn fcp_api_no_status_maps_to_external() {
        let err = NotionError::Api {
            message: "unknown".into(),
            status_code: None,
        };
        let fcp = err.to_fcp_error();
        match &fcp {
            FcpError::External {
                service,
                message,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "notion");
                assert_eq!(message, "unknown");
                assert_eq!(*status_code, None);
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn fcp_rate_limited_variant_maps_correctly() {
        let err = NotionError::RateLimited {
            retry_after_ms: 5000,
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(
            fcp,
            FcpError::RateLimited {
                retry_after_ms: 5000,
                violation: None
            }
        ));
    }

    #[test]
    fn fcp_rate_limited_preserves_arbitrary_ms() {
        let err = NotionError::RateLimited {
            retry_after_ms: 123_456,
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(
            fcp,
            FcpError::RateLimited {
                retry_after_ms: 123_456,
                violation: None,
            }
        ));
    }

    #[test]
    fn fcp_unauthorized_variant() {
        let err = NotionError::Unauthorized;
        let fcp = err.to_fcp_error();
        match &fcp {
            FcpError::Unauthorized { code, message } => {
                assert_eq!(*code, 2001);
                assert_eq!(message, "Notion API authentication failed");
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn fcp_not_found_maps_to_resource_not_found() {
        let err = NotionError::NotFound {
            resource: "page:abc123".into(),
        };
        let fcp = err.to_fcp_error();
        match &fcp {
            FcpError::ResourceNotFound { resource } => {
                assert_eq!(resource, "page:abc123");
            }
            other => panic!("expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn fcp_not_found_empty_resource() {
        let err = NotionError::NotFound {
            resource: String::new(),
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(
            fcp,
            FcpError::ResourceNotFound { resource } if resource.is_empty()
        ));
    }

    #[test]
    fn fcp_validation_maps_to_invalid_request() {
        let err = NotionError::Validation {
            message: "bad input".into(),
        };
        let fcp = err.to_fcp_error();
        match &fcp {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(*code, 1003);
                assert_eq!(message, "bad input");
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn fcp_json_error_maps_to_internal() {
        let json_err: serde_json::Error =
            serde_json::from_str::<serde_json::Value>("invalid").unwrap_err();
        let err = NotionError::Json(json_err);
        let fcp = err.to_fcp_error();
        match &fcp {
            FcpError::Internal { message } => {
                assert!(message.starts_with("JSON error: "));
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    // ── Debug format ─────────────────────────────────────────────────

    #[test]
    fn debug_format_api_error() {
        let err = NotionError::Api {
            message: "oops".into(),
            status_code: Some(500),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Api"));
        assert!(dbg.contains("oops"));
        assert!(dbg.contains("500"));
    }

    #[test]
    fn debug_format_rate_limited() {
        let err = NotionError::RateLimited {
            retry_after_ms: 2000,
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("RateLimited"));
        assert!(dbg.contains("2000"));
    }

    #[test]
    fn debug_format_unauthorized() {
        let err = NotionError::Unauthorized;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Unauthorized"));
    }

    #[test]
    fn debug_format_not_found() {
        let err = NotionError::NotFound {
            resource: "db:xyz".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("NotFound"));
        assert!(dbg.contains("db:xyz"));
    }

    #[test]
    fn debug_format_validation() {
        let err = NotionError::Validation {
            message: "missing parent".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Validation"));
        assert!(dbg.contains("missing parent"));
    }

    #[test]
    fn debug_format_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("bad").unwrap_err();
        let err = NotionError::Json(json_err);
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Json"));
    }

    // ── std::error::Error trait ──────────────────────────────────────

    #[test]
    fn error_trait_source_for_json() {
        let json_err = serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err();
        let err = NotionError::Json(json_err);
        // The #[from] attribute sets up the source chain
        let source = std::error::Error::source(&err);
        assert!(source.is_some(), "Json variant should have a source");
    }

    #[test]
    fn error_trait_source_none_for_api() {
        let err = NotionError::Api {
            message: "test".into(),
            status_code: Some(400),
        };
        let source = std::error::Error::source(&err);
        assert!(source.is_none(), "Api variant should not have a source");
    }

    #[test]
    fn error_trait_source_none_for_unauthorized() {
        let err = NotionError::Unauthorized;
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn error_trait_source_none_for_rate_limited() {
        let err = NotionError::RateLimited {
            retry_after_ms: 100,
        };
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn error_trait_source_none_for_not_found() {
        let err = NotionError::NotFound {
            resource: "r".into(),
        };
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn error_trait_source_none_for_validation() {
        let err = NotionError::Validation {
            message: "m".into(),
        };
        assert!(std::error::Error::source(&err).is_none());
    }

    // ── NotionResult type alias ──────────────────────────────────────

    #[test]
    fn notion_result_ok() {
        let r: NotionResult<u32> = Ok(42);
        assert!(matches!(r, Ok(42)));
    }

    #[test]
    fn notion_result_err() {
        let r: NotionResult<u32> = Err(NotionError::Unauthorized);
        assert!(r.is_err());
    }

    // ── From conversions ─────────────────────────────────────────────

    #[test]
    fn from_serde_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("nope").unwrap_err();
        let err: NotionError = json_err.into();
        assert!(matches!(err, NotionError::Json(_)));
    }

    // ── Comprehensive is_retryable sweep ─────────────────────────────

    #[test]
    fn retryable_exhaustive() {
        // All retryable cases
        let retryable_cases: Vec<NotionError> = vec![
            NotionError::RateLimited {
                retry_after_ms: 100,
            },
            NotionError::Api {
                message: String::new(),
                status_code: Some(500),
            },
            NotionError::Api {
                message: String::new(),
                status_code: Some(501),
            },
            NotionError::Api {
                message: String::new(),
                status_code: Some(502),
            },
            NotionError::Api {
                message: String::new(),
                status_code: Some(503),
            },
            NotionError::Api {
                message: String::new(),
                status_code: Some(504),
            },
            NotionError::Api {
                message: String::new(),
                status_code: Some(429),
            },
        ];
        for err in &retryable_cases {
            assert!(err.is_retryable(), "{err:?} should be retryable");
        }

        // All non-retryable cases
        let non_retryable_cases: Vec<NotionError> = vec![
            NotionError::Unauthorized,
            NotionError::NotFound {
                resource: "x".into(),
            },
            NotionError::Validation {
                message: "x".into(),
            },
            NotionError::Api {
                message: String::new(),
                status_code: Some(400),
            },
            NotionError::Api {
                message: String::new(),
                status_code: Some(401),
            },
            NotionError::Api {
                message: String::new(),
                status_code: Some(403),
            },
            NotionError::Api {
                message: String::new(),
                status_code: Some(404),
            },
            NotionError::Api {
                message: String::new(),
                status_code: Some(422),
            },
            NotionError::Api {
                message: String::new(),
                status_code: None,
            },
        ];
        for err in &non_retryable_cases {
            assert!(!err.is_retryable(), "{err:?} should NOT be retryable");
        }
    }

    // ── Edge cases ───────────────────────────────────────────────────

    #[test]
    fn api_error_with_empty_message() {
        let err = NotionError::Api {
            message: String::new(),
            status_code: Some(500),
        };
        assert_eq!(err.to_string(), "Notion API error: ");
        let fcp = err.to_fcp_error();
        if let FcpError::External { message, .. } = &fcp {
            assert!(message.is_empty());
        } else {
            panic!("expected External");
        }
    }

    #[test]
    fn validation_error_with_unicode() {
        let err = NotionError::Validation {
            message: "champ invalide: données 日本語".into(),
        };
        assert!(err.to_string().contains("日本語"));
        let fcp = err.to_fcp_error();
        if let FcpError::InvalidRequest { message, .. } = &fcp {
            assert!(message.contains("日本語"));
        } else {
            panic!("expected InvalidRequest");
        }
    }

    #[test]
    fn not_found_with_long_resource() {
        let resource = "x".repeat(10_000);
        let err = NotionError::NotFound { resource };
        let fcp = err.to_fcp_error();
        if let FcpError::ResourceNotFound { resource: r } = &fcp {
            assert_eq!(r.len(), 10_000);
        } else {
            panic!("expected ResourceNotFound");
        }
    }

    #[test]
    fn rate_limited_large_retry_after() {
        let err = NotionError::RateLimited {
            retry_after_ms: u64::MAX,
        };
        let d = err.retry_after().unwrap();
        assert_eq!(d.as_millis(), u128::from(u64::MAX));
    }
}
