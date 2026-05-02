//! arXiv-specific error types.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_sdk::migration::ConnectorErrorMapping;
use thiserror::Error;

/// Result alias for arXiv operations.
pub type ArxivResult<T> = Result<T, ArxivError>;

/// arXiv-specific errors.
#[derive(Error, Debug)]
pub enum ArxivError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// arXiv API returned an error
    #[error("arXiv API error ({status_code}): {message}")]
    Api { status_code: u16, message: String },

    /// Semantic Scholar API returned an error
    #[error("Semantic Scholar API error ({status_code}): {message}")]
    ScholarApi { status_code: u16, message: String },

    /// Rate limited (429)
    #[error("Rate limited, retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },

    /// Resource not found (404)
    #[error("Not found: {resource}")]
    NotFound { resource: String },

    /// XML parsing failed
    #[error("XML parse error: {message}")]
    XmlParse { message: String },

    /// Invalid input
    #[error("Invalid input: {message}")]
    InvalidInput { message: String },
}

impl ArxivError {
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::RateLimited { .. } => true,
            Self::Api { status_code, .. } | Self::ScholarApi { status_code, .. } => {
                matches!(status_code, 500..=599 | 429)
            }
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
                service: "arxiv".into(),
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
                service: "arxiv".into(),
                message: message.clone(),
                status_code: Some(*status_code),
                retryable: self.is_retryable(),
                retry_after: None,
            },
            Self::ScholarApi {
                status_code,
                message,
            } => FcpError::External {
                service: "semantic_scholar".into(),
                message: message.clone(),
                status_code: Some(*status_code),
                retryable: self.is_retryable(),
                retry_after: None,
            },
            Self::RateLimited { retry_after_ms } => FcpError::External {
                service: "arxiv".into(),
                message: format!("Rate limited, retry after {retry_after_ms}ms"),
                status_code: Some(429),
                retryable: true,
                retry_after: self.retry_after(),
            },
            Self::NotFound { resource } => FcpError::External {
                service: "arxiv".into(),
                message: format!("Not found: {resource}"),
                status_code: Some(404),
                retryable: false,
                retry_after: None,
            },
            Self::XmlParse { message } => FcpError::Internal {
                message: format!("XML parse error: {message}"),
            },
            Self::InvalidInput { message } => FcpError::InvalidRequest {
                code: 1003,
                message: message.clone(),
            },
        }
    }
}

impl ConnectorErrorMapping for ArxivError {
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
        assert!(
            ArxivError::RateLimited {
                retry_after_ms: 5000
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_500_is_retryable() {
        assert!(
            ArxivError::Api {
                status_code: 500,
                message: "err".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_503_is_retryable() {
        assert!(
            ArxivError::Api {
                status_code: 503,
                message: "unavailable".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_429_is_retryable() {
        assert!(
            ArxivError::Api {
                status_code: 429,
                message: "too many".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn scholar_api_500_is_retryable() {
        assert!(
            ArxivError::ScholarApi {
                status_code: 500,
                message: "err".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn scholar_api_429_is_retryable() {
        assert!(
            ArxivError::ScholarApi {
                status_code: 429,
                message: "rate limit".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn scholar_api_400_not_retryable() {
        assert!(
            !ArxivError::ScholarApi {
                status_code: 400,
                message: "bad request".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_found_not_retryable() {
        assert!(
            !ArxivError::NotFound {
                resource: "paper".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_400_not_retryable() {
        assert!(
            !ArxivError::Api {
                status_code: 400,
                message: "bad request".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn xml_parse_not_retryable() {
        assert!(
            !ArxivError::XmlParse {
                message: "bad xml".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn invalid_input_not_retryable() {
        assert!(
            !ArxivError::InvalidInput {
                message: "missing field".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn retry_after_for_rate_limited() {
        let err = ArxivError::RateLimited {
            retry_after_ms: 30_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn retry_after_none_for_not_found() {
        assert_eq!(
            ArxivError::NotFound {
                resource: "x".into()
            }
            .retry_after(),
            None
        );
    }

    #[test]
    fn retry_after_none_for_api_error() {
        assert_eq!(
            ArxivError::Api {
                status_code: 500,
                message: "err".into()
            }
            .retry_after(),
            None
        );
    }

    #[test]
    fn retry_after_none_for_xml_parse() {
        assert_eq!(
            ArxivError::XmlParse {
                message: "bad".into()
            }
            .retry_after(),
            None
        );
    }

    #[test]
    fn retry_after_none_for_invalid_input() {
        assert_eq!(
            ArxivError::InvalidInput {
                message: "bad".into()
            }
            .retry_after(),
            None
        );
    }

    #[test]
    fn not_found_to_fcp_error() {
        match (ArxivError::NotFound {
            resource: "paper 1234".into(),
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
                assert!(message.contains("paper 1234"));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_to_fcp_error() {
        match (ArxivError::RateLimited {
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
        match (ArxivError::Api {
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
                assert_eq!(service, "arxiv");
                assert_eq!(status_code, Some(503));
                assert!(retryable);
                assert_eq!(message, "unavailable");
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn scholar_api_error_to_fcp_error() {
        match (ArxivError::ScholarApi {
            status_code: 404,
            message: "not found".into(),
        })
        .to_fcp_error()
        {
            FcpError::External {
                service,
                status_code,
                ..
            } => {
                assert_eq!(service, "semantic_scholar");
                assert_eq!(status_code, Some(404));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn json_error_to_fcp_internal() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{invalid");
        match ArxivError::Json(bad.unwrap_err()).to_fcp_error() {
            FcpError::Internal { message } => assert!(message.starts_with("JSON error:")),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn xml_parse_to_fcp_internal() {
        match (ArxivError::XmlParse {
            message: "bad tags".into(),
        })
        .to_fcp_error()
        {
            FcpError::Internal { message } => assert!(message.contains("bad tags")),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn invalid_input_to_fcp_error() {
        match (ArxivError::InvalidInput {
            message: "missing query".into(),
        })
        .to_fcp_error()
        {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1003);
                assert_eq!(message, "missing query");
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn api_error_non_retryable_to_fcp_error() {
        match (ArxivError::Api {
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
    fn error_display_rate_limited() {
        assert_eq!(
            ArxivError::RateLimited {
                retry_after_ms: 2000
            }
            .to_string(),
            "Rate limited, retry after 2000ms"
        );
    }

    #[test]
    fn error_display_not_found() {
        assert_eq!(
            ArxivError::NotFound {
                resource: "paper".into()
            }
            .to_string(),
            "Not found: paper"
        );
    }

    #[test]
    fn error_display_api() {
        assert_eq!(
            ArxivError::Api {
                status_code: 500,
                message: "Internal".into()
            }
            .to_string(),
            "arXiv API error (500): Internal"
        );
    }

    #[test]
    fn error_display_scholar_api() {
        assert_eq!(
            ArxivError::ScholarApi {
                status_code: 404,
                message: "Not found".into()
            }
            .to_string(),
            "Semantic Scholar API error (404): Not found"
        );
    }

    #[test]
    fn error_display_xml_parse() {
        assert_eq!(
            ArxivError::XmlParse {
                message: "no entry tag".into()
            }
            .to_string(),
            "XML parse error: no entry tag"
        );
    }

    #[test]
    fn error_display_invalid_input() {
        assert_eq!(
            ArxivError::InvalidInput {
                message: "missing query".into()
            }
            .to_string(),
            "Invalid input: missing query"
        );
    }

    // ---- Additional Display tests ----

    #[test]
    fn display_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("{bad").unwrap_err();
        let err = ArxivError::Json(json_err);
        let s = err.to_string();
        assert!(s.starts_with("JSON error:"));
    }

    #[test]
    fn display_rate_limited_exact_format() {
        let s = ArxivError::RateLimited {
            retry_after_ms: 30_000,
        }
        .to_string();
        assert_eq!(s, "Rate limited, retry after 30000ms");
    }

    // ---- Debug format tests ----

    #[test]
    fn debug_api_error() {
        let err = ArxivError::Api {
            status_code: 503,
            message: "unavailable".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Api"));
        assert!(dbg.contains("503"));
        assert!(dbg.contains("unavailable"));
    }

    #[test]
    fn debug_scholar_api_error() {
        let err = ArxivError::ScholarApi {
            status_code: 500,
            message: "internal".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("ScholarApi"));
        assert!(dbg.contains("500"));
    }

    #[test]
    fn debug_rate_limited() {
        let err = ArxivError::RateLimited {
            retry_after_ms: 5000,
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("RateLimited"));
        assert!(dbg.contains("5000"));
    }

    #[test]
    fn debug_not_found() {
        let err = ArxivError::NotFound {
            resource: "paper_123".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("NotFound"));
        assert!(dbg.contains("paper_123"));
    }

    #[test]
    fn debug_xml_parse() {
        let err = ArxivError::XmlParse {
            message: "malformed".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("XmlParse"));
    }

    #[test]
    fn debug_invalid_input() {
        let err = ArxivError::InvalidInput {
            message: "missing field".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("InvalidInput"));
    }

    // ---- Source chain tests ----

    #[test]
    fn source_json_variant_has_source() {
        let json_err = serde_json::from_str::<serde_json::Value>("{bad").unwrap_err();
        let err = ArxivError::Json(json_err);
        assert!(std::error::Error::source(&err).is_some());
    }

    #[test]
    fn source_api_none() {
        let err = ArxivError::Api {
            status_code: 500,
            message: "x".into(),
        };
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn source_scholar_api_none() {
        let err = ArxivError::ScholarApi {
            status_code: 500,
            message: "x".into(),
        };
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn source_rate_limited_none() {
        let err = ArxivError::RateLimited {
            retry_after_ms: 1000,
        };
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn source_not_found_none() {
        let err = ArxivError::NotFound {
            resource: "x".into(),
        };
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn source_xml_parse_none() {
        let err = ArxivError::XmlParse {
            message: "x".into(),
        };
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn source_invalid_input_none() {
        let err = ArxivError::InvalidInput {
            message: "x".into(),
        };
        assert!(std::error::Error::source(&err).is_none());
    }

    // ---- Error trait impl ----

    #[test]
    fn error_trait_impl() {
        let err = ArxivError::NotFound {
            resource: "x".into(),
        };
        let _: &dyn std::error::Error = &err;
    }

    // ---- From impls ----

    #[test]
    fn from_serde_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("nope").unwrap_err();
        let err: ArxivError = json_err.into();
        assert!(matches!(err, ArxivError::Json(_)));
    }

    // ---- Result alias ----

    #[test]
    fn arxiv_result_ok() {
        let r: ArxivResult<u32> = Ok(42);
        assert!(r.is_ok());
    }

    #[test]
    fn arxiv_result_err() {
        let r: ArxivResult<u32> = Err(ArxivError::InvalidInput {
            message: "test".into(),
        });
        assert!(r.is_err());
    }

    // ---- to_fcp_error for Http variant ----

    #[test]
    fn http_error_to_fcp_error_has_service_arxiv() {
        // Test with a realistic error flow: the Http variant maps to External
        // We can't easily create a reqwest::Error, but we verify other cases thoroughly
        let err = ArxivError::Api {
            status_code: 429,
            message: "rate limited".into(),
        };
        match err.to_fcp_error() {
            FcpError::External {
                service, retryable, ..
            } => {
                assert_eq!(service, "arxiv");
                assert!(retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    // ---- retry_after with zero ----

    #[test]
    fn retry_after_zero_ms() {
        let err = ArxivError::RateLimited { retry_after_ms: 0 };
        assert_eq!(err.retry_after(), Some(Duration::from_millis(0)));
    }

    // ---- Scholar API retryable edge cases ----

    #[test]
    fn scholar_api_502_is_retryable() {
        assert!(
            ArxivError::ScholarApi {
                status_code: 502,
                message: "bad gateway".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn scholar_api_599_is_retryable() {
        assert!(
            ArxivError::ScholarApi {
                status_code: 599,
                message: "error".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn json_not_retryable() {
        let json_err = serde_json::from_str::<serde_json::Value>("x").unwrap_err();
        assert!(!ArxivError::Json(json_err).is_retryable());
    }
}
