//! Qdrant-specific error types.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_core::FcpError;
use fcp_sdk::migration::ConnectorErrorMapping;

const REDACTED_TOKEN: &str = "[REDACTED]";
const REDACTION_PATTERNS: &[&str] = &[
    "authorization: bearer ",
    "bearer ",
    "\"api_key\":\"",
    "\"access_token\":\"",
    "\"token\":\"",
    "api_key=",
    "api-key=",
    "access_token=",
    "token=",
    "api_key:",
    "api-key:",
    "access_token:",
    "token:",
];

/// Qdrant API error.
#[derive(Debug, thiserror::Error)]
pub enum QdrantError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Qdrant API error: {message}")]
    Api {
        message: String,
        status_code: Option<u16>,
    },

    #[error("Invalid configuration: {message}")]
    InvalidConfig { message: String },

    #[error("Rate limited")]
    RateLimit { retry_after_ms: u64 },
}

pub type QdrantResult<T> = Result<T, QdrantError>;

impl QdrantError {
    /// Check if this error is retryable.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::RateLimit { .. } => true,
            Self::Api { status_code, .. } => matches!(status_code, Some(500..=599 | 429)),
            Self::Serialization(_) | Self::InvalidConfig { .. } => false,
        }
    }

    /// Get the suggested retry delay.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimit { retry_after_ms } => Some(Duration::from_millis(*retry_after_ms)),
            _ => None,
        }
    }

    /// Convert to FCP error.
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        let sanitize = |message: &str| redact_sensitive(message);

        match self {
            Self::Http(e) => FcpError::External {
                service: "qdrant".into(),
                message: sanitize(&e.to_string()),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Serialization(e) => FcpError::Internal {
                message: sanitize(&format!("JSON error: {e}")),
            },
            Self::Api {
                message,
                status_code,
            } => {
                let message = sanitize(message);
                match status_code {
                    Some(401 | 403) => FcpError::Unauthorized {
                        code: 2001,
                        message,
                    },
                    Some(404) => FcpError::ResourceNotFound { resource: message },
                    Some(429) => FcpError::RateLimited {
                        retry_after_ms: 60_000,
                        violation: None,
                    },
                    _ => FcpError::External {
                        service: "qdrant".into(),
                        message,
                        status_code: *status_code,
                        retryable: self.is_retryable(),
                        retry_after: self.retry_after(),
                    },
                }
            }
            Self::InvalidConfig { message } => FcpError::InvalidRequest {
                code: 1003,
                message: sanitize(message),
            },
            Self::RateLimit { retry_after_ms } => FcpError::RateLimited {
                retry_after_ms: *retry_after_ms,
                violation: None,
            },
        }
    }
}

fn redact_sensitive(input: &str) -> String {
    let mut redacted = input.to_string();
    for pattern in REDACTION_PATTERNS {
        redacted = redact_after_pattern(&redacted, pattern);
    }
    redacted
}

fn redact_after_pattern(input: &str, pattern: &str) -> String {
    let lowercase_input = input.to_ascii_lowercase();
    let lowercase_pattern = pattern.to_ascii_lowercase();

    let mut output = String::with_capacity(input.len());
    let mut cursor = 0usize;

    while let Some(offset) = lowercase_input[cursor..].find(&lowercase_pattern) {
        let match_start = cursor + offset;
        let value_start = match_start + pattern.len();
        output.push_str(&input[cursor..value_start]);

        let value_end = find_secret_end(input, value_start);
        if value_end == value_start {
            cursor = value_start;
            continue;
        }
        output.push_str(REDACTED_TOKEN);
        cursor = value_end;
    }

    output.push_str(&input[cursor..]);
    output
}

fn find_secret_end(input: &str, start: usize) -> usize {
    if start >= input.len() {
        return start;
    }

    for (offset, ch) in input[start..].char_indices() {
        if ch.is_whitespace() || matches!(ch, ',' | ';' | '"' | '\'' | '`' | ')' | ']' | '}') {
            return start + offset;
        }
    }

    input.len()
}

impl ConnectorErrorMapping for QdrantError {
    fn from_async_error(error: AsyncError) -> Self {
        match error {
            AsyncError::Timeout { timeout_ms } => Self::Api {
                message: format!("deadline exceeded after {timeout_ms}ms"),
                status_code: Some(408),
            },
            AsyncError::Cancelled => Self::Api {
                message: "request cancelled".into(),
                status_code: None,
            },
            other => Self::Api {
                message: other.to_string(),
                status_code: None,
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

    // ── Display message tests ──────────────────────────────────────────

    #[test]
    fn display_http_error() {
        // Build a reqwest error by making an invalid URL request
        let err_inner = reqwest::Client::new()
            .get("http://[::bad")
            .build()
            .unwrap_err();
        let err = QdrantError::Http(err_inner);
        let display = format!("{err}");
        assert!(display.starts_with("HTTP error:"), "got: {display}");
    }

    #[test]
    fn display_serialization_error() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{invalid");
        let err = QdrantError::Serialization(bad.unwrap_err());
        let display = format!("{err}");
        assert!(display.starts_with("JSON error:"), "got: {display}");
    }

    #[test]
    fn display_api_error() {
        let err = QdrantError::Api {
            message: "something went wrong".into(),
            status_code: Some(500),
        };
        assert_eq!(format!("{err}"), "Qdrant API error: something went wrong");
    }

    #[test]
    fn display_invalid_config_error() {
        let err = QdrantError::InvalidConfig {
            message: "missing url".into(),
        };
        assert_eq!(format!("{err}"), "Invalid configuration: missing url");
    }

    #[test]
    fn display_rate_limit_error() {
        let err = QdrantError::RateLimit {
            retry_after_ms: 5000,
        };
        assert_eq!(format!("{err}"), "Rate limited");
    }

    // ── is_retryable tests ─────────────────────────────────────────────

    #[test]
    fn http_error_is_retryable() {
        let err_inner = reqwest::Client::new()
            .get("http://[::bad")
            .build()
            .unwrap_err();
        let err = QdrantError::Http(err_inner);
        assert!(err.is_retryable());
    }

    #[test]
    fn rate_limit_is_retryable() {
        let err = QdrantError::RateLimit {
            retry_after_ms: 1000,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn serialization_not_retryable() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{bad");
        let err = QdrantError::Serialization(bad.unwrap_err());
        assert!(!err.is_retryable());
    }

    #[test]
    fn invalid_config_not_retryable() {
        let err = QdrantError::InvalidConfig {
            message: "bad".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_500_is_retryable() {
        let err = QdrantError::Api {
            message: "server error".into(),
            status_code: Some(500),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_502_is_retryable() {
        let err = QdrantError::Api {
            message: "bad gateway".into(),
            status_code: Some(502),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_503_is_retryable() {
        let err = QdrantError::Api {
            message: "service unavailable".into(),
            status_code: Some(503),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_429_is_retryable() {
        let err = QdrantError::Api {
            message: "too many requests".into(),
            status_code: Some(429),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_400_not_retryable() {
        let err = QdrantError::Api {
            message: "bad request".into(),
            status_code: Some(400),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_401_not_retryable() {
        let err = QdrantError::Api {
            message: "unauthorized".into(),
            status_code: Some(401),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_403_not_retryable() {
        let err = QdrantError::Api {
            message: "forbidden".into(),
            status_code: Some(403),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_404_not_retryable() {
        let err = QdrantError::Api {
            message: "not found".into(),
            status_code: Some(404),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_no_status_code_not_retryable() {
        let err = QdrantError::Api {
            message: "unknown".into(),
            status_code: None,
        };
        assert!(!err.is_retryable());
    }

    // ── retry_after tests ──────────────────────────────────────────────

    #[test]
    fn retry_after_rate_limit() {
        let err = QdrantError::RateLimit {
            retry_after_ms: 3000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(3)));
    }

    #[test]
    fn retry_after_zero_ms() {
        let err = QdrantError::RateLimit { retry_after_ms: 0 };
        assert_eq!(err.retry_after(), Some(Duration::ZERO));
    }

    #[test]
    fn retry_after_none_for_http() {
        let err_inner = reqwest::Client::new()
            .get("http://[::bad")
            .build()
            .unwrap_err();
        let err = QdrantError::Http(err_inner);
        assert_eq!(err.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_api() {
        let err = QdrantError::Api {
            message: "fail".into(),
            status_code: Some(500),
        };
        assert_eq!(err.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_serialization() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{bad");
        let err = QdrantError::Serialization(bad.unwrap_err());
        assert_eq!(err.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_invalid_config() {
        let err = QdrantError::InvalidConfig {
            message: "bad".into(),
        };
        assert_eq!(err.retry_after(), None);
    }

    // ── to_fcp_error tests ─────────────────────────────────────────────

    #[test]
    fn maps_unauthorized_api_error() {
        let err = QdrantError::Api {
            message: "bad auth".into(),
            status_code: Some(401),
        };

        match err.to_fcp_error() {
            FcpError::Unauthorized { code, message } => {
                assert_eq!(code, 2001);
                assert_eq!(message, "bad auth");
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn maps_forbidden_api_error() {
        let err = QdrantError::Api {
            message: "forbidden resource".into(),
            status_code: Some(403),
        };

        match err.to_fcp_error() {
            FcpError::Unauthorized { code, message } => {
                assert_eq!(code, 2001);
                assert_eq!(message, "forbidden resource");
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn maps_not_found_api_error() {
        let err = QdrantError::Api {
            message: "collection missing".into(),
            status_code: Some(404),
        };

        match err.to_fcp_error() {
            FcpError::ResourceNotFound { resource } => {
                assert_eq!(resource, "collection missing");
            }
            other => panic!("expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn maps_rate_limited_api_error() {
        let err = QdrantError::Api {
            message: "too many requests".into(),
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
    fn maps_api_server_error_to_external() {
        let err = QdrantError::Api {
            message: "internal failure".into(),
            status_code: Some(500),
        };

        match err.to_fcp_error() {
            FcpError::External {
                service,
                message,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "qdrant");
                assert_eq!(message, "internal failure");
                assert_eq!(status_code, Some(500));
                assert!(retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn maps_api_error_no_status_to_external() {
        let err = QdrantError::Api {
            message: "unknown issue".into(),
            status_code: None,
        };

        match err.to_fcp_error() {
            FcpError::External {
                service,
                message,
                status_code,
                retryable,
                retry_after,
            } => {
                assert_eq!(service, "qdrant");
                assert_eq!(message, "unknown issue");
                assert_eq!(status_code, None);
                assert!(!retryable);
                assert!(retry_after.is_none());
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn maps_api_400_to_external() {
        let err = QdrantError::Api {
            message: "bad request".into(),
            status_code: Some(400),
        };

        match err.to_fcp_error() {
            FcpError::External {
                service,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "qdrant");
                assert_eq!(status_code, Some(400));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn maps_http_error_to_external() {
        let err_inner = reqwest::Client::new()
            .get("http://[::bad")
            .build()
            .unwrap_err();
        let err = QdrantError::Http(err_inner);

        match err.to_fcp_error() {
            FcpError::External {
                service,
                retryable,
                retry_after,
                ..
            } => {
                assert_eq!(service, "qdrant");
                assert!(retryable);
                assert!(retry_after.is_none());
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn maps_serialization_error_to_internal() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{bad");
        let err = QdrantError::Serialization(bad.unwrap_err());

        match err.to_fcp_error() {
            FcpError::Internal { message } => {
                assert!(message.starts_with("JSON error:"), "got: {message}");
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn maps_invalid_config_to_invalid_request() {
        let err = QdrantError::InvalidConfig {
            message: "missing cluster url".into(),
        };

        match err.to_fcp_error() {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1003);
                assert_eq!(message, "missing cluster url");
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn maps_rate_limit_to_rate_limited() {
        let err = QdrantError::RateLimit {
            retry_after_ms: 5000,
        };

        match err.to_fcp_error() {
            FcpError::RateLimited {
                retry_after_ms,
                violation,
            } => {
                assert_eq!(retry_after_ms, 5000);
                assert!(violation.is_none());
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    // ── Debug format tests ─────────────────────────────────────────────

    #[test]
    fn debug_format_api_error() {
        let err = QdrantError::Api {
            message: "test".into(),
            status_code: Some(500),
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("Api"), "got: {debug}");
        assert!(debug.contains("500"), "got: {debug}");
        assert!(debug.contains("test"), "got: {debug}");
    }

    #[test]
    fn debug_format_invalid_config() {
        let err = QdrantError::InvalidConfig {
            message: "bad url".into(),
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("InvalidConfig"), "got: {debug}");
        assert!(debug.contains("bad url"), "got: {debug}");
    }

    #[test]
    fn debug_format_rate_limit() {
        let err = QdrantError::RateLimit {
            retry_after_ms: 7777,
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("RateLimit"), "got: {debug}");
        assert!(debug.contains("7777"), "got: {debug}");
    }

    // ── std::error::Error trait tests ──────────────────────────────────

    #[test]
    fn error_trait_source_for_http() {
        let err_inner = reqwest::Client::new()
            .get("http://[::bad")
            .build()
            .unwrap_err();
        let err = QdrantError::Http(err_inner);
        // Http variant wraps reqwest::Error via #[from], so source should be Some
        let as_error: &dyn std::error::Error = &err;
        assert!(as_error.source().is_some());
    }

    #[test]
    fn error_trait_source_for_serialization() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{bad");
        let err = QdrantError::Serialization(bad.unwrap_err());
        let as_error: &dyn std::error::Error = &err;
        assert!(as_error.source().is_some());
    }

    #[test]
    fn error_trait_source_for_api() {
        let err = QdrantError::Api {
            message: "fail".into(),
            status_code: Some(400),
        };
        let as_error: &dyn std::error::Error = &err;
        // Api is a struct variant, no inner source
        assert!(as_error.source().is_none());
    }

    #[test]
    fn error_trait_source_for_invalid_config() {
        let err = QdrantError::InvalidConfig {
            message: "bad".into(),
        };
        let as_error: &dyn std::error::Error = &err;
        assert!(as_error.source().is_none());
    }

    #[test]
    fn error_trait_source_for_rate_limit() {
        let err = QdrantError::RateLimit {
            retry_after_ms: 100,
        };
        let as_error: &dyn std::error::Error = &err;
        assert!(as_error.source().is_none());
    }

    // ── From impls (auto-generated by thiserror #[from]) ───────────────

    #[test]
    fn from_reqwest_error() {
        let err_inner = reqwest::Client::new()
            .get("http://[::bad")
            .build()
            .unwrap_err();
        let qdrant_err: QdrantError = err_inner.into();
        assert!(matches!(qdrant_err, QdrantError::Http(_)));
    }

    #[test]
    fn from_serde_json_error() {
        let json_err: serde_json::Error =
            serde_json::from_str::<serde_json::Value>("{bad").unwrap_err();
        let qdrant_err: QdrantError = json_err.into();
        assert!(matches!(qdrant_err, QdrantError::Serialization(_)));
    }

    // ── Redaction tests ────────────────────────────────────────────────

    #[test]
    fn redacts_sensitive_values_in_api_error_message() {
        let err = QdrantError::Api {
            message: "authorization: bearer secret-token-123 api_key=abcd1234".into(),
            status_code: Some(500),
        };

        match err.to_fcp_error() {
            FcpError::External { message, .. } => {
                assert!(!message.contains("secret-token-123"));
                assert!(!message.contains("abcd1234"));
                assert!(message.contains(REDACTED_TOKEN));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn redacts_sensitive_values_in_invalid_config_message() {
        let err = QdrantError::InvalidConfig {
            message: "token=super-secret-value".into(),
        };

        match err.to_fcp_error() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(!message.contains("super-secret-value"));
                assert!(message.contains(REDACTED_TOKEN));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn redacts_bearer_pattern() {
        let result = redact_sensitive("bearer my-secret-key here");
        assert!(!result.contains("my-secret-key"));
        assert!(result.contains(REDACTED_TOKEN));
    }

    #[test]
    fn redacts_access_token_pattern() {
        let result = redact_sensitive("access_token=xyzzy123");
        assert!(!result.contains("xyzzy123"));
        assert!(result.contains(REDACTED_TOKEN));
    }

    #[test]
    fn redacts_api_key_colon_pattern() {
        let result = redact_sensitive("api-key:secret-value rest");
        assert!(!result.contains("secret-value"));
        assert!(result.contains(REDACTED_TOKEN));
    }

    #[test]
    fn redacts_json_style_token() {
        let result = redact_sensitive(r#""token":"mysecret""#);
        assert!(!result.contains("mysecret"));
        assert!(result.contains(REDACTED_TOKEN));
    }

    #[test]
    fn no_redaction_when_no_sensitive_patterns() {
        let input = "simple error with no secrets";
        let result = redact_sensitive(input);
        assert_eq!(result, input);
    }

    #[test]
    fn redaction_case_insensitive() {
        let result = redact_sensitive("Authorization: Bearer MY-TOKEN-XYZ rest");
        assert!(!result.contains("MY-TOKEN-XYZ"));
        assert!(result.contains(REDACTED_TOKEN));
    }

    #[test]
    fn redacts_multiple_patterns_in_one_string() {
        let result = redact_sensitive("bearer tok1 api_key=tok2 token:tok3");
        assert!(!result.contains("tok1"));
        assert!(!result.contains("tok2"));
        assert!(!result.contains("tok3"));
    }

    #[test]
    fn redact_after_pattern_empty_value() {
        // Pattern followed by a delimiter immediately (empty secret)
        let result = redact_after_pattern("api_key= rest", "api_key=");
        // The space comes right after the pattern, so no secret to redact
        assert_eq!(result, "api_key= rest");
    }

    #[test]
    fn find_secret_end_at_input_end() {
        let result = find_secret_end("abcdef", 6);
        assert_eq!(result, 6);
    }

    #[test]
    fn find_secret_end_delimiters() {
        assert_eq!(find_secret_end("secret,rest", 0), 6);
        assert_eq!(find_secret_end("secret;rest", 0), 6);
        assert_eq!(find_secret_end(r#"secret"rest"#, 0), 6);
        assert_eq!(find_secret_end("secret rest", 0), 6);
        assert_eq!(find_secret_end("secret)rest", 0), 6);
        assert_eq!(find_secret_end("secret]rest", 0), 6);
        assert_eq!(find_secret_end("secret}rest", 0), 6);
    }

    #[test]
    fn find_secret_end_no_delimiter() {
        assert_eq!(find_secret_end("nospaces", 0), 8);
    }

    // ── QdrantResult type alias ────────────────────────────────────────

    #[test]
    fn qdrant_result_ok() {
        let result: QdrantResult<u32> = Ok(42);
        assert!(matches!(result, Ok(42)));
    }

    #[test]
    fn qdrant_result_err() {
        let result: QdrantResult<u32> = Err(QdrantError::InvalidConfig {
            message: "test".into(),
        });
        assert!(result.is_err());
    }
}
