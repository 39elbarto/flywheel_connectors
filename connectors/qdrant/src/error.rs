//! Qdrant-specific error types.

use std::time::Duration;

use fcp_core::FcpError;

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

#[cfg(test)]
mod tests {
    use super::*;

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
            FcpError::RateLimited { retry_after_ms, .. } => {
                assert_eq!(retry_after_ms, 60_000);
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

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
}
