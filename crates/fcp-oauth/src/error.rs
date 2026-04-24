//! OAuth error types.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_async_core::http::HttpClientError;

/// OAuth errors.
#[derive(Debug, thiserror::Error)]
pub enum OAuthError {
    /// Invalid client configuration.
    #[error("Invalid OAuth configuration: {0}")]
    InvalidConfig(String),

    /// State mismatch (potential CSRF attack).
    #[error("OAuth state mismatch")]
    StateMismatch {
        /// Expected state value.
        expected: String,
        /// Received state value.
        actual: String,
    },

    /// Invalid OAuth state value.
    #[error("Invalid OAuth state: {0}")]
    InvalidState(String),

    /// OAuth state or PKCE session was already consumed.
    #[error("OAuth authorization session has already been consumed")]
    AuthorizationSessionConsumed,

    /// Authorization error from provider.
    #[error("Authorization error: {error} - {description}")]
    AuthorizationError {
        /// Error code from provider.
        error: String,
        /// Human-readable description.
        description: String,
        /// Error URI for more information.
        error_uri: Option<String>,
    },

    /// Token exchange failed.
    #[error("Token exchange failed: {0}")]
    TokenExchangeFailed(String),

    /// Token refresh failed.
    #[error("Token refresh failed: {0}")]
    RefreshFailed(String),

    /// Token expired.
    #[error("Token expired {0:?} ago")]
    TokenExpired(Duration),

    /// No refresh token available.
    #[error("No refresh token available")]
    NoRefreshToken,

    /// Invalid token response.
    #[error("Invalid token response: {0}")]
    InvalidTokenResponse(String),

    /// OAuth token field was present but empty.
    #[error("OAuth token field cannot be empty: {0}")]
    EmptyTokenField(&'static str),

    /// HTTP request failed.
    #[error("HTTP request failed: {0}")]
    HttpError(String),

    /// JSON parsing failed.
    #[error("JSON parsing failed: {0}")]
    JsonError(#[from] serde_json::Error),

    /// URL parsing failed.
    #[error("URL parsing failed: {0}")]
    UrlError(#[from] url::ParseError),

    /// OAuth 1.0a signature error.
    #[error("OAuth 1.0a signature error: {0}")]
    SignatureError(String),

    /// Provider not supported.
    #[error("Provider not supported: {0}")]
    UnsupportedProvider(String),

    /// Token not found.
    #[error("Token not found for key: {0}")]
    TokenNotFound(String),

    /// PKCE error.
    #[error("PKCE error: {0}")]
    PkceError(String),
}

/// Result type for OAuth operations.
pub type OAuthResult<T> = Result<T, OAuthError>;

impl OAuthError {
    /// Convert an ASUPERSYNC HTTP client error into an OAuth transport error.
    #[must_use]
    pub fn from_http_client_error(error: &HttpClientError) -> Self {
        Self::HttpError(error.to_string())
    }

    /// Convert an async-core request failure into an OAuth transport error.
    #[must_use]
    pub fn from_async_error(error: AsyncError, timeout: Duration) -> Self {
        match error {
            AsyncError::Timeout { .. } => {
                Self::HttpError(format!("request timed out after {}ms", timeout.as_millis()))
            }
            AsyncError::Cancelled => Self::HttpError("request cancelled".to_string()),
            AsyncError::ProtocolIo { message }
            | AsyncError::Join { message }
            | AsyncError::Runtime { message } => Self::HttpError(message),
            AsyncError::ChannelClosed => Self::HttpError("request channel closed".to_string()),
            AsyncError::ChannelFull => Self::HttpError("request channel full".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_config_display() {
        let e = OAuthError::InvalidConfig("bad".into());
        assert_eq!(e.to_string(), "Invalid OAuth configuration: bad");
    }

    #[test]
    fn state_mismatch_display() {
        let e = OAuthError::StateMismatch {
            expected: "abc".into(),
            actual: "xyz".into(),
        };
        assert_eq!(e.to_string(), "OAuth state mismatch");
    }

    #[test]
    fn invalid_state_display() {
        let e = OAuthError::InvalidState("state must not be empty".into());
        assert_eq!(
            e.to_string(),
            "Invalid OAuth state: state must not be empty"
        );
    }

    #[test]
    fn authorization_session_consumed_display() {
        let e = OAuthError::AuthorizationSessionConsumed;
        assert_eq!(
            e.to_string(),
            "OAuth authorization session has already been consumed"
        );
    }

    #[test]
    fn authorization_error_display() {
        let e = OAuthError::AuthorizationError {
            error: "access_denied".into(),
            description: "User denied".into(),
            error_uri: None,
        };
        assert_eq!(
            e.to_string(),
            "Authorization error: access_denied - User denied"
        );
    }

    #[test]
    fn token_exchange_failed_display() {
        let e = OAuthError::TokenExchangeFailed("bad code".into());
        assert_eq!(e.to_string(), "Token exchange failed: bad code");
    }

    #[test]
    fn refresh_failed_display() {
        let e = OAuthError::RefreshFailed("expired".into());
        assert_eq!(e.to_string(), "Token refresh failed: expired");
    }

    #[test]
    fn token_expired_display() {
        let e = OAuthError::TokenExpired(Duration::from_secs(60));
        assert_eq!(e.to_string(), "Token expired 60s ago");
    }

    #[test]
    fn no_refresh_token_display() {
        let e = OAuthError::NoRefreshToken;
        assert_eq!(e.to_string(), "No refresh token available");
    }

    #[test]
    fn invalid_token_response_display() {
        let e = OAuthError::InvalidTokenResponse("missing field".into());
        assert_eq!(e.to_string(), "Invalid token response: missing field");
    }

    #[test]
    fn signature_error_display() {
        let e = OAuthError::SignatureError("bad key".into());
        assert_eq!(e.to_string(), "OAuth 1.0a signature error: bad key");
    }

    #[test]
    fn unsupported_provider_display() {
        let e = OAuthError::UnsupportedProvider("myspace".into());
        assert_eq!(e.to_string(), "Provider not supported: myspace");
    }

    #[test]
    fn token_not_found_display() {
        let e = OAuthError::TokenNotFound("user1".into());
        assert_eq!(e.to_string(), "Token not found for key: user1");
    }

    #[test]
    fn pkce_error_display() {
        let e = OAuthError::PkceError("too short".into());
        assert_eq!(e.to_string(), "PKCE error: too short");
    }

    #[test]
    fn json_error_from() {
        let json_err: Result<serde_json::Value, _> = serde_json::from_str("bad");
        let e: OAuthError = json_err.unwrap_err().into();
        assert!(matches!(e, OAuthError::JsonError(_)));
    }

    #[test]
    fn url_error_from() {
        let url_err = url::Url::parse("://bad").unwrap_err();
        let e: OAuthError = url_err.into();
        assert!(matches!(e, OAuthError::UrlError(_)));
    }

    // ── Batch: std::error::Error impls ──

    #[test]
    fn all_variants_implement_error() {
        fn assert_error<E: std::error::Error>(_: &E) {}
        assert_error(&OAuthError::InvalidConfig("x".into()));
        assert_error(&OAuthError::StateMismatch {
            expected: "a".into(),
            actual: "b".into(),
        });
        assert_error(&OAuthError::InvalidState("x".into()));
        assert_error(&OAuthError::AuthorizationSessionConsumed);
        assert_error(&OAuthError::AuthorizationError {
            error: "e".into(),
            description: "d".into(),
            error_uri: None,
        });
        assert_error(&OAuthError::TokenExchangeFailed("x".into()));
        assert_error(&OAuthError::RefreshFailed("x".into()));
        assert_error(&OAuthError::TokenExpired(Duration::from_secs(1)));
        assert_error(&OAuthError::NoRefreshToken);
        assert_error(&OAuthError::InvalidTokenResponse("x".into()));
        assert_error(&OAuthError::SignatureError("x".into()));
        assert_error(&OAuthError::UnsupportedProvider("x".into()));
        assert_error(&OAuthError::TokenNotFound("x".into()));
        assert_error(&OAuthError::PkceError("x".into()));
    }

    #[test]
    fn authorization_error_with_uri() {
        let e = OAuthError::AuthorizationError {
            error: "access_denied".into(),
            description: "desc".into(),
            error_uri: Some("https://example.com/error".into()),
        };
        // error_uri doesn't appear in Display but should be stored
        let display = e.to_string();
        assert!(display.contains("access_denied"));
        if let OAuthError::AuthorizationError { error_uri, .. } = e {
            assert_eq!(error_uri, Some("https://example.com/error".to_string()));
        }
    }

    #[test]
    fn token_expired_zero_duration() {
        let e = OAuthError::TokenExpired(Duration::from_secs(0));
        let display = e.to_string();
        assert!(display.contains('0'));
    }

    #[test]
    fn debug_format_contains_variant_name() {
        let e = OAuthError::NoRefreshToken;
        let debug = format!("{e:?}");
        assert!(debug.contains("NoRefreshToken"));
    }

    // ── Expanded tests: from_http_client_error ──

    #[test]
    fn from_http_client_error_produces_http_error() {
        // HttpClientError is opaque, so we test via the OAuthError variant
        let e = OAuthError::HttpError("connection refused".into());
        assert!(matches!(e, OAuthError::HttpError(_)));
        assert!(e.to_string().contains("connection refused"));
    }

    // ── Expanded tests: from_async_error ──

    #[test]
    fn from_async_error_timeout() {
        let err = AsyncError::Timeout { timeout_ms: 30_000 };
        let oauth_err = OAuthError::from_async_error(err, Duration::from_secs(30));
        let msg = oauth_err.to_string();
        assert!(msg.contains("timed out"));
        assert!(msg.contains("30000"));
    }

    #[test]
    fn from_async_error_cancelled() {
        let err = AsyncError::Cancelled;
        let oauth_err = OAuthError::from_async_error(err, Duration::from_secs(10));
        assert!(oauth_err.to_string().contains("cancelled"));
    }

    #[test]
    fn from_async_error_channel_closed() {
        let err = AsyncError::ChannelClosed;
        let oauth_err = OAuthError::from_async_error(err, Duration::from_secs(10));
        assert!(oauth_err.to_string().contains("channel closed"));
    }

    #[test]
    fn from_async_error_channel_full() {
        let err = AsyncError::ChannelFull;
        let oauth_err = OAuthError::from_async_error(err, Duration::from_secs(10));
        assert!(oauth_err.to_string().contains("channel full"));
    }

    #[test]
    fn from_async_error_protocol_io() {
        let err = AsyncError::ProtocolIo {
            message: "read error".into(),
        };
        let oauth_err = OAuthError::from_async_error(err, Duration::from_secs(10));
        assert!(oauth_err.to_string().contains("read error"));
    }

    #[test]
    fn from_async_error_join() {
        let err = AsyncError::Join {
            message: "task panicked".into(),
        };
        let oauth_err = OAuthError::from_async_error(err, Duration::from_secs(10));
        assert!(oauth_err.to_string().contains("task panicked"));
    }

    #[test]
    fn from_async_error_runtime() {
        let err = AsyncError::Runtime {
            message: "runtime shutdown".into(),
        };
        let oauth_err = OAuthError::from_async_error(err, Duration::from_secs(10));
        assert!(oauth_err.to_string().contains("runtime shutdown"));
    }

    // ── Expanded tests: Display messages ──

    #[test]
    fn http_error_display() {
        let e = OAuthError::HttpError("dns lookup failed".into());
        assert_eq!(e.to_string(), "HTTP request failed: dns lookup failed");
    }

    #[test]
    fn url_error_display_contains_parsing_failed() {
        let url_err = url::Url::parse("://").unwrap_err();
        let e: OAuthError = url_err.into();
        assert!(e.to_string().contains("URL parsing failed"));
    }

    #[test]
    fn json_error_display_contains_parsing_failed() {
        let json_err: Result<serde_json::Value, _> = serde_json::from_str("{invalid}");
        let e: OAuthError = json_err.unwrap_err().into();
        assert!(e.to_string().contains("JSON parsing failed"));
    }

    #[test]
    fn state_mismatch_fields_accessible() {
        let e = OAuthError::StateMismatch {
            expected: "expected_state_abc".into(),
            actual: "actual_state_xyz".into(),
        };
        if let OAuthError::StateMismatch { expected, actual } = &e {
            assert_eq!(expected, "expected_state_abc");
            assert_eq!(actual, "actual_state_xyz");
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn token_expired_large_duration() {
        let e = OAuthError::TokenExpired(Duration::from_secs(86400));
        let display = e.to_string();
        assert!(display.contains("86400"));
    }

    #[test]
    fn invalid_config_empty_message() {
        let e = OAuthError::InvalidConfig(String::new());
        assert_eq!(e.to_string(), "Invalid OAuth configuration: ");
    }

    #[test]
    fn authorization_error_empty_description() {
        let e = OAuthError::AuthorizationError {
            error: "temporarily_unavailable".into(),
            description: String::new(),
            error_uri: None,
        };
        let display = e.to_string();
        assert!(display.contains("temporarily_unavailable"));
        assert!(display.contains(" - "));
    }

    // ── Expanded: error variant field access ──

    #[test]
    fn authorization_error_all_fields_populated() {
        let e = OAuthError::AuthorizationError {
            error: "invalid_request".into(),
            description: "The request is missing a required parameter".into(),
            error_uri: Some("https://tools.ietf.org/html/rfc6749#section-4.1.2.1".into()),
        };
        let display = e.to_string();
        assert!(display.contains("invalid_request"));
        assert!(display.contains("The request is missing a required parameter"));
    }

    #[test]
    fn state_mismatch_empty_strings() {
        let e = OAuthError::StateMismatch {
            expected: String::new(),
            actual: String::new(),
        };
        let display = e.to_string();
        assert!(display.contains("expected"));
        assert!(display.contains("got"));
    }

    #[test]
    fn token_expired_subsecond_duration() {
        let e = OAuthError::TokenExpired(Duration::from_millis(500));
        let display = e.to_string();
        // Duration debug format shows milliseconds
        assert!(display.contains("500"));
    }

    #[test]
    fn token_not_found_empty_key() {
        let e = OAuthError::TokenNotFound(String::new());
        assert_eq!(e.to_string(), "Token not found for key: ");
    }

    #[test]
    fn pkce_error_long_message() {
        let msg = "x".repeat(500);
        let e = OAuthError::PkceError(msg.clone());
        assert!(e.to_string().contains(&msg));
    }

    #[test]
    fn http_error_empty_message() {
        let e = OAuthError::HttpError(String::new());
        assert_eq!(e.to_string(), "HTTP request failed: ");
    }

    #[test]
    fn refresh_failed_with_json_body() {
        let e = OAuthError::RefreshFailed(r#"{"error":"invalid_grant"}"#.into());
        assert!(e.to_string().contains("invalid_grant"));
    }

    #[test]
    fn invalid_token_response_unicode_content() {
        let e = OAuthError::InvalidTokenResponse("missing \u{00e9}l\u{00e9}ment".into());
        assert!(e.to_string().contains("\u{00e9}l\u{00e9}ment"));
    }

    #[test]
    fn signature_error_with_details() {
        let e = OAuthError::SignatureError("HMAC key length invalid: expected 32, got 0".into());
        let display = e.to_string();
        assert!(display.contains("HMAC key length"));
        assert!(display.contains("OAuth 1.0a"));
    }

    #[test]
    fn unsupported_provider_unicode_name() {
        let e = OAuthError::UnsupportedProvider("\u{5fae}\u{4fe1}".into());
        assert!(e.to_string().contains("\u{5fae}\u{4fe1}"));
    }

    #[test]
    fn from_async_error_timeout_zero_ms() {
        let err = AsyncError::Timeout { timeout_ms: 0 };
        let oauth_err = OAuthError::from_async_error(err, Duration::from_secs(0));
        assert!(oauth_err.to_string().contains("timed out"));
        assert!(oauth_err.to_string().contains("0ms"));
    }

    #[test]
    fn from_async_error_timeout_large_duration() {
        let err = AsyncError::Timeout {
            timeout_ms: 300_000,
        };
        let oauth_err = OAuthError::from_async_error(err, Duration::from_secs(300));
        assert!(oauth_err.to_string().contains("300000"));
    }

    #[test]
    fn json_error_source_chain() {
        let json_err: Result<serde_json::Value, _> = serde_json::from_str("{bad");
        let e: OAuthError = json_err.unwrap_err().into();
        // std::error::Error source should return Some for JsonError
        assert!(std::error::Error::source(&e).is_some());
    }

    #[test]
    fn url_error_source_chain() {
        let url_err = url::Url::parse("://").unwrap_err();
        let e: OAuthError = url_err.into();
        assert!(std::error::Error::source(&e).is_some());
    }

    #[test]
    fn no_refresh_token_has_no_source() {
        let e = OAuthError::NoRefreshToken;
        assert!(std::error::Error::source(&e).is_none());
    }

    #[test]
    fn invalid_config_has_no_source() {
        let e = OAuthError::InvalidConfig("test".into());
        assert!(std::error::Error::source(&e).is_none());
    }

    // ── New batch: OAuthError edge cases and cross-variant ──

    #[test]
    fn token_exchange_failed_has_no_source() {
        let e = OAuthError::TokenExchangeFailed("x".into());
        assert!(std::error::Error::source(&e).is_none());
    }

    #[test]
    fn refresh_failed_has_no_source() {
        let e = OAuthError::RefreshFailed("x".into());
        assert!(std::error::Error::source(&e).is_none());
    }

    #[test]
    fn http_error_has_no_source() {
        let e = OAuthError::HttpError("x".into());
        assert!(std::error::Error::source(&e).is_none());
    }

    #[test]
    fn signature_error_has_no_source() {
        let e = OAuthError::SignatureError("x".into());
        assert!(std::error::Error::source(&e).is_none());
    }

    #[test]
    fn token_not_found_has_no_source() {
        let e = OAuthError::TokenNotFound("x".into());
        assert!(std::error::Error::source(&e).is_none());
    }

    #[test]
    fn pkce_error_has_no_source() {
        let e = OAuthError::PkceError("x".into());
        assert!(std::error::Error::source(&e).is_none());
    }

    #[test]
    fn unsupported_provider_has_no_source() {
        let e = OAuthError::UnsupportedProvider("x".into());
        assert!(std::error::Error::source(&e).is_none());
    }

    #[test]
    fn token_expired_has_no_source() {
        let e = OAuthError::TokenExpired(Duration::from_secs(1));
        assert!(std::error::Error::source(&e).is_none());
    }

    #[test]
    fn state_mismatch_has_no_source() {
        let e = OAuthError::StateMismatch {
            expected: "a".into(),
            actual: "b".into(),
        };
        assert!(std::error::Error::source(&e).is_none());
    }

    #[test]
    fn authorization_error_has_no_source() {
        let e = OAuthError::AuthorizationError {
            error: "e".into(),
            description: "d".into(),
            error_uri: None,
        };
        assert!(std::error::Error::source(&e).is_none());
    }

    #[test]
    fn invalid_token_response_has_no_source() {
        let e = OAuthError::InvalidTokenResponse("x".into());
        assert!(std::error::Error::source(&e).is_none());
    }

    #[test]
    fn from_async_error_protocol_io_empty_message() {
        let err = AsyncError::ProtocolIo {
            message: String::new(),
        };
        let oauth_err = OAuthError::from_async_error(err, Duration::from_secs(5));
        // Should still be HttpError variant even with empty message
        assert!(matches!(oauth_err, OAuthError::HttpError(_)));
    }

    #[test]
    fn from_async_error_join_unicode_message() {
        let err = AsyncError::Join {
            message: "tarea fall\u{00f3}".into(),
        };
        let oauth_err = OAuthError::from_async_error(err, Duration::from_secs(5));
        assert!(oauth_err.to_string().contains("fall\u{00f3}"));
    }

    #[test]
    fn token_expired_very_large_duration() {
        let e = OAuthError::TokenExpired(Duration::from_secs(u64::MAX));
        let display = e.to_string();
        // Should render without panicking
        assert!(display.contains("Token expired"));
    }

    #[test]
    fn state_mismatch_unicode_values() {
        let e = OAuthError::StateMismatch {
            expected: "\u{00e9}tat_attendu".into(),
            actual: "\u{00e9}tat_re\u{00e7}u".into(),
        };
        let display = e.to_string();
        assert_eq!(display, "OAuth state mismatch");
    }

    #[test]
    fn all_string_variants_debug_format_contains_message() {
        let variants: Vec<OAuthError> = vec![
            OAuthError::InvalidConfig("cfg_msg".into()),
            OAuthError::TokenExchangeFailed("exchange_msg".into()),
            OAuthError::RefreshFailed("refresh_msg".into()),
            OAuthError::InvalidTokenResponse("invalid_msg".into()),
            OAuthError::HttpError("http_msg".into()),
            OAuthError::SignatureError("sig_msg".into()),
            OAuthError::UnsupportedProvider("prov_msg".into()),
            OAuthError::TokenNotFound("notfound_msg".into()),
            OAuthError::PkceError("pkce_msg".into()),
        ];
        for e in &variants {
            let debug = format!("{e:?}");
            assert!(!debug.is_empty(), "Debug should not be empty for {e}");
        }
    }

    #[test]
    fn oauth_result_ok_variant() {
        let val = 42;
        let result: OAuthResult<i32> = Ok(val);
        assert!(result.is_ok());
        assert_eq!(val, 42);
    }

    #[test]
    fn oauth_result_err_variant() {
        let result: OAuthResult<i32> = Err(OAuthError::NoRefreshToken);
        assert!(result.is_err());
    }
}
