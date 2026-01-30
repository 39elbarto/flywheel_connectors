//! OAuth error types.

use std::time::Duration;

/// OAuth errors.
#[derive(Debug, thiserror::Error)]
pub enum OAuthError {
    /// Invalid client configuration.
    #[error("Invalid OAuth configuration: {0}")]
    InvalidConfig(String),

    /// State mismatch (potential CSRF attack).
    #[error("OAuth state mismatch: expected {expected}, got {actual}")]
    StateMismatch {
        /// Expected state value.
        expected: String,
        /// Received state value.
        actual: String,
    },

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

    /// HTTP request failed.
    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),

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
        assert_eq!(e.to_string(), "OAuth state mismatch: expected abc, got xyz");
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
}
