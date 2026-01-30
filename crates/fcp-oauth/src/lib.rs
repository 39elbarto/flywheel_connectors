//! FCP OAuth - Unified OAuth library for FCP connectors
//!
//! This crate provides comprehensive OAuth support:
//!
//! - **OAuth 2.0**: Authorization code (with PKCE), client credentials
//! - **OAuth 1.0a**: For legacy providers like Twitter
//! - **Token Management**: Automatic refresh, caching, validation
//! - **Provider Support**: Pre-configured for common providers
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use fcp_oauth::{OAuth2Client, OAuth2Config, Pkce};
//!
//! // Create OAuth 2.0 client with PKCE
//! let config = OAuth2Config::new(
//!     "client_id",
//!     "client_secret",
//!     "https://auth.example.com/authorize",
//!     "https://auth.example.com/token",
//! ).with_redirect_uri("https://localhost:3000/callback");
//!
//! let client = OAuth2Client::new(config);
//!
//! // Generate authorization URL with PKCE
//! let (auth_url, state, pkce) = client.authorization_url_with_pkce(&["read", "write"]);
//!
//! // After user authorization, exchange code for tokens
//! let tokens = client.exchange_code_with_pkce(&code, &pkce).await?;
//! ```

#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

mod error;
mod oauth1;
mod oauth2;
mod pkce;
mod provider;
mod token;

pub use error::*;
pub use oauth1::*;
pub use oauth2::*;
pub use pkce::*;
pub use provider::*;
pub use token::*;

use std::time::Duration;

/// Default token refresh threshold (refresh when less than this time remaining).
pub const DEFAULT_REFRESH_THRESHOLD: Duration = Duration::from_secs(300); // 5 minutes

/// OAuth grant types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantType {
    /// Authorization code grant (user authorization flow).
    AuthorizationCode,
    /// Client credentials grant (service-to-service).
    ClientCredentials,
    /// Refresh token grant.
    RefreshToken,
    /// Device code grant.
    #[serde(rename = "urn:ietf:params:oauth:grant-type:device_code")]
    DeviceCode,
}

impl std::fmt::Display for GrantType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AuthorizationCode => write!(f, "authorization_code"),
            Self::ClientCredentials => write!(f, "client_credentials"),
            Self::RefreshToken => write!(f, "refresh_token"),
            Self::DeviceCode => write!(f, "urn:ietf:params:oauth:grant-type:device_code"),
        }
    }
}

/// OAuth response mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResponseMode {
    /// Query parameters in redirect URI.
    #[default]
    Query,
    /// Fragment in redirect URI.
    Fragment,
    /// Form POST to redirect URI.
    FormPost,
}

impl std::fmt::Display for ResponseMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Query => write!(f, "query"),
            Self::Fragment => write!(f, "fragment"),
            Self::FormPost => write!(f, "form_post"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_type_display() {
        assert_eq!(
            GrantType::AuthorizationCode.to_string(),
            "authorization_code"
        );
        assert_eq!(
            GrantType::ClientCredentials.to_string(),
            "client_credentials"
        );
        assert_eq!(GrantType::RefreshToken.to_string(), "refresh_token");
        assert_eq!(
            GrantType::DeviceCode.to_string(),
            "urn:ietf:params:oauth:grant-type:device_code"
        );
    }

    #[test]
    fn grant_type_serde_roundtrip() {
        let variants = vec![
            (GrantType::AuthorizationCode, "\"authorization_code\""),
            (GrantType::ClientCredentials, "\"client_credentials\""),
            (GrantType::RefreshToken, "\"refresh_token\""),
            (
                GrantType::DeviceCode,
                "\"urn:ietf:params:oauth:grant-type:device_code\"",
            ),
        ];

        for (grant, expected_json) in variants {
            let json = serde_json::to_string(&grant).unwrap();
            assert_eq!(json, expected_json);
            let roundtrip: GrantType = serde_json::from_str(&json).unwrap();
            assert_eq!(roundtrip, grant);
        }
    }

    #[test]
    fn response_mode_display() {
        assert_eq!(ResponseMode::Query.to_string(), "query");
        assert_eq!(ResponseMode::Fragment.to_string(), "fragment");
        assert_eq!(ResponseMode::FormPost.to_string(), "form_post");
    }

    #[test]
    fn response_mode_default_is_query() {
        assert_eq!(ResponseMode::default(), ResponseMode::Query);
    }
}
