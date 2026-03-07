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

    // ── Expanded tests: GrantType ──

    #[test]
    fn grant_type_serde_invalid_value_rejected() {
        let result: Result<GrantType, _> = serde_json::from_str("\"invalid_grant_type\"");
        assert!(result.is_err());
    }

    #[test]
    fn grant_type_serde_null_rejected() {
        let result: Result<GrantType, _> = serde_json::from_str("null");
        assert!(result.is_err());
    }

    #[test]
    fn grant_type_serde_integer_rejected() {
        let result: Result<GrantType, _> = serde_json::from_str("42");
        assert!(result.is_err());
    }

    #[test]
    fn grant_type_debug_contains_variant_names() {
        assert!(format!("{:?}", GrantType::AuthorizationCode).contains("AuthorizationCode"));
        assert!(format!("{:?}", GrantType::ClientCredentials).contains("ClientCredentials"));
        assert!(format!("{:?}", GrantType::RefreshToken).contains("RefreshToken"));
        assert!(format!("{:?}", GrantType::DeviceCode).contains("DeviceCode"));
    }

    #[test]
    fn grant_type_clone() {
        let gt = GrantType::AuthorizationCode;
        let cloned = gt;
        assert_eq!(gt, cloned);
    }

    #[test]
    fn grant_type_eq_all_variants() {
        assert_eq!(GrantType::AuthorizationCode, GrantType::AuthorizationCode);
        assert_eq!(GrantType::ClientCredentials, GrantType::ClientCredentials);
        assert_eq!(GrantType::RefreshToken, GrantType::RefreshToken);
        assert_eq!(GrantType::DeviceCode, GrantType::DeviceCode);
        assert_ne!(GrantType::AuthorizationCode, GrantType::ClientCredentials);
        assert_ne!(GrantType::RefreshToken, GrantType::DeviceCode);
    }

    #[test]
    fn grant_type_device_code_serde_urn_format() {
        let json = serde_json::to_string(&GrantType::DeviceCode).unwrap();
        assert!(json.contains("urn:ietf:params:oauth:grant-type:device_code"));
        let roundtrip: GrantType = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip, GrantType::DeviceCode);
    }

    #[test]
    fn grant_type_display_matches_serde() {
        // Display values should match the serde JSON values (without quotes)
        for gt in [
            GrantType::AuthorizationCode,
            GrantType::ClientCredentials,
            GrantType::RefreshToken,
            GrantType::DeviceCode,
        ] {
            let display = gt.to_string();
            let serde_val = serde_json::to_string(&gt).unwrap();
            // serde wraps in quotes, so strip them
            let serde_inner = &serde_val[1..serde_val.len() - 1];
            assert_eq!(display, serde_inner, "Display != serde for {gt:?}");
        }
    }

    // ── Expanded tests: ResponseMode ──

    #[test]
    fn response_mode_clone_and_copy() {
        let mode = ResponseMode::Fragment;
        let copied = mode;
        assert_eq!(mode, copied);
    }

    #[test]
    fn response_mode_eq_all_variants() {
        assert_eq!(ResponseMode::Query, ResponseMode::Query);
        assert_eq!(ResponseMode::Fragment, ResponseMode::Fragment);
        assert_eq!(ResponseMode::FormPost, ResponseMode::FormPost);
        assert_ne!(ResponseMode::Query, ResponseMode::Fragment);
        assert_ne!(ResponseMode::Fragment, ResponseMode::FormPost);
    }

    #[test]
    fn response_mode_debug_output() {
        assert!(format!("{:?}", ResponseMode::Query).contains("Query"));
        assert!(format!("{:?}", ResponseMode::Fragment).contains("Fragment"));
        assert!(format!("{:?}", ResponseMode::FormPost).contains("FormPost"));
    }

    // ── Expanded tests: DEFAULT_REFRESH_THRESHOLD ──

    #[test]
    fn default_refresh_threshold_is_five_minutes() {
        assert_eq!(DEFAULT_REFRESH_THRESHOLD, std::time::Duration::from_secs(300));
    }
}
