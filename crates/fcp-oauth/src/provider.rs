//! Pre-configured OAuth providers.
//!
//! Ready-to-use configurations for common OAuth providers.

use crate::{OAuth1Config, OAuth2Config, PkceMethod};

/// Known OAuth provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthProvider {
    /// Google (OAuth 2.0 + PKCE).
    Google,
    /// GitHub (OAuth 2.0).
    GitHub,
    /// Twitter/X OAuth 2.0.
    Twitter,
    /// Twitter/X OAuth 1.0a (legacy).
    TwitterLegacy,
    /// Slack (OAuth 2.0).
    Slack,
    /// Notion (OAuth 2.0).
    Notion,
    /// Linear (OAuth 2.0).
    Linear,
    /// Discord (OAuth 2.0).
    Discord,
    /// Spotify (OAuth 2.0).
    Spotify,
    /// Microsoft/Azure AD (OAuth 2.0).
    Microsoft,
    /// Dropbox (OAuth 2.0).
    Dropbox,
}

impl OAuthProvider {
    /// Get OAuth 2.0 configuration for this provider.
    ///
    /// Returns `None` for OAuth 1.0a-only providers.
    #[must_use]
    pub fn oauth2_config(&self, client_id: &str, client_secret: &str) -> Option<OAuth2Config> {
        match self {
            Self::Google => Some(google_config(client_id, client_secret)),
            Self::GitHub => Some(github_config(client_id, client_secret)),
            Self::Twitter => Some(twitter_oauth2_config(client_id, client_secret)),
            Self::TwitterLegacy => None,
            Self::Slack => Some(slack_config(client_id, client_secret)),
            Self::Notion => Some(notion_config(client_id, client_secret)),
            Self::Linear => Some(linear_config(client_id, client_secret)),
            Self::Discord => Some(discord_config(client_id, client_secret)),
            Self::Spotify => Some(spotify_config(client_id, client_secret)),
            Self::Microsoft => Some(microsoft_config(client_id, client_secret)),
            Self::Dropbox => Some(dropbox_config(client_id, client_secret)),
        }
    }

    /// Get OAuth 1.0a configuration for this provider.
    ///
    /// Returns `None` for OAuth 2.0-only providers.
    #[must_use]
    pub fn oauth1_config(&self, consumer_key: &str, consumer_secret: &str) -> Option<OAuth1Config> {
        match self {
            Self::TwitterLegacy => Some(twitter_oauth1_config(consumer_key, consumer_secret)),
            _ => None,
        }
    }

    /// Check if this provider supports OAuth 2.0.
    #[must_use]
    pub const fn supports_oauth2(&self) -> bool {
        !matches!(self, Self::TwitterLegacy)
    }

    /// Check if this provider supports OAuth 1.0a.
    #[must_use]
    pub const fn supports_oauth1(&self) -> bool {
        matches!(self, Self::TwitterLegacy)
    }

    /// Check if this provider requires PKCE.
    #[must_use]
    pub const fn requires_pkce(&self) -> bool {
        matches!(self, Self::Google | Self::Twitter)
    }
}

// Provider-specific configurations

/// Google OAuth 2.0 configuration.
fn google_config(client_id: &str, client_secret: &str) -> OAuth2Config {
    OAuth2Config::new(
        client_id,
        client_secret,
        "https://accounts.google.com/o/oauth2/v2/auth",
        "https://oauth2.googleapis.com/token",
    )
    .with_pkce(true)
    .with_pkce_method(PkceMethod::S256)
    .with_auth_param("access_type", "offline")
    .with_auth_param("prompt", "consent")
}

/// GitHub OAuth 2.0 configuration.
fn github_config(client_id: &str, client_secret: &str) -> OAuth2Config {
    OAuth2Config::new(
        client_id,
        client_secret,
        "https://github.com/login/oauth/authorize",
        "https://github.com/login/oauth/access_token",
    )
    .with_pkce(false) // GitHub doesn't support PKCE
}

/// Twitter/X OAuth 2.0 configuration.
fn twitter_oauth2_config(client_id: &str, client_secret: &str) -> OAuth2Config {
    OAuth2Config::new(
        client_id,
        client_secret,
        "https://twitter.com/i/oauth2/authorize",
        "https://api.twitter.com/2/oauth2/token",
    )
    .with_pkce(true)
    .with_pkce_method(PkceMethod::S256)
}

/// Twitter/X OAuth 1.0a configuration (legacy).
fn twitter_oauth1_config(consumer_key: &str, consumer_secret: &str) -> OAuth1Config {
    OAuth1Config::new(
        consumer_key,
        consumer_secret,
        "https://api.twitter.com/oauth/request_token",
        "https://api.twitter.com/oauth/authorize",
        "https://api.twitter.com/oauth/access_token",
    )
}

/// Slack OAuth 2.0 configuration.
fn slack_config(client_id: &str, client_secret: &str) -> OAuth2Config {
    OAuth2Config::new(
        client_id,
        client_secret,
        "https://slack.com/oauth/v2/authorize",
        "https://slack.com/api/oauth.v2.access",
    )
    .with_pkce(false)
}

/// Notion OAuth 2.0 configuration.
fn notion_config(client_id: &str, client_secret: &str) -> OAuth2Config {
    OAuth2Config::new(
        client_id,
        client_secret,
        "https://api.notion.com/v1/oauth/authorize",
        "https://api.notion.com/v1/oauth/token",
    )
    .with_pkce(false)
    .with_auth_param("owner", "user")
}

/// Linear OAuth 2.0 configuration.
fn linear_config(client_id: &str, client_secret: &str) -> OAuth2Config {
    OAuth2Config::new(
        client_id,
        client_secret,
        "https://linear.app/oauth/authorize",
        "https://api.linear.app/oauth/token",
    )
    .with_pkce(false)
    .with_auth_param("response_type", "code")
}

/// Discord OAuth 2.0 configuration.
fn discord_config(client_id: &str, client_secret: &str) -> OAuth2Config {
    OAuth2Config::new(
        client_id,
        client_secret,
        "https://discord.com/oauth2/authorize",
        "https://discord.com/api/oauth2/token",
    )
    .with_pkce(false)
}

/// Spotify OAuth 2.0 configuration.
fn spotify_config(client_id: &str, client_secret: &str) -> OAuth2Config {
    OAuth2Config::new(
        client_id,
        client_secret,
        "https://accounts.spotify.com/authorize",
        "https://accounts.spotify.com/api/token",
    )
    .with_pkce(true)
    .with_pkce_method(PkceMethod::S256)
}

/// Microsoft/Azure AD OAuth 2.0 configuration.
fn microsoft_config(client_id: &str, client_secret: &str) -> OAuth2Config {
    OAuth2Config::new(
        client_id,
        client_secret,
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    )
    .with_pkce(true)
    .with_pkce_method(PkceMethod::S256)
}

/// Dropbox OAuth 2.0 configuration.
fn dropbox_config(client_id: &str, client_secret: &str) -> OAuth2Config {
    OAuth2Config::new(
        client_id,
        client_secret,
        "https://www.dropbox.com/oauth2/authorize",
        "https://api.dropboxapi.com/oauth2/token",
    )
    .with_pkce(true)
    .with_pkce_method(PkceMethod::S256)
    .with_auth_param("token_access_type", "offline")
}

/// Provider endpoints for custom configuration.
#[derive(Debug, Clone)]
pub struct ProviderEndpoints {
    /// Authorization endpoint.
    pub authorization_url: String,
    /// Token endpoint.
    pub token_url: String,
    /// Revocation endpoint (optional).
    pub revocation_url: Option<String>,
    /// User info endpoint (optional).
    pub userinfo_url: Option<String>,
}

impl ProviderEndpoints {
    /// Create new provider endpoints.
    #[must_use]
    pub fn new(authorization_url: impl Into<String>, token_url: impl Into<String>) -> Self {
        Self {
            authorization_url: authorization_url.into(),
            token_url: token_url.into(),
            revocation_url: None,
            userinfo_url: None,
        }
    }

    /// Set revocation URL.
    #[must_use]
    pub fn with_revocation_url(mut self, url: impl Into<String>) -> Self {
        self.revocation_url = Some(url.into());
        self
    }

    /// Set userinfo URL.
    #[must_use]
    pub fn with_userinfo_url(mut self, url: impl Into<String>) -> Self {
        self.userinfo_url = Some(url.into());
        self
    }

    /// Build OAuth2Config from these endpoints.
    #[must_use]
    pub fn to_oauth2_config(&self, client_id: &str, client_secret: &str) -> OAuth2Config {
        OAuth2Config::new(
            client_id,
            client_secret,
            &self.authorization_url,
            &self.token_url,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_google_config() {
        let config = OAuthProvider::Google
            .oauth2_config("client_id", "client_secret")
            .unwrap();

        assert!(config.use_pkce);
        assert_eq!(config.pkce_method, PkceMethod::S256);
        assert!(config.authorization_url.contains("google"));
    }

    #[test]
    fn test_github_config() {
        let config = OAuthProvider::GitHub
            .oauth2_config("client_id", "client_secret")
            .unwrap();

        assert!(!config.use_pkce); // GitHub doesn't support PKCE
        assert!(config.authorization_url.contains("github"));
    }

    #[test]
    fn test_twitter_oauth1() {
        let config = OAuthProvider::TwitterLegacy
            .oauth1_config("consumer_key", "consumer_secret")
            .unwrap();

        assert!(config.request_token_url.contains("twitter"));
    }

    #[test]
    fn test_provider_capabilities() {
        assert!(OAuthProvider::Google.supports_oauth2());
        assert!(!OAuthProvider::Google.supports_oauth1());
        assert!(OAuthProvider::Google.requires_pkce());

        assert!(!OAuthProvider::TwitterLegacy.supports_oauth2());
        assert!(OAuthProvider::TwitterLegacy.supports_oauth1());

        assert!(OAuthProvider::GitHub.supports_oauth2());
        assert!(!OAuthProvider::GitHub.requires_pkce());
    }

    #[test]
    fn test_custom_endpoints() {
        let endpoints = ProviderEndpoints::new(
            "https://custom.auth.com/authorize",
            "https://custom.auth.com/token",
        )
        .with_revocation_url("https://custom.auth.com/revoke")
        .with_userinfo_url("https://custom.auth.com/userinfo");

        let config = endpoints.to_oauth2_config("client_id", "client_secret");

        assert_eq!(
            config.authorization_url,
            "https://custom.auth.com/authorize"
        );
        assert_eq!(config.token_url, "https://custom.auth.com/token");
    }

    // ── New tests ──

    #[test]
    fn test_twitter_legacy_returns_none_for_oauth2() {
        let config = OAuthProvider::TwitterLegacy.oauth2_config("id", "secret");
        assert!(config.is_none());
    }

    #[test]
    fn test_non_legacy_returns_none_for_oauth1() {
        assert!(
            OAuthProvider::Google
                .oauth1_config("key", "secret")
                .is_none()
        );
        assert!(
            OAuthProvider::GitHub
                .oauth1_config("key", "secret")
                .is_none()
        );
        assert!(
            OAuthProvider::Slack
                .oauth1_config("key", "secret")
                .is_none()
        );
    }

    #[test]
    fn test_all_oauth2_providers_have_urls() {
        let providers = [
            OAuthProvider::Google,
            OAuthProvider::GitHub,
            OAuthProvider::Twitter,
            OAuthProvider::Slack,
            OAuthProvider::Notion,
            OAuthProvider::Linear,
            OAuthProvider::Discord,
            OAuthProvider::Spotify,
            OAuthProvider::Microsoft,
            OAuthProvider::Dropbox,
        ];

        for provider in providers {
            let config = provider.oauth2_config("id", "secret");
            assert!(
                config.is_some(),
                "Provider {provider:?} should return OAuth2 config"
            );
            let config = config.unwrap();
            assert!(!config.authorization_url.is_empty());
            assert!(!config.token_url.is_empty());
        }
    }

    #[test]
    fn test_provider_endpoints_defaults() {
        let endpoints = ProviderEndpoints::new(
            "https://auth.example.com/authorize",
            "https://auth.example.com/token",
        );
        assert!(endpoints.revocation_url.is_none());
        assert!(endpoints.userinfo_url.is_none());
    }

    #[test]
    fn test_pkce_required_providers() {
        assert!(OAuthProvider::Google.requires_pkce());
        assert!(OAuthProvider::Twitter.requires_pkce());
        assert!(!OAuthProvider::GitHub.requires_pkce());
        assert!(!OAuthProvider::Slack.requires_pkce());
    }
}
