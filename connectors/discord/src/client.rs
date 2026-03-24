//! Discord client wrapper with secret-redacting Debug and standard FCP client interface.
//!
//! Wraps [`DiscordApiClient`] to add:
//! - Secret-redacting `Debug` impl (bot credentials never leak to logs)
//! - Standard `from_config` constructor matching other FCP connectors
//! - `Deref` to the underlying API client for transparent method access

use std::fmt;
use std::ops::Deref;
use std::sync::Arc;

use crate::api::DiscordApiClient;
use crate::config::DiscordConfig;
use crate::error::DiscordResult;

/// Discord client with secret-redacting Debug.
///
/// This is the standard FCP client entry point for the Discord connector.
/// It wraps [`DiscordApiClient`] and ensures bot credentials are never
/// exposed in `Debug` or log output.
pub struct DiscordClient {
    inner: DiscordApiClient,
    /// Redacted base URL for Debug output (no credentials).
    base_url: String,
}

impl DiscordClient {
    /// Create a new Discord client from configuration.
    ///
    /// This is the standard FCP connector client constructor.
    pub fn from_config(config: &DiscordConfig) -> DiscordResult<Self> {
        let inner = DiscordApiClient::new(config)?;
        Ok(Self {
            inner,
            base_url: config.api_url.clone(),
        })
    }

    /// Convert into an `Arc<DiscordApiClient>` for use in the connector struct.
    ///
    /// This consumes the client and returns the inner API client wrapped in an Arc,
    /// which is the type that `DiscordConnector` stores.
    #[must_use]
    pub fn into_api_client(self) -> Arc<DiscordApiClient> {
        Arc::new(self.inner)
    }

    /// Get a reference to the underlying API client.
    #[must_use]
    pub const fn api_client(&self) -> &DiscordApiClient {
        &self.inner
    }
}

impl Deref for DiscordClient {
    type Target = DiscordApiClient;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl fmt::Debug for DiscordClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DiscordClient")
            .field("base_url", &self.base_url)
            .field("bot_credential", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DiscordConfig;

    fn test_config_with_url(url: &str) -> DiscordConfig {
        DiscordConfig {
            bot_credential: "super_secret_bot_token_12345".into(),
            api_url: url.into(),
            ..Default::default()
        }
    }

    // ── Construction ─────────────────────────────────────────────

    #[test]
    fn from_config_succeeds() {
        let config = test_config_with_url("https://discord.com/api/v10");
        let client = DiscordClient::from_config(&config);
        assert!(client.is_ok());
    }

    #[test]
    fn from_config_preserves_base_url() {
        let config = test_config_with_url("https://discord.com/api/v10");
        let client = DiscordClient::from_config(&config).unwrap();
        assert_eq!(client.base_url, "https://discord.com/api/v10");
    }

    // ── Debug redaction ──────────────────────────────────────────

    #[test]
    fn debug_redacts_bot_credential() {
        let config = test_config_with_url("https://discord.com/api/v10");
        let client = DiscordClient::from_config(&config).unwrap();
        let debug_output = format!("{client:?}");

        assert!(
            !debug_output.contains("super_secret_bot_token_12345"),
            "bot credential must not appear in Debug output, got: {debug_output}"
        );
        assert!(
            debug_output.contains("[REDACTED]"),
            "Debug output should contain [REDACTED], got: {debug_output}"
        );
    }

    #[test]
    fn debug_shows_base_url() {
        let config = test_config_with_url("https://discord.com/api/v10");
        let client = DiscordClient::from_config(&config).unwrap();
        let debug_output = format!("{client:?}");

        assert!(
            debug_output.contains("discord.com"),
            "Debug output should show base URL, got: {debug_output}"
        );
    }

    #[test]
    fn debug_shows_struct_name() {
        let config = test_config_with_url("https://discord.com/api/v10");
        let client = DiscordClient::from_config(&config).unwrap();
        let debug_output = format!("{client:?}");

        assert!(
            debug_output.contains("DiscordClient"),
            "Debug output should show struct name, got: {debug_output}"
        );
    }

    // ── Deref to DiscordApiClient ────────────────────────────────

    #[test]
    fn deref_provides_api_client_access() {
        let config = test_config_with_url("https://discord.com/api/v10");
        let client = DiscordClient::from_config(&config).unwrap();
        // Deref should give us a reference to DiscordApiClient.
        // We verify by checking that api_client() and deref() return the same pointer.
        let via_deref: *const DiscordApiClient = &*client;
        let via_method: *const DiscordApiClient = client.api_client();
        assert_eq!(via_deref, via_method);
    }

    // ── into_api_client ──────────────────────────────────────────

    #[test]
    fn into_api_client_returns_arc() {
        let config = test_config_with_url("https://discord.com/api/v10");
        let client = DiscordClient::from_config(&config).unwrap();
        let arc: Arc<DiscordApiClient> = client.into_api_client();
        // Verify the Arc is valid by checking strong_count
        assert_eq!(Arc::strong_count(&arc), 1);
    }

    // ── Credential isolation ─────────────────────────────────────

    #[test]
    fn different_credentials_produce_different_clients() {
        let config1 = DiscordConfig {
            bot_credential: "token_alpha".into(),
            api_url: "https://discord.com/api/v10".into(),
            ..Default::default()
        };
        let config2 = DiscordConfig {
            bot_credential: "token_beta".into(),
            api_url: "https://discord.com/api/v10".into(),
            ..Default::default()
        };

        let client1 = DiscordClient::from_config(&config1).unwrap();
        let client2 = DiscordClient::from_config(&config2).unwrap();

        // Both should redact identically in Debug
        let dbg1 = format!("{client1:?}");
        let dbg2 = format!("{client2:?}");
        assert_eq!(
            dbg1, dbg2,
            "Debug output should be identical regardless of credential"
        );
        assert!(!dbg1.contains("token_alpha"));
        assert!(!dbg2.contains("token_beta"));
    }

    // ── Integration: wiremock round-trip via Deref ────────────────

    #[fcp_async_core::runtime::test]
    async fn deref_allows_api_calls() {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{header, method, path},
        };

        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/users/@me"))
            .and(header("Authorization", "Bot test_deref_token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "999",
                "username": "DerefBot",
                "bot": true
            })))
            .mount(&mock_server)
            .await;

        let config = DiscordConfig {
            bot_credential: "test_deref_token".into(),
            api_url: mock_server.uri(),
            retry: crate::config::RetryConfig {
                max_attempts: 1,
                initial_delay_ms: 10,
                max_delay_ms: 100,
                jitter: 0.0,
            },
            ..Default::default()
        };
        let client = DiscordClient::from_config(&config).unwrap();

        // Call API method via Deref
        let user = client.get_current_user().await.unwrap();
        assert_eq!(user.id, "999");
        assert_eq!(user.username, "DerefBot");
        assert!(user.bot);
    }

    #[fcp_async_core::runtime::test]
    async fn into_api_client_preserves_functionality() {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{header, method, path},
        };

        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/users/@me"))
            .and(header("Authorization", "Bot arc_token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "888",
                "username": "ArcBot",
                "bot": true
            })))
            .mount(&mock_server)
            .await;

        let config = DiscordConfig {
            bot_credential: "arc_token".into(),
            api_url: mock_server.uri(),
            retry: crate::config::RetryConfig {
                max_attempts: 1,
                initial_delay_ms: 10,
                max_delay_ms: 100,
                jitter: 0.0,
            },
            ..Default::default()
        };
        let client = DiscordClient::from_config(&config).unwrap();
        let arc_client = client.into_api_client();

        let user = arc_client.get_current_user().await.unwrap();
        assert_eq!(user.id, "888");
        assert_eq!(user.username, "ArcBot");
    }
}
