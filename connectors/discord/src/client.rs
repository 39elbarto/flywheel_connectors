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
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration as StdDuration, Instant as StdInstant};

    struct TestHttpResponse {
        method: &'static str,
        path: &'static str,
        status: u16,
        body: serde_json::Value,
        required_headers: Vec<(&'static str, &'static str)>,
    }

    struct TestHttpServer {
        url: String,
        handle: Option<JoinHandle<()>>,
    }

    impl TestHttpResponse {
        fn json(
            method: &'static str,
            path: &'static str,
            status: u16,
            body: serde_json::Value,
        ) -> Self {
            Self {
                method,
                path,
                status,
                body,
                required_headers: Vec::new(),
            }
        }

        fn with_required_header(mut self, name: &'static str, value: &'static str) -> Self {
            self.required_headers.push((name, value));
            self
        }
    }

    impl TestHttpServer {
        fn respond(responses: Vec<TestHttpResponse>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let handle = thread::spawn(move || {
                listener.set_nonblocking(true).unwrap();
                for response in responses {
                    let stream = accept_test_connection(&listener);
                    handle_test_request(stream, &response);
                }
            });
            Self {
                url,
                handle: Some(handle),
            }
        }

        fn uri(&self) -> &str {
            &self.url
        }
    }

    impl Drop for TestHttpServer {
        fn drop(&mut self) {
            if let Some(handle) = self.handle.take() {
                if thread::panicking() {
                    let _ = handle.join();
                } else {
                    handle.join().unwrap();
                }
            }
        }
    }

    fn accept_test_connection(listener: &TcpListener) -> TcpStream {
        let deadline = StdInstant::now() + StdDuration::from_secs(5);
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    return stream;
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        StdInstant::now() < deadline,
                        "test server did not receive expected request"
                    );
                    thread::sleep(StdDuration::from_millis(10));
                }
                Err(err) => panic!("test listener failed: {err}"),
            }
        }
    }

    fn handle_test_request(stream: TcpStream, response: &TestHttpResponse) {
        stream
            .set_read_timeout(Some(StdDuration::from_secs(2)))
            .unwrap();
        let mut reader = BufReader::new(stream);
        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();
        let mut request_parts = request_line.split_whitespace();
        assert_eq!(request_parts.next(), Some(response.method));
        let actual_path = request_parts
            .next()
            .and_then(|path| path.split('?').next())
            .unwrap_or_default();
        assert_eq!(actual_path, response.path);

        let mut content_length = 0usize;
        let mut required_headers_seen = vec![false; response.required_headers.len()];
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let trimmed = line.trim_end_matches(['\r', '\n']);
            if trimmed.is_empty() {
                break;
            }
            if let Some((name, value)) = trimmed.split_once(':') {
                if name.eq_ignore_ascii_case("content-length") {
                    content_length = value.trim().parse().unwrap();
                }
                for (index, (required_name, required_value)) in
                    response.required_headers.iter().enumerate()
                {
                    if name.eq_ignore_ascii_case(required_name) && value.trim() == *required_value {
                        required_headers_seen[index] = true;
                    }
                }
            }
        }
        assert!(
            required_headers_seen.into_iter().all(|seen| seen),
            "required header was not sent"
        );
        if content_length > 0 {
            let mut request_body = vec![0u8; content_length];
            reader.read_exact(&mut request_body).unwrap();
        }

        let mut stream = reader.into_inner();
        let body = response.body.to_string();
        write!(
            stream,
            "HTTP/1.1 {} OK\r\ncontent-length: {}\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n{body}",
            response.status,
            body.len()
        )
        .unwrap();
        stream.flush().unwrap();
    }

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
        let via_deref: *const DiscordApiClient = &raw const *client;
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

    // ── Integration: HTTP round-trip via Deref ───────────────────

    #[fcp_async_core::runtime::test]
    async fn deref_allows_api_calls() {
        let server = TestHttpServer::respond(vec![
            TestHttpResponse::json(
                "GET",
                "/users/@me",
                200,
                serde_json::json!({
                "id": "999",
                "username": "DerefBot",
                "bot": true
                }),
            )
            .with_required_header("Authorization", "Bot test_deref_token"),
        ]);

        let config = DiscordConfig {
            bot_credential: "test_deref_token".into(),
            api_url: server.uri().into(),
            retry: crate::config::RetryConfig {
                max_attempts: 0,
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
        let server = TestHttpServer::respond(vec![
            TestHttpResponse::json(
                "GET",
                "/users/@me",
                200,
                serde_json::json!({
                "id": "888",
                "username": "ArcBot",
                "bot": true
                }),
            )
            .with_required_header("Authorization", "Bot arc_token"),
        ]);

        let config = DiscordConfig {
            bot_credential: "arc_token".into(),
            api_url: server.uri().into(),
            retry: crate::config::RetryConfig {
                max_attempts: 0,
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
