//! Discord REST API client.

use std::time::Duration;

use reqwest::{Client, Response, StatusCode};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tracing::{debug, instrument, warn};

use crate::{
    config::DiscordConfig,
    error::{DiscordError, DiscordResult},
    types::{Channel, Guild, Message, User},
};

/// Discord REST API client.
#[derive(Debug, Clone)]
pub struct DiscordApiClient {
    client: Client,
    base_url: String,
    bot_credential: String,
    max_retries: u32,
    initial_delay_ms: u64,
    max_delay_ms: u64,
}

impl DiscordApiClient {
    /// Create a new API client from configuration.
    pub fn new(config: &DiscordConfig) -> DiscordResult<Self> {
        let client = Client::builder()
            .timeout(config.timeout)
            .user_agent(format!("fcp-discord/{}", env!("CARGO_PKG_VERSION")))
            .build()?;

        // Normalize credential (remove "Bot " prefix if present)
        let bot_credential = config
            .bot_credential
            .strip_prefix("Bot ")
            .unwrap_or(&config.bot_credential)
            .to_string();

        Ok(Self {
            client,
            base_url: config.api_url.trim_end_matches('/').to_string(),
            bot_credential,
            max_retries: config.retry.max_attempts,
            initial_delay_ms: config.retry.initial_delay_ms,
            max_delay_ms: config.retry.max_delay_ms,
        })
    }

    /// Make a GET request.
    #[instrument(skip(self))]
    pub async fn get<T: DeserializeOwned>(&self, endpoint: &str) -> DiscordResult<T> {
        self.request("GET", endpoint, None::<&()>).await
    }

    /// Make a POST request.
    #[instrument(skip(self, body))]
    pub async fn post<T: DeserializeOwned, B: Serialize>(
        &self,
        endpoint: &str,
        body: &B,
    ) -> DiscordResult<T> {
        self.request("POST", endpoint, Some(body)).await
    }

    /// Make a PATCH request.
    #[instrument(skip(self, body))]
    pub async fn patch<T: DeserializeOwned, B: Serialize>(
        &self,
        endpoint: &str,
        body: &B,
    ) -> DiscordResult<T> {
        self.request("PATCH", endpoint, Some(body)).await
    }

    /// Make a DELETE request.
    #[instrument(skip(self))]
    pub async fn delete(&self, endpoint: &str) -> DiscordResult<()> {
        self.request_no_response("DELETE", endpoint).await
    }

    /// Make a request that expects no response body (e.g., DELETE returning 204).
    async fn request_no_response(&self, method: &str, endpoint: &str) -> DiscordResult<()> {
        let url = format!("{}{}", self.base_url, endpoint);
        let mut delay = Duration::from_millis(self.initial_delay_ms);
        let mut attempts = 0;

        loop {
            attempts += 1;
            debug!(
                attempt = attempts,
                method, endpoint, "Making Discord API request (no response expected)"
            );

            let req = match method {
                "DELETE" => self.client.delete(&url),
                "POST" => self.client.post(&url),
                _ => self.client.get(&url),
            };

            let req = req.header("Authorization", format!("Bot {}", self.bot_credential));
            let result = req.send().await;

            match result {
                Ok(response) => {
                    #[derive(Deserialize)]
                    struct DiscordApiError {
                        code: Option<i32>,
                        message: Option<String>,
                    }

                    let status = response.status();

                    // Handle rate limiting
                    if status == StatusCode::TOO_MANY_REQUESTS {
                        let retry_after = response
                            .headers()
                            .get("retry-after")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.parse::<f64>().ok())
                            .unwrap_or(30.0);

                        if attempts < self.max_retries {
                            delay = Duration::from_secs_f64(retry_after);
                            warn!(
                                attempt = attempts,
                                delay_ms = delay.as_millis(),
                                "Rate limited, retrying"
                            );
                            tokio::time::sleep(delay).await;
                            continue;
                        }
                        return Err(DiscordError::RateLimited { retry_after });
                    }

                    if status.is_success() {
                        return Ok(());
                    }

                    // Try to parse error from body
                    let bytes = response.bytes().await?;
                    let error: DiscordApiError =
                        serde_json::from_slice(&bytes).unwrap_or_else(|_| DiscordApiError {
                            code: Some(i32::from(status.as_u16())),
                            message: Some(String::from_utf8_lossy(&bytes).into_owned()),
                        });

                    let err = DiscordError::Api {
                        code: error.code.unwrap_or_else(|| i32::from(status.as_u16())),
                        message: error.message.unwrap_or_else(|| "Unknown error".into()),
                        retry_after: None,
                    };

                    if err.is_retryable() && attempts < self.max_retries {
                        warn!(attempt = attempts, delay_ms = delay.as_millis(), error = %err, "Retrying");
                        tokio::time::sleep(delay).await;
                        delay = std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
                        continue;
                    }
                    return Err(err);
                }
                Err(e) if e.is_timeout() || e.is_connect() => {
                    if attempts < self.max_retries {
                        warn!(attempt = attempts, delay_ms = delay.as_millis(), error = %e, "Retrying after connection error");
                        tokio::time::sleep(delay).await;
                        delay = std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
                    } else {
                        return Err(DiscordError::Http(e));
                    }
                }
                Err(e) => return Err(DiscordError::Http(e)),
            }
        }
    }

    async fn request<T: DeserializeOwned, B: Serialize>(
        &self,
        method: &str,
        endpoint: &str,
        body: Option<&B>,
    ) -> DiscordResult<T> {
        let url = format!("{}{}", self.base_url, endpoint);
        let mut delay = Duration::from_millis(self.initial_delay_ms);
        let mut attempts = 0;

        loop {
            attempts += 1;
            debug!(
                attempt = attempts,
                method, endpoint, "Making Discord API request"
            );

            let mut req = match method {
                "GET" => self.client.get(&url),
                "POST" => self.client.post(&url),
                "PATCH" => self.client.patch(&url),
                "DELETE" => self.client.delete(&url),
                _ => self.client.get(&url),
            };

            req = req.header("Authorization", format!("Bot {}", self.bot_credential));

            if let Some(b) = body {
                req = req.json(b);
            }

            let result = req.send().await;

            match result {
                Ok(response) => match self.handle_response(response).await {
                    Ok(data) => return Ok(data),
                    Err(e) if e.is_retryable() && attempts < self.max_retries => {
                        if let Some(retry_after) = e.retry_after() {
                            delay = retry_after;
                        }
                        warn!(
                            attempt = attempts,
                            delay_ms = delay.as_millis(),
                            error = %e,
                            "Retrying Discord API request"
                        );
                        tokio::time::sleep(delay).await;
                        delay = std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
                    }
                    Err(e) => return Err(e),
                },
                Err(e) if e.is_timeout() || e.is_connect() => {
                    if attempts < self.max_retries {
                        warn!(
                            attempt = attempts,
                            delay_ms = delay.as_millis(),
                            error = %e,
                            "Retrying after connection error"
                        );
                        tokio::time::sleep(delay).await;
                        delay = std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
                    } else {
                        return Err(DiscordError::Http(e));
                    }
                }
                Err(e) => return Err(DiscordError::Http(e)),
            }
        }
    }

    async fn handle_response<T: DeserializeOwned>(&self, response: Response) -> DiscordResult<T> {
        let status = response.status();

        // Handle rate limiting
        if status == StatusCode::TOO_MANY_REQUESTS {
            let retry_after = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<f64>().ok())
                .unwrap_or(30.0);

            return Err(DiscordError::RateLimited { retry_after });
        }

        let bytes = response.bytes().await?;

        if status.is_success() {
            serde_json::from_slice(&bytes).map_err(DiscordError::from)
        } else {
            // Try to parse Discord error
            #[derive(Deserialize)]
            struct DiscordApiError {
                code: Option<i32>,
                message: Option<String>,
                retry_after: Option<f64>,
            }

            let error: DiscordApiError =
                serde_json::from_slice(&bytes).unwrap_or_else(|_| DiscordApiError {
                    code: Some(i32::from(status.as_u16())),
                    message: Some(String::from_utf8_lossy(&bytes).into_owned()),
                    retry_after: None,
                });

            Err(DiscordError::Api {
                code: error.code.unwrap_or_else(|| i32::from(status.as_u16())),
                message: error.message.unwrap_or_else(|| "Unknown error".into()),
                retry_after: error.retry_after,
            })
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // User endpoints
    // ─────────────────────────────────────────────────────────────────────────

    /// Get the current bot user.
    pub async fn get_current_user(&self) -> DiscordResult<User> {
        self.get("/users/@me").await
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Channel endpoints
    // ─────────────────────────────────────────────────────────────────────────

    /// Get a channel by ID.
    pub async fn get_channel(&self, channel_id: &str) -> DiscordResult<Channel> {
        self.get(&format!("/channels/{channel_id}")).await
    }

    /// Create a message in a channel.
    pub async fn create_message(
        &self,
        channel_id: &str,
        content: Option<&str>,
        embeds: Option<Vec<crate::types::Embed>>,
        reply_to: Option<&str>,
    ) -> DiscordResult<Message> {
        #[derive(Serialize)]
        struct CreateMessageRequest<'a> {
            #[serde(skip_serializing_if = "Option::is_none")]
            content: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            embeds: Option<Vec<crate::types::Embed>>,
            #[serde(skip_serializing_if = "Option::is_none")]
            message_reference: Option<MessageReference<'a>>,
        }

        #[derive(Serialize)]
        struct MessageReference<'a> {
            message_id: &'a str,
        }

        let request = CreateMessageRequest {
            content,
            embeds,
            message_reference: reply_to.map(|id| MessageReference { message_id: id }),
        };

        self.post(&format!("/channels/{channel_id}/messages"), &request)
            .await
    }

    /// Edit a message.
    pub async fn edit_message(
        &self,
        channel_id: &str,
        message_id: &str,
        content: Option<&str>,
        embeds: Option<Vec<crate::types::Embed>>,
    ) -> DiscordResult<Message> {
        #[derive(Serialize)]
        struct EditMessageRequest<'a> {
            #[serde(skip_serializing_if = "Option::is_none")]
            content: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            embeds: Option<Vec<crate::types::Embed>>,
        }

        self.patch(
            &format!("/channels/{channel_id}/messages/{message_id}"),
            &EditMessageRequest { content, embeds },
        )
        .await
    }

    /// Delete a message.
    pub async fn delete_message(&self, channel_id: &str, message_id: &str) -> DiscordResult<()> {
        self.delete(&format!("/channels/{channel_id}/messages/{message_id}"))
            .await
    }

    /// Trigger typing indicator.
    pub async fn trigger_typing(&self, channel_id: &str) -> DiscordResult<()> {
        let _: serde_json::Value = self
            .post(
                &format!("/channels/{channel_id}/typing"),
                &serde_json::json!({}),
            )
            .await?;
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Guild endpoints
    // ─────────────────────────────────────────────────────────────────────────

    /// Get a guild by ID.
    pub async fn get_guild(&self, guild_id: &str) -> DiscordResult<Guild> {
        self.get(&format!("/guilds/{guild_id}")).await
    }

    /// Get guild channels.
    pub async fn get_guild_channels(&self, guild_id: &str) -> DiscordResult<Vec<Channel>> {
        self.get(&format!("/guilds/{guild_id}/channels")).await
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Gateway
    // ─────────────────────────────────────────────────────────────────────────

    /// Get the gateway URL.
    pub async fn get_gateway(&self) -> DiscordResult<String> {
        #[derive(Deserialize)]
        struct GatewayResponse {
            url: String,
        }

        let resp: GatewayResponse = self.get("/gateway/bot").await?;
        Ok(resp.url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_testkit::LogCapture;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path},
    };

    /// Create a test config pointing to the mock server.
    fn test_config(mock_server: &MockServer) -> DiscordConfig {
        DiscordConfig {
            bot_credential: "test_token_12345".into(),
            api_url: mock_server.uri(),
            retry: crate::config::RetryConfig {
                max_attempts: 1,
                initial_delay_ms: 10,
                max_delay_ms: 100,
                jitter: 0.0,
            },
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_get_current_user_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/users/@me"))
            .and(header("Authorization", "Bot test_token_12345"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "123456789",
                "username": "TestBot",
                "discriminator": "0",
                "bot": true
            })))
            .mount(&mock_server)
            .await;

        let config = test_config(&mock_server);
        let client = DiscordApiClient::new(&config).unwrap();

        let user = client.get_current_user().await.unwrap();
        assert_eq!(user.id, "123456789");
        assert_eq!(user.username, "TestBot");
        assert!(user.bot);
    }

    #[tokio::test]
    async fn test_get_current_user_unauthorized() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/users/@me"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "code": 0,
                "message": "401: Unauthorized"
            })))
            .mount(&mock_server)
            .await;

        let config = test_config(&mock_server);
        let client = DiscordApiClient::new(&config).unwrap();

        let result = client.get_current_user().await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, DiscordError::Api { .. }));
    }

    #[tokio::test]
    async fn test_create_message_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/channels/987654321/messages"))
            .and(header("Authorization", "Bot test_token_12345"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "111222333",
                "channel_id": "987654321",
                "content": "Hello, world!",
                "timestamp": "2024-01-01T00:00:00.000000+00:00",
                "tts": false,
                "mention_everyone": false,
                "attachments": [],
                "embeds": []
            })))
            .mount(&mock_server)
            .await;

        let config = test_config(&mock_server);
        let client = DiscordApiClient::new(&config).unwrap();

        let message = client
            .create_message("987654321", Some("Hello, world!"), None, None)
            .await
            .unwrap();

        assert_eq!(message.id, "111222333");
        assert_eq!(message.channel_id, "987654321");
        assert_eq!(message.content, "Hello, world!");
    }

    #[tokio::test]
    async fn test_create_message_with_embed() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/channels/987654321/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "111222333",
                "channel_id": "987654321",
                "content": "",
                "timestamp": "2024-01-01T00:00:00.000000+00:00",
                "tts": false,
                "mention_everyone": false,
                "attachments": [],
                "embeds": [{
                    "title": "Test Embed",
                    "description": "This is a test embed",
                    "color": 16711680
                }]
            })))
            .mount(&mock_server)
            .await;

        let config = test_config(&mock_server);
        let client = DiscordApiClient::new(&config).unwrap();

        let embed = crate::types::Embed {
            title: Some("Test Embed".into()),
            description: Some("This is a test embed".into()),
            color: Some(0xFF0000),
            ..Default::default()
        };

        let message = client
            .create_message("987654321", None, Some(vec![embed]), None)
            .await
            .unwrap();

        assert_eq!(message.embeds.len(), 1);
        assert_eq!(message.embeds[0].title.as_deref(), Some("Test Embed"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_logs_redact_token_and_body() {
        let capture = LogCapture::new();
        let _guard = capture.install_json_with_filter("debug");
        tracing::debug!("log_capture_ready");

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/channels/123/messages"))
            .and(header("Authorization", "Bot test_token_12345"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "111222333",
                "channel_id": "123",
                "content": "ok",
                "timestamp": "2024-01-01T00:00:00.000000+00:00",
                "tts": false,
                "mention_everyone": false,
                "attachments": [],
                "embeds": []
            })))
            .mount(&mock_server)
            .await;

        let config = test_config(&mock_server);
        let client = DiscordApiClient::new(&config).unwrap();
        let secret_body = "TopSecretMessage";
        let _ = client
            .create_message("123", Some(secret_body), None, None)
            .await
            .unwrap();

        let logs = capture.jsonl();
        assert!(
            logs.contains("log_capture_ready"),
            "expected debug logs to be captured"
        );
        assert!(
            !logs.contains(&config.bot_credential),
            "bot token should not appear in logs"
        );
        assert!(
            !logs.contains(secret_body),
            "message body should not appear in logs"
        );
    }

    #[tokio::test]
    async fn test_get_channel_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/channels/987654321"))
            .and(header("Authorization", "Bot test_token_12345"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "987654321",
                "type": 0,
                "guild_id": "111111111",
                "name": "general",
                "topic": "General discussion"
            })))
            .mount(&mock_server)
            .await;

        let config = test_config(&mock_server);
        let client = DiscordApiClient::new(&config).unwrap();

        let channel = client.get_channel("987654321").await.unwrap();
        assert_eq!(channel.id, "987654321");
        assert_eq!(channel.name.as_deref(), Some("general"));
        assert_eq!(channel.channel_type, 0);
    }

    #[tokio::test]
    async fn test_get_guild_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/guilds/111111111"))
            .and(header("Authorization", "Bot test_token_12345"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "111111111",
                "name": "Test Server",
                "icon": "abc123",
                "owner_id": "222222222"
            })))
            .mount(&mock_server)
            .await;

        let config = test_config(&mock_server);
        let client = DiscordApiClient::new(&config).unwrap();

        let guild = client.get_guild("111111111").await.unwrap();
        assert_eq!(guild.id, "111111111");
        assert_eq!(guild.name, "Test Server");
        assert_eq!(guild.owner_id.as_deref(), Some("222222222"));
    }

    #[tokio::test]
    async fn test_get_gateway_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/gateway/bot"))
            .and(header("Authorization", "Bot test_token_12345"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "url": "wss://gateway.discord.gg",
                "shards": 1,
                "session_start_limit": {
                    "total": 1000,
                    "remaining": 999,
                    "reset_after": 14400000,
                    "max_concurrency": 1
                }
            })))
            .mount(&mock_server)
            .await;

        let config = test_config(&mock_server);
        let client = DiscordApiClient::new(&config).unwrap();

        let gateway_url = client.get_gateway().await.unwrap();
        assert_eq!(gateway_url, "wss://gateway.discord.gg");
    }

    #[tokio::test]
    async fn test_rate_limited() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/users/@me"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("retry-after", "5")
                    .set_body_json(serde_json::json!({
                        "message": "You are being rate limited.",
                        "retry_after": 5.0,
                        "global": false
                    })),
            )
            .mount(&mock_server)
            .await;

        let config = test_config(&mock_server);
        let client = DiscordApiClient::new(&config).unwrap();

        let result = client.get_current_user().await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, DiscordError::RateLimited { retry_after } if retry_after == 5.0));
    }

    #[tokio::test]
    async fn test_delete_message_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("DELETE"))
            .and(path("/channels/987654321/messages/111222333"))
            .and(header("Authorization", "Bot test_token_12345"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&mock_server)
            .await;

        let config = test_config(&mock_server);
        let client = DiscordApiClient::new(&config).unwrap();

        let result = client.delete_message("987654321", "111222333").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_bot_credential_normalization() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/users/@me"))
            .and(header("Authorization", "Bot actual_token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "123",
                "username": "Bot",
                "bot": true
            })))
            .mount(&mock_server)
            .await;

        // Test that "Bot " prefix is stripped
        let config = DiscordConfig {
            bot_credential: "Bot actual_token".into(),
            api_url: mock_server.uri(),
            ..Default::default()
        };
        let client = DiscordApiClient::new(&config).unwrap();

        let user = client.get_current_user().await.unwrap();
        assert_eq!(user.id, "123");
    }

    #[tokio::test]
    async fn test_error_is_retryable() {
        // 429 is retryable
        let rate_limited = DiscordError::RateLimited { retry_after: 5.0 };
        assert!(rate_limited.is_retryable());

        // 500 is retryable
        let server_error = DiscordError::Api {
            code: 500,
            message: "Internal Server Error".into(),
            retry_after: None,
        };
        assert!(server_error.is_retryable());

        // 401 is not retryable
        let unauthorized = DiscordError::Api {
            code: 401,
            message: "Unauthorized".into(),
            retry_after: None,
        };
        assert!(!unauthorized.is_retryable());

        // 404 is not retryable
        let not_found = DiscordError::Api {
            code: 404,
            message: "Not Found".into(),
            retry_after: None,
        };
        assert!(!not_found.is_retryable());
    }

    #[tokio::test]
    async fn test_error_retry_after() {
        let rate_limited = DiscordError::RateLimited { retry_after: 5.0 };
        assert_eq!(
            rate_limited.retry_after(),
            Some(Duration::from_secs_f64(5.0))
        );

        let api_error_with_retry = DiscordError::Api {
            code: 429,
            message: "Rate limited".into(),
            retry_after: Some(10.0),
        };
        assert_eq!(
            api_error_with_retry.retry_after(),
            Some(Duration::from_secs_f64(10.0))
        );

        let api_error_no_retry = DiscordError::Api {
            code: 404,
            message: "Not Found".into(),
            retry_after: None,
        };
        assert_eq!(api_error_no_retry.retry_after(), None);
    }
}
