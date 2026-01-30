//! Telegram Bot API client.
//!
//! Implements the core Telegram Bot API methods using reqwest.
//! Based on patterns from clawdbot's Telegram integration.

use std::time::Duration;

use reqwest::{Client, StatusCode};
use serde::{Serialize, de::DeserializeOwned};
use tracing::{instrument, warn};

use crate::types::*;

/// Telegram Bot API client.
#[derive(Debug, Clone)]
pub struct TelegramClient {
    credential: String,
    client: Client,
    base_url: String,
}

impl TelegramClient {
    /// Create a new Telegram client.
    ///
    /// # Errors
    /// Returns an error if the HTTP client fails to build.
    pub fn new(credential: impl Into<String>) -> Result<Self, TelegramError> {
        let bot_credential = credential.into();
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(TelegramError::Http)?;

        Ok(Self {
            credential: bot_credential,
            client,
            base_url: "https://api.telegram.org".into(),
        })
    }

    /// Set a custom base URL.
    #[must_use]
    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
        self
    }

    /// Build the API URL for a method.
    fn api_url(&self, method: &str) -> String {
        format!("{}/bot{}/{}", self.base_url, self.credential, method)
    }

    /// Execute a request with retries.
    async fn request<T, B>(
        &self,
        method: &str,
        endpoint: &str,
        body: Option<&B>,
        timeout: Option<Duration>,
    ) -> Result<T, TelegramError>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        let url = self.api_url(endpoint);
        let mut attempts = 0;
        let max_retries = 3;
        let mut delay = Duration::from_millis(100);

        loop {
            attempts += 1;
            let mut req = match method {
                "POST" => self.client.post(&url),
                _ => self.client.get(&url),
            };

            if let Some(b) = body {
                req = req.json(b);
            }

            if let Some(t) = timeout {
                req = req.timeout(t);
            }

            let result = req.send().await;

            match result {
                Ok(response) => {
                    let status = response.status();

                    if status == StatusCode::TOO_MANY_REQUESTS {
                        let retry_after = response
                            .headers()
                            .get("retry-after")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.parse::<u64>().ok())
                            .unwrap_or(5);

                        if attempts < max_retries {
                            let wait = Duration::from_secs(retry_after);
                            warn!(
                                attempt = attempts,
                                wait_secs = retry_after,
                                "Rate limited, retrying"
                            );
                            tokio::time::sleep(wait).await;
                            continue;
                        }
                    }

                    // Telegram returns 200 even for logical errors, but check for HTTP errors anyway
                    if status.is_server_error() {
                        if attempts < max_retries {
                            warn!(attempt = attempts, status = %status, "Server error, retrying");
                            tokio::time::sleep(delay).await;
                            delay *= 2;
                            continue;
                        }
                    }

                    // Parse the Telegram response wrapper
                    let tg_response: TelegramResponse<T> = response.json().await?;

                    if tg_response.ok {
                        return tg_response.result.ok_or_else(|| TelegramError::Api {
                            code: 0,
                            description: "Empty result".into(),
                        });
                    }

                    // Handle logical API errors
                    let err = TelegramError::Api {
                        code: tg_response.error_code.unwrap_or(0),
                        description: tg_response.description.clone().unwrap_or_default(),
                    };

                    // Retry on 429 or 5xx equivalents in logical errors if applicable
                    if err.is_retryable() && attempts < max_retries {
                        warn!(attempt = attempts, error = %err, "Retryable API error");
                        tokio::time::sleep(delay).await;
                        delay *= 2;
                        continue;
                    }

                    return Err(err);
                }
                Err(e) => {
                    if (e.is_timeout() || e.is_connect()) && attempts < max_retries {
                        warn!(attempt = attempts, error = %e, "Connection error, retrying");
                        tokio::time::sleep(delay).await;
                        delay *= 2;
                        continue;
                    }
                    return Err(TelegramError::Http(e));
                }
            }
        }
    }

    /// Get bot information.
    #[instrument(skip(self))]
    pub async fn get_me(&self) -> Result<BotInfo, TelegramError> {
        self.request("GET", "getMe", None::<&()>, None).await
    }

    /// Get updates using long polling.
    #[instrument(skip(self))]
    pub async fn get_updates(
        &self,
        request: GetUpdatesRequest,
    ) -> Result<Vec<Update>, TelegramError> {
        let timeout =
            Duration::from_secs(u64::try_from(request.timeout.unwrap_or(30)).unwrap_or(30) + 10);
        // Default to empty vec if result is missing but ok is true (though request handles that)
        self.request("POST", "getUpdates", Some(&request), Some(timeout))
            .await
            .map(|opt: Vec<Update>| opt)
    }

    /// Send a text message.
    #[instrument(skip_all)]
    pub async fn send_message(
        &self,
        chat_id: impl Into<String>,
        text: impl Into<String>,
        options: SendMessageOptions,
    ) -> Result<Message, TelegramError> {
        let request = SendMessageRequest {
            chat_id: normalize_chat_id(&chat_id.into())?,
            text: text.into(),
            parse_mode: options.parse_mode,
            reply_to_message_id: options.reply_to_message_id,
            message_thread_id: options.message_thread_id,
        };

        self.request("POST", "sendMessage", Some(&request), None)
            .await
    }

    /// Get file information for downloading.
    #[instrument(skip_all)]
    pub async fn get_file(&self, file_id: impl Into<String>) -> Result<File, TelegramError> {
        let file_id = file_id.into();
        // getFile uses query params, but our request helper expects JSON body for POST or no body for GET.
        // reqwest GET with body is technically allowed but getFile supports query params.
        // We can just construct the URL with query params.
        // Or cleaner: make request() support query params?
        // Simpler: Just manual impl for get_file or change request() to take an enum for body/query.
        // Let's manually invoke client for get_file to keep request() simple for JSON-RPC style calls.
        let url = self.api_url("getFile");
        let response: TelegramResponse<File> = self
            .client
            .get(&url)
            .query(&[("file_id", &file_id)])
            .send()
            .await?
            .json()
            .await?;

        if response.ok {
            response.result.ok_or_else(|| TelegramError::Api {
                code: 0,
                description: "Empty result".into(),
            })
        } else {
            Err(TelegramError::Api {
                code: response.error_code.unwrap_or(0),
                description: response.description.unwrap_or_default(),
            })
        }
    }

    /// Download a file by its path.
    pub fn file_download_url(&self, file_path: &str) -> String {
        format!(
            "{}/file/bot{}/{}",
            self.base_url, self.credential, file_path
        )
    }

    /// Answer a callback query (acknowledge button press).
    #[instrument(skip_all)]
    pub async fn answer_callback_query(
        &self,
        callback_query_id: impl Into<String>,
        text: Option<&str>,
    ) -> Result<bool, TelegramError> {
        // answerCallbackQuery is POST with JSON (or form)
        #[derive(Serialize)]
        struct AnswerCallbackQueryRequest<'a> {
            callback_query_id: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            text: Option<&'a str>,
        }

        let request = AnswerCallbackQueryRequest {
            callback_query_id: callback_query_id.into(),
            text,
        };

        self.request("POST", "answerCallbackQuery", Some(&request), None)
            .await
    }
}

/// Options for sending messages.
#[derive(Debug, Default, Clone)]
pub struct SendMessageOptions {
    pub parse_mode: Option<String>,
    pub reply_to_message_id: Option<i64>,
    pub message_thread_id: Option<i64>,
}

#[allow(dead_code)] // Helper methods for future use
impl SendMessageOptions {
    /// Set parse mode to HTML.
    #[must_use]
    pub fn html(mut self) -> Self {
        self.parse_mode = Some("HTML".into());
        self
    }

    /// Set parse mode to MarkdownV2.
    #[must_use]
    pub fn markdown_v2(mut self) -> Self {
        self.parse_mode = Some("MarkdownV2".into());
        self
    }

    /// Set reply to a specific message.
    #[must_use]
    pub fn reply_to_message_id(mut self, id: i64) -> Self {
        self.reply_to_message_id = Some(id);
        self
    }
}

/// Telegram API errors.
#[derive(Debug, thiserror::Error)]
pub enum TelegramError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Telegram API error ({code}): {description}")]
    Api { code: i32, description: String },

    #[error("Invalid chat ID: {0}")]
    InvalidChatId(String),
}

impl TelegramError {
    /// Check if this error is retryable.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http(e) => e.is_timeout() || e.is_connect(),
            Self::Api { code, .. } => {
                // 429 = rate limited, 500+ = server errors
                *code == 429 || *code >= 500
            }
            Self::InvalidChatId(_) => false,
        }
    }
}

/// Normalize chat ID, handling various formats.
fn normalize_chat_id(id: &str) -> Result<String, TelegramError> {
    let trimmed = id.trim();
    if trimmed.is_empty() {
        return Err(TelegramError::InvalidChatId("Empty chat ID".into()));
    }

    // Strip common prefixes
    let normalized = trimmed
        .strip_prefix("telegram:")
        .or_else(|| trimmed.strip_prefix("tg:"))
        .unwrap_or(trimmed);

    // Strip group: prefix
    let normalized = normalized.strip_prefix("group:").unwrap_or(normalized);

    // Handle t.me links
    if let Some(username) = normalized
        .strip_prefix("https://t.me/")
        .or_else(|| normalized.strip_prefix("http://t.me/"))
        .or_else(|| normalized.strip_prefix("t.me/"))
    {
        // Skip invite links (start with +)
        if username.starts_with('+') {
            return Err(TelegramError::InvalidChatId(
                "Cannot use invite links as chat ID".into(),
            ));
        }
        return Ok(format!("@{username}"));
    }

    // If it starts with @, it's a username
    if normalized.starts_with('@') {
        return Ok(normalized.to_string());
    }

    // If it's numeric (with optional leading - for groups), use as-is
    // Valid: "123456", "-100123456" (group IDs start with -)
    let is_valid_numeric = if let Some(rest) = normalized.strip_prefix('-') {
        !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit())
    } else {
        !normalized.is_empty() && normalized.chars().all(|c| c.is_ascii_digit())
    };
    if is_valid_numeric {
        return Ok(normalized.to_string());
    }

    // Assume it's a username without @
    if normalized.len() >= 5 && normalized.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return Ok(format!("@{normalized}"));
    }

    Err(TelegramError::InvalidChatId(format!(
        "Cannot parse chat ID: {trimmed}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn test_normalize_chat_id() {
        // Valid numeric IDs
        assert_eq!(normalize_chat_id("123456").unwrap(), "123456");
        assert_eq!(normalize_chat_id("-100123456").unwrap(), "-100123456");

        // Username formats
        assert_eq!(normalize_chat_id("@username").unwrap(), "@username");
        assert_eq!(normalize_chat_id("myusername").unwrap(), "@myusername");

        // Prefixed formats
        assert_eq!(normalize_chat_id("telegram:123456").unwrap(), "123456");
        assert_eq!(
            normalize_chat_id("tg:group:-100123456").unwrap(),
            "-100123456"
        );

        // t.me links
        assert_eq!(normalize_chat_id("t.me/username").unwrap(), "@username");
        assert_eq!(normalize_chat_id("https://t.me/mybot").unwrap(), "@mybot");

        // Invalid inputs
        assert!(normalize_chat_id("").is_err());
        assert!(normalize_chat_id("t.me/+abc123").is_err()); // Invite links not allowed
        assert!(normalize_chat_id("---").is_err()); // Invalid numeric
        assert!(normalize_chat_id("1-2-3").is_err()); // Invalid numeric
        assert!(normalize_chat_id("-").is_err()); // Just a dash
    }

    // Helper to create a mock server with a test client
    async fn setup_mock_client() -> (MockServer, TelegramClient) {
        let mock_server = MockServer::start().await;
        let client = TelegramClient::new("test_token_12345")
            .unwrap()
            .with_base_url(mock_server.uri());
        (mock_server, client)
    }

    #[tokio::test]
    async fn test_get_me_success() {
        let (mock_server, client) = setup_mock_client().await;

        Mock::given(method("GET"))
            .and(path("/bottest_token_12345/getMe"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "result": {
                    "id": 123456789,
                    "is_bot": true,
                    "first_name": "Test Bot",
                    "username": "test_bot"
                }
            })))
            .mount(&mock_server)
            .await;

        let bot_info = client.get_me().await.unwrap();
        assert_eq!(bot_info.id, 123456789);
        assert!(bot_info.is_bot);
        assert_eq!(bot_info.first_name, "Test Bot");
        assert_eq!(bot_info.username.as_deref(), Some("test_bot"));
    }

    #[tokio::test]
    async fn test_get_me_unauthorized() {
        let (mock_server, client) = setup_mock_client().await;

        Mock::given(method("GET"))
            .and(path("/bottest_token_12345/getMe"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "ok": false,
                "error_code": 401,
                "description": "Unauthorized"
            })))
            .mount(&mock_server)
            .await;

        let result = client.get_me().await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, TelegramError::Api { .. }));
        if let TelegramError::Api { code, description } = err {
            assert_eq!(code, 401);
            assert_eq!(description, "Unauthorized");
        }
    }

    #[tokio::test]
    async fn test_send_message_success() {
        let (mock_server, client) = setup_mock_client().await;

        Mock::given(method("POST"))
            .and(path("/bottest_token_12345/sendMessage"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "result": {
                    "message_id": 42,
                    "chat": {
                        "id": 123456,
                        "type": "private",
                        "first_name": "Test"
                    },
                    "date": 1234567890,
                    "text": "Hello, World!"
                }
            })))
            .mount(&mock_server)
            .await;

        let message = client
            .send_message("123456", "Hello, World!", SendMessageOptions::default())
            .await
            .unwrap();

        assert_eq!(message.message_id, 42);
        assert_eq!(message.chat.id, 123456);
        assert_eq!(message.text.as_deref(), Some("Hello, World!"));
    }

    #[tokio::test]
    async fn test_send_message_with_html_parse_mode() {
        let (mock_server, client) = setup_mock_client().await;

        Mock::given(method("POST"))
            .and(path("/bottest_token_12345/sendMessage"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "result": {
                    "message_id": 43,
                    "chat": {
                        "id": 123456,
                        "type": "private",
                        "first_name": "Test"
                    },
                    "date": 1234567890,
                    "text": "Bold text"
                }
            })))
            .mount(&mock_server)
            .await;

        let options = SendMessageOptions::default().html();
        let message = client
            .send_message("123456", "<b>Bold text</b>", options)
            .await
            .unwrap();

        assert_eq!(message.message_id, 43);
    }

    #[tokio::test]
    async fn test_send_message_with_reply_and_thread() {
        let (mock_server, client) = setup_mock_client().await;

        Mock::given(method("POST"))
            .and(path("/bottest_token_12345/sendMessage"))
            .and(body_json(serde_json::json!({
                "chat_id": "123456",
                "text": "*Hello*",
                "parse_mode": "MarkdownV2",
                "reply_to_message_id": 7,
                "message_thread_id": 9
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "result": {
                    "message_id": 44,
                    "chat": {
                        "id": 123456,
                        "type": "private",
                        "first_name": "Test"
                    },
                    "date": 1234567890,
                    "text": "Hello"
                }
            })))
            .mount(&mock_server)
            .await;

        let mut options = SendMessageOptions::default()
            .markdown_v2()
            .reply_to_message_id(7);
        options.message_thread_id = Some(9);

        let message = client
            .send_message("123456", "*Hello*", options)
            .await
            .unwrap();

        assert_eq!(message.message_id, 44);
    }

    #[tokio::test]
    async fn test_send_message_rate_limited() {
        let (mock_server, client) = setup_mock_client().await;

        Mock::given(method("POST"))
            .and(path("/bottest_token_12345/sendMessage"))
            .respond_with(ResponseTemplate::new(429).set_body_json(serde_json::json!({
                "ok": false,
                "error_code": 429,
                "description": "Too Many Requests: retry after 30"
            })))
            .mount(&mock_server)
            .await;

        let result = client
            .send_message("123456", "Test", SendMessageOptions::default())
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.is_retryable());
        assert!(matches!(err, TelegramError::Api { .. }));
        if let TelegramError::Api { code, .. } = err {
            assert_eq!(code, 429);
        }
    }

    #[tokio::test]
    async fn test_get_updates_success() {
        let (mock_server, client) = setup_mock_client().await;

        Mock::given(method("POST"))
            .and(path("/bottest_token_12345/getUpdates"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "result": [
                    {
                        "update_id": 100,
                        "message": {
                            "message_id": 1,
                            "chat": {
                                "id": 12345,
                                "type": "private",
                                "first_name": "User"
                            },
                            "date": 1234567890,
                            "text": "Hello"
                        }
                    },
                    {
                        "update_id": 101,
                        "message": {
                            "message_id": 2,
                            "chat": {
                                "id": 12345,
                                "type": "private",
                                "first_name": "User"
                            },
                            "date": 1234567891,
                            "text": "World"
                        }
                    }
                ]
            })))
            .mount(&mock_server)
            .await;

        let request = GetUpdatesRequest {
            offset: None,
            limit: Some(10),
            timeout: Some(5),
            allowed_updates: None,
        };

        let updates = client.get_updates(request).await.unwrap();
        assert_eq!(updates.len(), 2);
        assert_eq!(updates[0].update_id, 100);
        assert_eq!(updates[1].update_id, 101);
    }

    #[tokio::test]
    async fn test_get_updates_empty() {
        let (mock_server, client) = setup_mock_client().await;

        Mock::given(method("POST"))
            .and(path("/bottest_token_12345/getUpdates"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "result": []
            })))
            .mount(&mock_server)
            .await;

        let request = GetUpdatesRequest {
            offset: Some(100),
            limit: Some(10),
            timeout: Some(5),
            allowed_updates: None,
        };

        let updates = client.get_updates(request).await.unwrap();
        assert!(updates.is_empty());
    }

    #[tokio::test]
    async fn test_get_file_success() {
        let (mock_server, client) = setup_mock_client().await;

        Mock::given(method("GET"))
            .and(path("/bottest_token_12345/getFile"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "result": {
                    "file_id": "AgACAgIAAxkBAAI",
                    "file_unique_id": "AQADAgATqRkyGw",
                    "file_size": 12345,
                    "file_path": "photos/file_0.jpg"
                }
            })))
            .mount(&mock_server)
            .await;

        let file = client.get_file("AgACAgIAAxkBAAI").await.unwrap();
        assert_eq!(file.file_id, "AgACAgIAAxkBAAI");
        assert_eq!(file.file_unique_id, "AQADAgATqRkyGw");
        assert_eq!(file.file_size, Some(12345));
        assert_eq!(file.file_path.as_deref(), Some("photos/file_0.jpg"));
    }

    #[tokio::test]
    async fn test_file_download_url() {
        let client = TelegramClient::new("my_bot_token").unwrap();
        let url = client.file_download_url("photos/file_0.jpg");
        assert_eq!(
            url,
            "https://api.telegram.org/file/botmy_bot_token/photos/file_0.jpg"
        );
    }

    #[tokio::test]
    async fn test_telegram_error_is_retryable() {
        // Rate limited errors should be retryable
        let rate_limited = TelegramError::Api {
            code: 429,
            description: "Too Many Requests".into(),
        };
        assert!(rate_limited.is_retryable());

        // Server errors should be retryable
        let server_error = TelegramError::Api {
            code: 500,
            description: "Internal Server Error".into(),
        };
        assert!(server_error.is_retryable());

        // Client errors should not be retryable
        let bad_request = TelegramError::Api {
            code: 400,
            description: "Bad Request".into(),
        };
        assert!(!bad_request.is_retryable());

        // Invalid chat ID should not be retryable
        let invalid_chat = TelegramError::InvalidChatId("bad".into());
        assert!(!invalid_chat.is_retryable());
    }
}
