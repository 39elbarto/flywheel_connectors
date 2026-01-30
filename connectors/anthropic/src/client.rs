//! Anthropic API client.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use futures_util::StreamExt;
use reqwest::{Client, Response, StatusCode};
use serde::Deserialize;
use tokio_stream::Stream;
use tracing::{debug, instrument, warn};

use crate::{
    error::{AnthropicError, AnthropicResult},
    types::{
        ApiError, Message, MessagesRequest, MessagesResponse, Model, StreamEvent, Tool, ToolChoice,
        Usage,
    },
};

/// Default API base URL.
const DEFAULT_BASE_URL: &str = "https://api.anthropic.com";

/// Current API version.
const API_VERSION: &str = "2023-06-01";

/// Anthropic API client.
#[derive(Debug)]
pub struct AnthropicClient {
    client: Client,
    api_key: String,
    base_url: String,
    max_retries: u32,
    initial_delay_ms: u64,
    max_delay_ms: u64,
    // Cost tracking
    total_input_tokens: AtomicU64,
    total_output_tokens: AtomicU64,
}

impl AnthropicClient {
    /// Create a new Anthropic client.
    pub fn new(api_key: impl Into<String>) -> AnthropicResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(AnthropicError::Http)?;

        Ok(Self {
            client,
            api_key: api_key.into(),
            base_url: DEFAULT_BASE_URL.into(),
            max_retries: 3,
            initial_delay_ms: 500,
            max_delay_ms: 30_000,
            total_input_tokens: AtomicU64::new(0),
            total_output_tokens: AtomicU64::new(0),
        })
    }

    /// Set the base URL (for testing).
    #[must_use]
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    /// Set retry configuration.
    #[must_use]
    pub const fn with_retry_config(
        mut self,
        max_retries: u32,
        initial_delay_ms: u64,
        max_delay_ms: u64,
    ) -> Self {
        self.max_retries = max_retries;
        self.initial_delay_ms = initial_delay_ms;
        self.max_delay_ms = max_delay_ms;
        self
    }

    /// Get total input tokens used.
    #[must_use]
    pub fn total_input_tokens(&self) -> u64 {
        self.total_input_tokens.load(Ordering::Relaxed)
    }

    /// Get total output tokens used.
    #[must_use]
    pub fn total_output_tokens(&self) -> u64 {
        self.total_output_tokens.load(Ordering::Relaxed)
    }

    /// Reset token counters.
    pub fn reset_token_counts(&self) {
        self.total_input_tokens.store(0, Ordering::Relaxed);
        self.total_output_tokens.store(0, Ordering::Relaxed);
    }

    /// Track usage from a response.
    fn track_usage(&self, usage: &Usage) {
        self.total_input_tokens
            .fetch_add(u64::from(usage.input_tokens), Ordering::Relaxed);
        self.total_output_tokens
            .fetch_add(u64::from(usage.output_tokens), Ordering::Relaxed);
    }

    /// Send a message to Claude.
    #[instrument(skip(self, messages, system, tools))]
    pub async fn message(
        &self,
        model: Model,
        messages: Vec<Message>,
        max_tokens: u32,
        system: Option<&str>,
        temperature: Option<f64>,
        tools: Option<Vec<Tool>>,
        tool_choice: Option<ToolChoice>,
    ) -> AnthropicResult<MessagesResponse> {
        let request = MessagesRequest {
            model: model.as_str().into(),
            messages,
            max_tokens,
            system: system.map(Into::into),
            temperature,
            stream: Some(false),
            tools,
            tool_choice,
            stop_sequences: None,
        };

        let response: MessagesResponse = self.post("/v1/messages", &request).await?;
        self.track_usage(&response.usage);
        Ok(response)
    }

    /// Send a simple text message and get the text response.
    pub async fn chat(
        &self,
        model: Model,
        user_message: &str,
        system: Option<&str>,
        max_tokens: u32,
    ) -> AnthropicResult<String> {
        let messages = vec![Message {
            role: crate::types::Role::User,
            content: user_message.into(),
        }];

        let response = self
            .message(model, messages, max_tokens, system, None, None, None)
            .await?;

        // Extract text from response
        let text = response
            .content
            .iter()
            .filter_map(|block| block.as_text())
            .collect::<Vec<_>>()
            .join("");

        Ok(text)
    }

    /// Stream a message response.
    #[instrument(skip(self, messages, system, tools))]
    pub async fn message_stream(
        &self,
        model: Model,
        messages: Vec<Message>,
        max_tokens: u32,
        system: Option<&str>,
        temperature: Option<f64>,
        tools: Option<Vec<Tool>>,
        tool_choice: Option<ToolChoice>,
    ) -> AnthropicResult<impl Stream<Item = AnthropicResult<StreamEvent>>> {
        let request = MessagesRequest {
            model: model.as_str().into(),
            messages,
            max_tokens,
            system: system.map(Into::into),
            temperature,
            stream: Some(true),
            tools,
            tool_choice,
            stop_sequences: None,
        };

        let response = self.post_stream("/v1/messages", &request).await?;
        Ok(parse_sse_stream(response))
    }

    /// Make a POST request.
    async fn post<T, R>(&self, endpoint: &str, body: &T) -> AnthropicResult<R>
    where
        T: serde::Serialize,
        R: serde::de::DeserializeOwned,
    {
        let url = format!("{}{endpoint}", self.base_url);
        let mut delay = Duration::from_millis(self.initial_delay_ms);
        let mut attempts = 0;

        loop {
            attempts += 1;
            debug!(attempt = attempts, endpoint, "Making Anthropic API request");

            let result = self
                .client
                .post(&url)
                .header("x-api-key", &self.api_key)
                .header("anthropic-version", API_VERSION)
                .header("content-type", "application/json")
                .json(body)
                .send()
                .await;

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
                            "Retrying Anthropic API request"
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
                        return Err(AnthropicError::Http(e));
                    }
                }
                Err(e) => return Err(AnthropicError::Http(e)),
            }
        }
    }

    /// Make a streaming POST request.
    async fn post_stream<T>(&self, endpoint: &str, body: &T) -> AnthropicResult<Response>
    where
        T: serde::Serialize,
    {
        let url = format!("{}{endpoint}", self.base_url);

        let response = self
            .client
            .post(&url)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", API_VERSION)
            .header("content-type", "application/json")
            .json(body)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let bytes = response.bytes().await?;
            return Err(parse_error_response(status, &bytes));
        }

        Ok(response)
    }

    /// Handle a response.
    async fn handle_response<R>(&self, response: Response) -> AnthropicResult<R>
    where
        R: serde::de::DeserializeOwned,
    {
        let status = response.status();
        let bytes = response.bytes().await?;

        if status.is_success() {
            serde_json::from_slice(&bytes).map_err(AnthropicError::from)
        } else {
            Err(parse_error_response(status, &bytes))
        }
    }
}

/// Parse an error response.
fn parse_error_response(status: StatusCode, bytes: &Bytes) -> AnthropicError {
    // Try to parse as API error
    #[derive(Deserialize)]
    struct ErrorWrapper {
        error: ApiError,
    }

    if let Ok(wrapper) = serde_json::from_slice::<ErrorWrapper>(bytes) {
        let error = wrapper.error;

        // Check for specific error types
        if status == StatusCode::TOO_MANY_REQUESTS {
            // Extract retry-after if present
            return AnthropicError::RateLimited {
                retry_after_ms: 30_000, // Default 30s
            };
        }

        if status.as_u16() == 529 {
            return AnthropicError::Overloaded {
                retry_after_ms: 60_000, // Default 60s
            };
        }

        if status == StatusCode::UNAUTHORIZED {
            return AnthropicError::InvalidApiKey;
        }

        if error.error_type == "invalid_request_error" && error.message.contains("context length") {
            return AnthropicError::ContextLengthExceeded {
                message: error.message,
            };
        }

        return AnthropicError::Api {
            error_type: error.error_type,
            message: error.message,
            status_code: Some(status.as_u16()),
        };
    }

    // Fallback for unparseable errors
    AnthropicError::Api {
        error_type: "unknown".into(),
        message: String::from_utf8_lossy(bytes).into_owned(),
        status_code: Some(status.as_u16()),
    }
}

/// Parse SSE stream into events.
fn parse_sse_stream(response: Response) -> impl Stream<Item = AnthropicResult<StreamEvent>> {
    async_stream::stream! {
        let mut stream = response.bytes_stream();
        let mut buffer = String::new();

        while let Some(chunk) = stream.next().await {
            let chunk = match chunk {
                Ok(c) => c,
                Err(e) => {
                    yield Err(AnthropicError::Http(e));
                    return;
                }
            };

            buffer.push_str(&String::from_utf8_lossy(&chunk));

            // Process complete SSE events
            while let Some(pos) = buffer.find("\n\n") {
                let event_str = buffer[..pos].to_string();
                buffer = buffer[pos + 2..].to_string();

                if let Some(event) = parse_sse_event(&event_str) {
                    yield event;
                }
            }
        }

        // Process any remaining buffer
        if !buffer.is_empty() {
            if let Some(event) = parse_sse_event(&buffer) {
                yield event;
            }
        }
    }
}

/// Parse a single SSE event.
fn parse_sse_event(event_str: &str) -> Option<AnthropicResult<StreamEvent>> {
    let mut event_type = None;
    let mut data = None;

    for line in event_str.lines() {
        if let Some(value) = line.strip_prefix("event: ") {
            event_type = Some(value.trim());
        } else if let Some(value) = line.strip_prefix("data: ") {
            data = Some(value.trim());
        }
    }

    let data = data?;

    // Parse based on event type
    match event_type {
        Some(
            "message_start"
            | "content_block_start"
            | "content_block_delta"
            | "content_block_stop"
            | "message_delta"
            | "message_stop"
            | "ping"
            | "error",
        ) => match serde_json::from_str::<StreamEvent>(data) {
            Ok(event) => Some(Ok(event)),
            Err(e) => Some(Err(AnthropicError::Json(e))),
        },
        _ => None,
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

    #[tokio::test]
    async fn test_chat_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .and(header("x-api-key", "test_key"))
            .and(header("anthropic-version", API_VERSION))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "msg_123",
                "type": "message",
                "role": "assistant",
                "content": [{"type": "text", "text": "Hello!"}],
                "model": "claude-sonnet-4-20250514",
                "stop_reason": "end_turn",
                "usage": {
                    "input_tokens": 10,
                    "output_tokens": 5
                }
            })))
            .mount(&mock_server)
            .await;

        let client = AnthropicClient::new("test_key")
            .unwrap()
            .with_base_url(mock_server.uri());

        let response = client
            .chat(Model::ClaudeSonnet4, "Hi", None, 1024)
            .await
            .unwrap();

        assert_eq!(response, "Hello!");
        assert_eq!(client.total_input_tokens(), 10);
        assert_eq!(client.total_output_tokens(), 5);
    }

    #[tokio::test]
    async fn test_unauthorized() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "error": {
                    "type": "authentication_error",
                    "message": "Invalid API key"
                }
            })))
            .mount(&mock_server)
            .await;

        let client = AnthropicClient::new("bad_key")
            .unwrap()
            .with_base_url(mock_server.uri())
            .with_retry_config(1, 10, 100);

        let result = client.chat(Model::ClaudeSonnet4, "Hi", None, 1024).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AnthropicError::InvalidApiKey));
    }

    #[tokio::test]
    async fn test_rate_limited() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(429).set_body_json(serde_json::json!({
                "error": {
                    "type": "rate_limit_error",
                    "message": "Rate limit exceeded"
                }
            })))
            .mount(&mock_server)
            .await;

        let client = AnthropicClient::new("test_key")
            .unwrap()
            .with_base_url(mock_server.uri())
            .with_retry_config(1, 10, 100);

        let result = client.chat(Model::ClaudeSonnet4, "Hi", None, 1024).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AnthropicError::RateLimited { .. }
        ));
    }

    #[tokio::test]
    async fn test_overloaded() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(529).set_body_json(serde_json::json!({
                "error": {
                    "type": "overloaded_error",
                    "message": "Overloaded"
                }
            })))
            .mount(&mock_server)
            .await;

        let client = AnthropicClient::new("test_key")
            .unwrap()
            .with_base_url(mock_server.uri())
            .with_retry_config(1, 10, 100);

        let result = client.chat(Model::ClaudeSonnet4, "Hi", None, 1024).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AnthropicError::Overloaded { .. }
        ));
    }

    #[tokio::test]
    async fn test_context_length_exceeded() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": {
                    "type": "invalid_request_error",
                    "message": "context length exceeded"
                }
            })))
            .mount(&mock_server)
            .await;

        let client = AnthropicClient::new("test_key")
            .unwrap()
            .with_base_url(mock_server.uri())
            .with_retry_config(1, 10, 100);

        let result = client.chat(Model::ClaudeSonnet4, "Hi", None, 1024).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AnthropicError::ContextLengthExceeded { .. }
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_logs_redact_api_key_and_prompt() {
        let capture = LogCapture::new();
        let _guard = capture.install_json_with_filter("debug");
        tracing::debug!("log_capture_ready");

        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .and(header("x-api-key", "test_key"))
            .and(header("anthropic-version", API_VERSION))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "msg_123",
                "type": "message",
                "role": "assistant",
                "content": [{"type": "text", "text": "Hello!"}],
                "model": "claude-sonnet-4-20250514",
                "stop_reason": "end_turn",
                "usage": {
                    "input_tokens": 10,
                    "output_tokens": 5
                }
            })))
            .mount(&mock_server)
            .await;

        let client = AnthropicClient::new("test_key")
            .unwrap()
            .with_base_url(mock_server.uri());
        let secret_prompt = "TopSecretPrompt";
        let _ = client
            .chat(Model::ClaudeSonnet4, secret_prompt, None, 1024)
            .await
            .unwrap();

        let logs = capture.jsonl();
        assert!(
            logs.contains("log_capture_ready"),
            "expected debug logs to be captured"
        );
        assert!(
            !logs.contains("test_key"),
            "API key should not appear in logs"
        );
        assert!(
            !logs.contains(secret_prompt),
            "prompt text should not appear in logs"
        );
    }

    #[test]
    fn test_parse_sse_event_ping() {
        let event = parse_sse_event("event: ping\ndata: {\"type\":\"ping\"}\n");
        let event = event
            .expect("expected ping event")
            .expect("expected ok event");

        assert!(matches!(event, StreamEvent::Ping));
    }

    #[test]
    fn test_parse_sse_event_invalid_json() {
        let event = parse_sse_event("event: ping\ndata: {not json}\n");
        let event = event.expect("expected ping event");

        assert!(matches!(event, Err(AnthropicError::Json(_))));
    }

    #[test]
    fn test_parse_sse_event_unknown_ignored() {
        let event = parse_sse_event("event: unknown\ndata: {}\n");
        assert!(event.is_none());
    }

    #[tokio::test]
    async fn test_model_pricing() {
        assert_eq!(Model::ClaudeOpus4_5.input_price_per_million(), 15.0);
        assert_eq!(Model::ClaudeOpus4_5.output_price_per_million(), 75.0);
        assert_eq!(Model::ClaudeSonnet4.input_price_per_million(), 3.0);
        assert_eq!(Model::ClaudeSonnet4.output_price_per_million(), 15.0);
        assert_eq!(Model::Claude3_5Haiku.input_price_per_million(), 0.25);
        assert_eq!(Model::Claude3_5Haiku.output_price_per_million(), 1.25);
    }

    #[tokio::test]
    async fn test_usage_cost_calculation() {
        let usage = Usage {
            input_tokens: 1000,
            output_tokens: 500,
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: 0,
        };

        // Sonnet: 1000 input * $3/1M + 500 output * $15/1M
        let cost = usage.calculate_cost(Model::ClaudeSonnet4);
        assert!((cost - 0.0105).abs() < 0.0001);
    }

    #[test]
    fn test_error_is_retryable() {
        assert!(
            AnthropicError::RateLimited {
                retry_after_ms: 1000
            }
            .is_retryable()
        );
        assert!(
            AnthropicError::Overloaded {
                retry_after_ms: 1000
            }
            .is_retryable()
        );
        assert!(!AnthropicError::InvalidApiKey.is_retryable());
        // assert!(!AnthropicError::NotConfigured.is_retryable()); // Removed as it doesn't exist
    }
}
