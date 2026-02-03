//! OpenAI API client.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use fcp_core::CredentialId;
use futures_util::StreamExt;
use reqwest::{Client, Response, StatusCode};
use tokio_stream::Stream;
use tracing::{debug, instrument, warn};

use crate::{
    error::{OpenAIError, OpenAIResult},
    types::{
        ApiError, ChatCompletionChunk, ChatCompletionRequest, ChatCompletionResponse, Message,
        Model, Tool, ToolChoice, Usage,
    },
};

/// Default API base URL.
pub const DEFAULT_BASE_URL: &str = "https://api.openai.com";

/// Authentication mode for OpenAI API access.
#[derive(Clone)]
pub enum OpenAIAuth {
    /// Direct API key (legacy; avoided in secretless deployments).
    ApiKey(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl OpenAIAuth {
    /// Render a redacted label suitable for logs/diagnostics.
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::ApiKey(_) => "api_key:redacted".to_string(),
            Self::CredentialId(id) => {
                let id_str = id.to_string();
                let prefix = id_str.chars().take(8).collect::<String>();
                format!("credential_id:{prefix}…")
            }
        }
    }

    /// True if this uses secretless credential injection.
    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for OpenAIAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApiKey(_) => f.debug_tuple("ApiKey").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// OpenAI API client.
#[derive(Debug)]
pub struct OpenAIClient {
    client: Client,
    auth: OpenAIAuth,
    base_url: String,
    organization: Option<String>,
    max_retries: u32,
    initial_delay_ms: u64,
    max_delay_ms: u64,
    // Usage tracking
    total_prompt_tokens: AtomicU64,
    total_completion_tokens: AtomicU64,
}

impl OpenAIClient {
    /// Create a new OpenAI client.
    pub fn new(api_key: impl Into<String>) -> OpenAIResult<Self> {
        Self::new_with_auth(OpenAIAuth::ApiKey(api_key.into()))
    }

    /// Create a new OpenAI client with explicit auth mode.
    pub fn new_with_auth(auth: OpenAIAuth) -> OpenAIResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(OpenAIError::Http)?;

        Ok(Self {
            client,
            auth,
            base_url: DEFAULT_BASE_URL.into(),
            organization: None,
            max_retries: 3,
            initial_delay_ms: 500,
            max_delay_ms: 30_000,
            total_prompt_tokens: AtomicU64::new(0),
            total_completion_tokens: AtomicU64::new(0),
        })
    }

    /// Set the base URL (for testing).
    #[must_use]
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    /// Set the organization ID.
    #[must_use]
    pub fn with_organization(mut self, org: impl Into<String>) -> Self {
        self.organization = Some(org.into());
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

    /// Get total prompt tokens used.
    #[must_use]
    pub fn total_prompt_tokens(&self) -> u64 {
        self.total_prompt_tokens.load(Ordering::Relaxed)
    }

    /// Get total completion tokens used.
    #[must_use]
    pub fn total_completion_tokens(&self) -> u64 {
        self.total_completion_tokens.load(Ordering::Relaxed)
    }

    /// Reset token counters.
    pub fn reset_token_counts(&self) {
        self.total_prompt_tokens.store(0, Ordering::Relaxed);
        self.total_completion_tokens.store(0, Ordering::Relaxed);
    }

    fn apply_auth(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        let request = match &self.auth {
            OpenAIAuth::ApiKey(key) => request.header("Authorization", format!("Bearer {key}")),
            OpenAIAuth::CredentialId(credential_id) => {
                request.header("X-FCP-Credential-ID", credential_id.to_string())
            }
        };

        if let Some(org) = &self.organization {
            request.header("OpenAI-Organization", org)
        } else {
            request
        }
    }

    /// Perform a lightweight credentials/availability check.
    pub async fn health_check(&self) -> OpenAIResult<()> {
        let url = format!("{}/v1/models", self.base_url);
        let request = self
            .client
            .get(&url)
            .header("Content-Type", "application/json");
        let request = self.apply_auth(request);

        let response = request.send().await?;
        let status = response.status();
        let bytes = response.bytes().await?;
        if status.is_success() {
            Ok(())
        } else {
            Err(parse_error_response(status, &bytes))
        }
    }

    /// Track usage from a response.
    fn track_usage(&self, usage: &Usage) {
        self.total_prompt_tokens
            .fetch_add(u64::from(usage.prompt_tokens), Ordering::Relaxed);
        self.total_completion_tokens
            .fetch_add(u64::from(usage.completion_tokens), Ordering::Relaxed);
    }

    /// Send a chat completion request.
    #[instrument(skip(self, messages, tools))]
    pub async fn chat_completion(
        &self,
        model: Model,
        messages: Vec<Message>,
        max_tokens: Option<u32>,
        temperature: Option<f64>,
        tools: Option<Vec<Tool>>,
        tool_choice: Option<ToolChoice>,
    ) -> OpenAIResult<ChatCompletionResponse> {
        let request = ChatCompletionRequest {
            model: model.as_str().into(),
            messages,
            max_tokens,
            temperature,
            top_p: None,
            n: None,
            stream: Some(false),
            stop: None,
            presence_penalty: None,
            frequency_penalty: None,
            user: None,
            tools,
            tool_choice,
            response_format: None,
            seed: None,
        };

        let response: ChatCompletionResponse = self.post("/v1/chat/completions", &request).await?;
        if let Some(usage) = &response.usage {
            self.track_usage(usage);
        }
        Ok(response)
    }

    /// Send a simple text message and get the text response.
    pub async fn chat(
        &self,
        model: Model,
        user_message: &str,
        system: Option<&str>,
        max_tokens: Option<u32>,
    ) -> OpenAIResult<String> {
        let mut messages = Vec::new();

        if let Some(sys) = system {
            messages.push(Message::system(sys));
        }
        messages.push(Message::user(user_message));

        let response = self
            .chat_completion(model, messages, max_tokens, None, None, None)
            .await?;

        // Extract text from first choice
        let text = response
            .choices
            .first()
            .and_then(|c| c.message.content.as_ref())
            .cloned()
            .unwrap_or_default();

        Ok(text)
    }

    /// Stream a chat completion response.
    #[instrument(skip(self, messages, tools))]
    pub async fn chat_completion_stream(
        &self,
        model: Model,
        messages: Vec<Message>,
        max_tokens: Option<u32>,
        temperature: Option<f64>,
        tools: Option<Vec<Tool>>,
        tool_choice: Option<ToolChoice>,
    ) -> OpenAIResult<impl Stream<Item = OpenAIResult<ChatCompletionChunk>>> {
        let request = ChatCompletionRequest {
            model: model.as_str().into(),
            messages,
            max_tokens,
            temperature,
            top_p: None,
            n: None,
            stream: Some(true),
            stop: None,
            presence_penalty: None,
            frequency_penalty: None,
            user: None,
            tools,
            tool_choice,
            response_format: None,
            seed: None,
        };

        let response = self.post_stream("/v1/chat/completions", &request).await?;
        Ok(parse_sse_stream(response))
    }

    /// Make a POST request.
    async fn post<T, R>(&self, endpoint: &str, body: &T) -> OpenAIResult<R>
    where
        T: serde::Serialize,
        R: serde::de::DeserializeOwned,
    {
        let url = format!("{}{endpoint}", self.base_url);
        let mut delay = Duration::from_millis(self.initial_delay_ms);
        let mut attempts = 0;

        loop {
            attempts += 1;
            debug!(attempt = attempts, endpoint, "Making OpenAI API request");

            let request = self
                .client
                .post(&url)
                .header("Content-Type", "application/json");

            let request = self.apply_auth(request);

            let result = request.json(body).send().await;

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
                            "Retrying OpenAI API request"
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
                        return Err(OpenAIError::Http(e));
                    }
                }
                Err(e) => return Err(OpenAIError::Http(e)),
            }
        }
    }

    /// Make a streaming POST request.
    async fn post_stream<T>(&self, endpoint: &str, body: &T) -> OpenAIResult<Response>
    where
        T: serde::Serialize,
    {
        let url = format!("{}{endpoint}", self.base_url);

        let request = self
            .client
            .post(&url)
            .header("Content-Type", "application/json");

        let request = self.apply_auth(request);

        let response = request.json(body).send().await?;

        let status = response.status();
        if !status.is_success() {
            let bytes = response.bytes().await?;
            return Err(parse_error_response(status, &bytes));
        }

        Ok(response)
    }

    /// Handle a response.
    async fn handle_response<R>(&self, response: Response) -> OpenAIResult<R>
    where
        R: serde::de::DeserializeOwned,
    {
        let status = response.status();
        let bytes = response.bytes().await?;

        if status.is_success() {
            serde_json::from_slice(&bytes).map_err(OpenAIError::from)
        } else {
            Err(parse_error_response(status, &bytes))
        }
    }
}

/// Parse an error response.
fn parse_error_response(status: StatusCode, bytes: &Bytes) -> OpenAIError {
    // Try to parse as API error
    if let Ok(api_error) = serde_json::from_slice::<ApiError>(bytes) {
        let details = api_error.error;

        // Check for specific error types
        if status == StatusCode::TOO_MANY_REQUESTS {
            return OpenAIError::RateLimited {
                retry_after_ms: 30_000, // Default 30s
            };
        }

        if status == StatusCode::SERVICE_UNAVAILABLE {
            return OpenAIError::Overloaded {
                retry_after_ms: 60_000, // Default 60s
            };
        }

        if status == StatusCode::UNAUTHORIZED {
            return OpenAIError::InvalidApiKey;
        }

        // Check for context length errors
        if details.error_type == "invalid_request_error"
            && (details.message.contains("context_length")
                || details.message.contains("maximum context length"))
        {
            return OpenAIError::ContextLengthExceeded {
                message: details.message,
            };
        }

        // Check for content filter
        if details.error_type == "invalid_request_error"
            && details.code.as_deref() == Some("content_filter")
        {
            return OpenAIError::ContentFiltered {
                message: details.message,
            };
        }

        return OpenAIError::Api {
            error_type: details.error_type,
            message: details.message,
            status_code: Some(status.as_u16()),
        };
    }

    // Fallback for unparseable errors
    OpenAIError::Api {
        error_type: "unknown".into(),
        message: String::from_utf8_lossy(bytes).into_owned(),
        status_code: Some(status.as_u16()),
    }
}

/// Parse SSE stream into chunks.
fn parse_sse_stream(response: Response) -> impl Stream<Item = OpenAIResult<ChatCompletionChunk>> {
    async_stream::stream! {
        let mut stream = response.bytes_stream();
        let mut buffer = String::new();

        while let Some(chunk) = stream.next().await {
            let chunk = match chunk {
                Ok(c) => c,
                Err(e) => {
                    yield Err(OpenAIError::Http(e));
                    return;
                }
            };

            buffer.push_str(&String::from_utf8_lossy(&chunk));

            // Process complete SSE events
            while let Some(pos) = buffer.find("\n\n") {
                let event_str = buffer[..pos].to_string();
                buffer = buffer[pos + 2..].to_string();

                if let Some(chunk) = parse_sse_event(&event_str) {
                    yield chunk;
                }
            }
        }

        // Process any remaining buffer
        if !buffer.is_empty() {
            if let Some(chunk) = parse_sse_event(&buffer) {
                yield chunk;
            }
        }
    }
}

/// Parse a single SSE event.
fn parse_sse_event(event_str: &str) -> Option<OpenAIResult<ChatCompletionChunk>> {
    for line in event_str.lines() {
        if let Some(data) = line.strip_prefix("data: ") {
            let data = data.trim();

            // Check for stream end
            if data == "[DONE]" {
                return None;
            }

            return Some(
                serde_json::from_str::<ChatCompletionChunk>(data).map_err(OpenAIError::from),
            );
        }
    }
    None
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
            .and(path("/v1/chat/completions"))
            .and(header("Authorization", "Bearer test_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "chatcmpl-123",
                "object": "chat.completion",
                "created": 1677652288,
                "model": "gpt-4o",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "Hello! How can I help you today?"
                    },
                    "finish_reason": "stop"
                }],
                "usage": {
                    "prompt_tokens": 10,
                    "completion_tokens": 8,
                    "total_tokens": 18
                }
            })))
            .mount(&mock_server)
            .await;

        let client = OpenAIClient::new("test_key")
            .unwrap()
            .with_base_url(mock_server.uri());

        let response = client
            .chat(Model::Gpt4o, "Hi", None, Some(1024))
            .await
            .unwrap();

        assert_eq!(response, "Hello! How can I help you today?");
        assert_eq!(client.total_prompt_tokens(), 10);
        assert_eq!(client.total_completion_tokens(), 8);
    }

    #[tokio::test]
    async fn test_unauthorized() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "error": {
                    "message": "Incorrect API key provided",
                    "type": "invalid_request_error",
                    "param": null,
                    "code": "invalid_api_key"
                }
            })))
            .mount(&mock_server)
            .await;

        let client = OpenAIClient::new("bad_key")
            .unwrap()
            .with_base_url(mock_server.uri())
            .with_retry_config(1, 10, 100);

        let result = client.chat(Model::Gpt4o, "Hi", None, Some(1024)).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), OpenAIError::InvalidApiKey));
    }

    #[tokio::test]
    async fn test_rate_limited() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(429).set_body_json(serde_json::json!({
                "error": {
                    "message": "Rate limit exceeded",
                    "type": "rate_limit_error",
                    "param": null,
                    "code": null
                }
            })))
            .mount(&mock_server)
            .await;

        let client = OpenAIClient::new("test_key")
            .unwrap()
            .with_base_url(mock_server.uri())
            .with_retry_config(1, 10, 100);

        let result = client.chat(Model::Gpt4o, "Hi", None, Some(1024)).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            OpenAIError::RateLimited { .. }
        ));
    }

    #[tokio::test]
    async fn test_overloaded() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(503).set_body_json(serde_json::json!({
                "error": {
                    "message": "Server overloaded",
                    "type": "server_error",
                    "param": null,
                    "code": null
                }
            })))
            .mount(&mock_server)
            .await;

        let client = OpenAIClient::new("test_key")
            .unwrap()
            .with_base_url(mock_server.uri())
            .with_retry_config(1, 10, 100);

        let result = client.chat(Model::Gpt4o, "Hi", None, Some(1024)).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            OpenAIError::Overloaded { .. }
        ));
    }

    #[tokio::test]
    async fn test_context_length_exceeded() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": {
                    "message": "maximum context length exceeded",
                    "type": "invalid_request_error",
                    "param": null,
                    "code": null
                }
            })))
            .mount(&mock_server)
            .await;

        let client = OpenAIClient::new("test_key")
            .unwrap()
            .with_base_url(mock_server.uri())
            .with_retry_config(1, 10, 100);

        let result = client.chat(Model::Gpt4o, "Hi", None, Some(1024)).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            OpenAIError::ContextLengthExceeded { .. }
        ));
    }

    #[tokio::test]
    async fn test_content_filtered() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": {
                    "message": "Content filtered",
                    "type": "invalid_request_error",
                    "param": null,
                    "code": "content_filter"
                }
            })))
            .mount(&mock_server)
            .await;

        let client = OpenAIClient::new("test_key")
            .unwrap()
            .with_base_url(mock_server.uri())
            .with_retry_config(1, 10, 100);

        let result = client.chat(Model::Gpt4o, "Hi", None, Some(1024)).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            OpenAIError::ContentFiltered { .. }
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_logs_redact_api_key_and_prompt() {
        let capture = LogCapture::new();
        let _guard = capture.install_json_with_filter("debug");
        tracing::debug!("log_capture_ready");

        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .and(header("Authorization", "Bearer test_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "chatcmpl-123",
                "object": "chat.completion",
                "created": 1677652288,
                "model": "gpt-4o",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "Hello! How can I help you today?"
                    },
                    "finish_reason": "stop"
                }],
                "usage": {
                    "prompt_tokens": 10,
                    "completion_tokens": 8,
                    "total_tokens": 18
                }
            })))
            .mount(&mock_server)
            .await;

        let client = OpenAIClient::new("test_key")
            .unwrap()
            .with_base_url(mock_server.uri());
        let secret_prompt = "TopSecretPrompt";
        let _ = client
            .chat(Model::Gpt4o, secret_prompt, None, Some(1024))
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

    #[tokio::test]
    async fn test_model_pricing() {
        assert_eq!(Model::Gpt4o.input_price_per_million(), 2.50);
        assert_eq!(Model::Gpt4o.output_price_per_million(), 10.0);
        assert_eq!(Model::Gpt4oMini.input_price_per_million(), 0.15);
        assert_eq!(Model::Gpt4oMini.output_price_per_million(), 0.60);
        assert_eq!(Model::Gpt35Turbo.input_price_per_million(), 0.50);
        assert_eq!(Model::Gpt35Turbo.output_price_per_million(), 1.50);
    }

    #[tokio::test]
    async fn test_usage_cost_calculation() {
        let usage = Usage {
            prompt_tokens: 1000,
            completion_tokens: 500,
            total_tokens: 1500,
            prompt_tokens_details: None,
        };

        // GPT-4o: 1000 input * $2.50/1M + 500 output * $10/1M
        let cost = usage.calculate_cost(Model::Gpt4o);
        assert!((cost - 0.0075).abs() < 0.0001);

        // Test with cached tokens (GPT-4o, 50% discount)
        // 1000 uncached * $2.50/1M = 0.0025
        // 1000 cached * $1.25/1M = 0.00125
        // Total = 0.00375
        let cached_usage = Usage {
            prompt_tokens: 2000,
            completion_tokens: 0,
            total_tokens: 2000,
            prompt_tokens_details: Some(crate::types::PromptTokensDetails {
                cached_tokens: 1000,
            }),
        };
        let cost_cached = cached_usage.calculate_cost(Model::Gpt4o);
        assert!((cost_cached - 0.00375).abs() < 0.0001);
    }

    #[test]
    fn test_error_is_retryable() {
        assert!(
            OpenAIError::RateLimited {
                retry_after_ms: 1000
            }
            .is_retryable()
        );
        assert!(
            OpenAIError::Overloaded {
                retry_after_ms: 1000
            }
            .is_retryable()
        );
        assert!(!OpenAIError::InvalidApiKey.is_retryable());
    }

    #[test]
    fn test_parse_sse_event_done() {
        let event = parse_sse_event("data: [DONE]\n");
        assert!(event.is_none());
    }

    #[test]
    fn test_parse_sse_event_invalid_json() {
        let event = parse_sse_event("data: {not json}\n");
        let event = event.expect("expected event");
        assert!(matches!(event, Err(OpenAIError::Json(_))));
    }
}
