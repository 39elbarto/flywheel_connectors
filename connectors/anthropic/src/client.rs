//! Anthropic API client.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use fcp_async_core::ExecutionContext;
use fcp_core::CredentialId;
use fcp_sdk::migration::{AttemptOutcome, HttpRetryConfig, RetryLoop};
use futures_util::{Stream, StreamExt};
use reqwest::{Client, Response, StatusCode};
use serde::Deserialize;
use tracing::{debug, instrument};

use crate::{
    error::{AnthropicError, AnthropicResult},
    types::{
        ApiError, Message, MessagesRequest, MessagesResponse, Model, StreamEvent, Tool, ToolChoice,
        Usage,
    },
};

/// Default API base URL.
pub const DEFAULT_BASE_URL: &str = "https://api.anthropic.com";

/// Current API version.
const API_VERSION: &str = "2023-06-01";

/// Authentication mode for the Anthropic API.
#[derive(Clone)]
pub enum AnthropicAuth {
    /// Direct API key (legacy; avoided in secretless deployments).
    ApiKey(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl AnthropicAuth {
    /// Render a redacted label suitable for logs/diagnostics.
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::ApiKey(_) => "api_key:redacted".to_string(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    /// Whether this auth mode requires egress proxy credential injection.
    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for AnthropicAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApiKey(_) => f.debug_tuple("ApiKey").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// Anthropic API client.
pub struct AnthropicClient {
    client: Client,
    auth: AnthropicAuth,
    base_url: String,
    retry_config: HttpRetryConfig,
    // Cost tracking
    total_input_tokens: AtomicU64,
    total_output_tokens: AtomicU64,
}

impl fmt::Debug for AnthropicClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnthropicClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .field("retry_config", &self.retry_config)
            .finish_non_exhaustive()
    }
}

impl AnthropicClient {
    /// Create a new Anthropic client with a direct API key.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be constructed.
    pub fn new(api_key: impl Into<String>) -> AnthropicResult<Self> {
        Self::new_with_auth(AnthropicAuth::ApiKey(api_key.into()))
    }

    /// Create a new Anthropic client with explicit auth mode.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be constructed.
    pub fn new_with_auth(auth: AnthropicAuth) -> AnthropicResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(AnthropicError::Http)?;

        Ok(Self {
            client,
            auth,
            base_url: DEFAULT_BASE_URL.into(),
            retry_config: HttpRetryConfig::default(),
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
    pub fn with_retry_config(
        mut self,
        max_retries: u32,
        initial_delay_ms: u64,
        max_delay_ms: u64,
    ) -> Self {
        self.retry_config = HttpRetryConfig {
            max_retries,
            initial_delay_ms,
            max_delay_ms,
            ..HttpRetryConfig::default()
        };
        self
    }

    /// Get a reference to the auth mode.
    #[must_use]
    pub const fn auth(&self) -> &AnthropicAuth {
        &self.auth
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

    /// Perform a safe, read-only health check by listing models.
    ///
    /// This validates that the API key is valid and the API is reachable
    /// without incurring any cost or side effects.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, authentication errors, or rate limiting.
    pub async fn health_check(&self) -> AnthropicResult<()> {
        // The Anthropic API doesn't have a /v1/models list endpoint like OpenAI,
        // so we send a minimal messages request with max_tokens=1 to validate
        // auth. This is the cheapest possible validation call.
        let url = format!("{}/v1/messages", self.base_url);
        let request = self
            .client
            .post(&url)
            .header("anthropic-version", API_VERSION)
            .header("content-type", "application/json");
        let request = self.apply_auth(request);
        let request = request.json(&serde_json::json!({
            "model": "claude-3-5-haiku-20241022",
            "max_tokens": 1,
            "messages": [{"role": "user", "content": "hi"}]
        }));

        let response = request.send().await?;
        let status = response.status();
        let bytes = response.bytes().await?;
        if status.is_success() {
            Ok(())
        } else {
            Err(parse_error_response(status, &bytes))
        }
    }

    /// Apply auth headers to a request builder.
    fn apply_auth(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            AnthropicAuth::ApiKey(key) => request.header("x-api-key", key),
            AnthropicAuth::CredentialId(credential_id) => {
                request.header("X-FCP-Credential-ID", credential_id.to_string())
            }
        }
    }

    /// Send a message to Claude.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, authentication errors,
    /// or context length violations.
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
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, authentication errors,
    /// or context length violations.
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
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, or authentication errors.
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

    /// Make a POST request with automatic retry via [`RetryLoop`].
    async fn post<T, R>(&self, endpoint: &str, body: &T) -> AnthropicResult<R>
    where
        T: serde::Serialize + Sync,
        R: serde::de::DeserializeOwned + Send,
    {
        let url = format!("{}{endpoint}", self.base_url);
        let ctx = ExecutionContext::request_scoped(Duration::from_secs(120));
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = &url;
            async move {
                debug!(attempt, endpoint, "Making Anthropic API request");

                let request = self
                    .client
                    .post(url.as_str())
                    .header("anthropic-version", API_VERSION)
                    .header("content-type", "application/json");
                let request = self.apply_auth(request);

                match request.json(body).send().await {
                    Ok(response) => match self.handle_response(response).await {
                        Ok(data) => AttemptOutcome::Success(data),
                        Err(e) if e.is_retryable() => AttemptOutcome::Retryable {
                            retry_after: e.retry_after(),
                            error: e,
                        },
                        Err(e) => AttemptOutcome::Terminal(e),
                    },
                    Err(e) if e.is_timeout() || e.is_connect() => AttemptOutcome::Retryable {
                        error: AnthropicError::Http(e),
                        retry_after: None,
                    },
                    Err(e) => AttemptOutcome::Terminal(AnthropicError::Http(e)),
                }
            }
        })
        .await
    }

    /// Make a streaming POST request.
    async fn post_stream<T>(&self, endpoint: &str, body: &T) -> AnthropicResult<Response>
    where
        T: serde::Serialize + Sync,
    {
        let url = format!("{}{endpoint}", self.base_url);

        let request = self
            .client
            .post(&url)
            .header("anthropic-version", API_VERSION)
            .header("content-type", "application/json");
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
    async fn handle_response<R>(&self, response: Response) -> AnthropicResult<R>
    where
        R: serde::de::DeserializeOwned + Send,
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

    #[fcp_async_core::runtime::test]
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

    #[fcp_async_core::runtime::test]
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

    #[fcp_async_core::runtime::test]
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

    #[fcp_async_core::runtime::test]
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

    #[fcp_async_core::runtime::test]
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

    #[fcp_async_core::runtime::test(flavor = "current_thread")]
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

    #[fcp_async_core::runtime::test]
    async fn test_model_pricing() {
        assert_eq!(Model::ClaudeOpus4_5.input_price_per_million(), 15.0);
        assert_eq!(Model::ClaudeOpus4_5.output_price_per_million(), 75.0);
        assert_eq!(Model::ClaudeSonnet4.input_price_per_million(), 3.0);
        assert_eq!(Model::ClaudeSonnet4.output_price_per_million(), 15.0);
        assert_eq!(Model::Claude3_5Haiku.input_price_per_million(), 0.25);
        assert_eq!(Model::Claude3_5Haiku.output_price_per_million(), 1.25);
    }

    #[fcp_async_core::runtime::test]
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
    }

    // ---- Auth tests ----

    #[test]
    fn auth_api_key_redacted_label() {
        let auth = AnthropicAuth::ApiKey("secret-key".into());
        assert_eq!(auth.redacted_label(), "api_key:redacted");
    }

    #[test]
    fn auth_credential_id_redacted_label() {
        let cred_id = fcp_core::CredentialId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
        let auth = AnthropicAuth::CredentialId(cred_id);
        let label = auth.redacted_label();
        assert!(label.starts_with("credential_id:"));
    }

    #[test]
    fn auth_api_key_not_secretless() {
        let auth = AnthropicAuth::ApiKey("key".into());
        assert!(!auth.is_secretless());
    }

    #[test]
    fn auth_credential_id_is_secretless() {
        let cred_id = fcp_core::CredentialId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
        let auth = AnthropicAuth::CredentialId(cred_id);
        assert!(auth.is_secretless());
    }

    #[test]
    fn auth_debug_api_key_redacted() {
        let auth = AnthropicAuth::ApiKey("super-secret".into());
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains("super-secret"));
    }

    #[test]
    fn auth_debug_credential_id() {
        let cred_id = fcp_core::CredentialId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
        let auth = AnthropicAuth::CredentialId(cred_id);
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn auth_clone_api_key() {
        let original = AnthropicAuth::ApiKey("clone-me".into());
        let cloned = original.clone();
        drop(original);
        assert!(!cloned.is_secretless());
        assert_eq!(cloned.redacted_label(), "api_key:redacted");
    }

    // ---- Client construction tests ----

    #[test]
    fn client_new_default_base_url() {
        let client = AnthropicClient::new("test-key").unwrap();
        assert_eq!(client.total_input_tokens(), 0);
        assert_eq!(client.total_output_tokens(), 0);
    }

    #[test]
    fn client_with_base_url_changes_url() {
        let client = AnthropicClient::new("key")
            .unwrap()
            .with_base_url("https://custom.api.com");
        let dbg = format!("{client:?}");
        assert!(dbg.contains("custom.api.com"));
    }

    #[test]
    fn client_with_retry_config() {
        let client = AnthropicClient::new("key")
            .unwrap()
            .with_retry_config(5, 100, 60_000);
        let dbg = format!("{client:?}");
        assert!(dbg.contains("max_retries: 5"));
    }

    #[test]
    fn client_debug_format() {
        let client = AnthropicClient::new("secret-key").unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("AnthropicClient"));
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains("secret-key"));
    }

    #[test]
    fn client_reset_token_counts() {
        let client = AnthropicClient::new("key").unwrap();
        client
            .total_input_tokens
            .store(100, std::sync::atomic::Ordering::Relaxed);
        client
            .total_output_tokens
            .store(50, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(client.total_input_tokens(), 100);
        assert_eq!(client.total_output_tokens(), 50);
        client.reset_token_counts();
        assert_eq!(client.total_input_tokens(), 0);
        assert_eq!(client.total_output_tokens(), 0);
    }

    #[test]
    fn client_track_usage() {
        let client = AnthropicClient::new("key").unwrap();
        let usage = Usage {
            input_tokens: 100,
            output_tokens: 50,
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: 0,
        };
        client.track_usage(&usage);
        assert_eq!(client.total_input_tokens(), 100);
        assert_eq!(client.total_output_tokens(), 50);
        client.track_usage(&usage);
        assert_eq!(client.total_input_tokens(), 200);
        assert_eq!(client.total_output_tokens(), 100);
    }

    #[test]
    fn client_auth_accessor() {
        let client = AnthropicClient::new("test-key").unwrap();
        assert!(!client.auth().is_secretless());
    }

    // ---- SSE parsing additional tests ----

    #[test]
    fn parse_sse_event_message_stop() {
        let event = parse_sse_event("event: message_stop\ndata: {\"type\":\"message_stop\"}\n");
        let event = event.unwrap().unwrap();
        assert!(matches!(event, StreamEvent::MessageStop));
    }

    #[test]
    fn parse_sse_event_content_block_stop() {
        let event = parse_sse_event(
            "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n",
        );
        let event = event.unwrap().unwrap();
        match event {
            StreamEvent::ContentBlockStop { index } => assert_eq!(index, 0),
            _ => panic!("expected ContentBlockStop"),
        }
    }

    #[test]
    fn parse_sse_event_error() {
        let event = parse_sse_event(
            "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"api_error\",\"message\":\"fail\"}}\n",
        );
        let event = event.unwrap().unwrap();
        match event {
            StreamEvent::Error { error } => {
                assert_eq!(error.error_type, "api_error");
                assert_eq!(error.message, "fail");
            }
            _ => panic!("expected Error"),
        }
    }

    #[test]
    fn parse_sse_event_no_data() {
        let event = parse_sse_event("event: ping\n");
        assert!(event.is_none());
    }

    #[test]
    fn parse_sse_event_empty_string() {
        let event = parse_sse_event("");
        assert!(event.is_none());
    }

    #[test]
    fn parse_sse_event_message_start() {
        let event = parse_sse_event(
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"role\":\"assistant\",\"model\":\"claude-sonnet-4-20250514\",\"usage\":{\"input_tokens\":10,\"output_tokens\":0}}}\n",
        );
        let event = event.unwrap().unwrap();
        match event {
            StreamEvent::MessageStart { message } => {
                assert_eq!(message.id, "msg_1");
                assert_eq!(message.role, crate::types::Role::Assistant);
            }
            _ => panic!("expected MessageStart"),
        }
    }

    // ---- parse_error_response tests ----

    #[test]
    fn parse_error_response_429() {
        let bytes = bytes::Bytes::from(
            r#"{"error":{"type":"rate_limit_error","message":"Rate limit exceeded"}}"#,
        );
        let err = parse_error_response(StatusCode::TOO_MANY_REQUESTS, &bytes);
        assert!(matches!(err, AnthropicError::RateLimited { .. }));
    }

    #[test]
    fn parse_error_response_529() {
        let bytes =
            bytes::Bytes::from(r#"{"error":{"type":"overloaded_error","message":"Overloaded"}}"#);
        let err = parse_error_response(StatusCode::from_u16(529).unwrap(), &bytes);
        assert!(matches!(err, AnthropicError::Overloaded { .. }));
    }

    #[test]
    fn parse_error_response_401() {
        let bytes = bytes::Bytes::from(
            r#"{"error":{"type":"authentication_error","message":"Invalid key"}}"#,
        );
        let err = parse_error_response(StatusCode::UNAUTHORIZED, &bytes);
        assert!(matches!(err, AnthropicError::InvalidApiKey));
    }

    #[test]
    fn parse_error_response_context_length() {
        let bytes = bytes::Bytes::from(
            r#"{"error":{"type":"invalid_request_error","message":"context length exceeded"}}"#,
        );
        let err = parse_error_response(StatusCode::BAD_REQUEST, &bytes);
        assert!(matches!(err, AnthropicError::ContextLengthExceeded { .. }));
    }

    #[test]
    fn parse_error_response_generic_api_error() {
        let bytes = bytes::Bytes::from(
            r#"{"error":{"type":"not_found_error","message":"Model not found"}}"#,
        );
        let err = parse_error_response(StatusCode::NOT_FOUND, &bytes);
        match err {
            AnthropicError::Api {
                error_type,
                message,
                status_code,
            } => {
                assert_eq!(error_type, "not_found_error");
                assert_eq!(message, "Model not found");
                assert_eq!(status_code, Some(404));
            }
            _ => panic!("expected Api error"),
        }
    }

    #[test]
    fn parse_error_response_unparseable() {
        let bytes = bytes::Bytes::from("not json");
        let err = parse_error_response(StatusCode::INTERNAL_SERVER_ERROR, &bytes);
        match err {
            AnthropicError::Api {
                error_type,
                message,
                status_code,
            } => {
                assert_eq!(error_type, "unknown");
                assert_eq!(message, "not json");
                assert_eq!(status_code, Some(500));
            }
            _ => panic!("expected Api error"),
        }
    }

    // ---- DEFAULT_BASE_URL ----

    #[test]
    fn default_base_url_is_anthropic() {
        assert_eq!(DEFAULT_BASE_URL, "https://api.anthropic.com");
    }
}
