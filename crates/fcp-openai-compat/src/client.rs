//! HTTP client implementation.

use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::{Duration, Instant};

use bytes::Bytes;
use fcp_async_core::bytes::Buf as _;
use fcp_async_core::http::body::Body as _;
use fcp_async_core::http::client_io::ClientIo;
use fcp_async_core::http::{ClientIncomingBody, HttpClient, Method};
use fcp_async_core::{Cx, time};
use futures_util::Stream;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::error::{NetworkError, OpenAiError, StreamingError, truncate_response_body};
use crate::rate_limit::{
    HeaderList, RateLimitConfig, RateLimitPolicy, RateLimitSnapshot, parse_rate_limit_headers,
    upsert_header,
};
use crate::sse::{OpenAiSseDecoder, OpenAiStreamEvent};
use crate::types::{
    ChatChunk, ChatCompletionsRequest, ChatCompletionsResponse, CompletionsRequest,
    CompletionsResponse, EmbeddingsRequest, EmbeddingsResponse, ModelInfo, ModelsResponse,
};

const ACCEPT_HEADER: &str = "Accept";
const AUTHORIZATION_HEADER: &str = "Authorization";
const CONTENT_TYPE_HEADER: &str = "Content-Type";
const JSON_CONTENT_TYPE: &str = "application/json";
const USER_AGENT_HEADER: &str = "User-Agent";

static DEFAULT_ERROR_MAPPER: DefaultOpenAiErrorMapper = DefaultOpenAiErrorMapper;

/// Mutable request metadata passed to provider auth hooks.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HttpRequest {
    /// Request headers.
    pub headers: HeaderList,
}

impl HttpRequest {
    /// Add or replace a header.
    pub fn upsert_header(&mut self, name: impl Into<String>, value: impl Into<String>) {
        upsert_header(&mut self.headers, name, value);
    }

    /// Add an Authorization bearer token without storing it in this crate.
    pub fn bearer_auth(&mut self, bearer: &str) {
        self.upsert_header(AUTHORIZATION_HEADER, format!("Bearer {bearer}"));
    }
}

/// Provider policy for an OpenAI-compatible endpoint.
pub trait OpenAiCompatProvider: Send + Sync + 'static {
    /// Base URL, for example `https://api.groq.com/openai/v1`.
    fn base_url(&self) -> &str;

    /// Apply provider authentication headers.
    fn auth_header(&self, req: &mut HttpRequest);

    /// Connector-specific user agent.
    fn user_agent(&self) -> &'static str;

    /// Provider name for diagnostics.
    fn provider_name(&self) -> &'static str;

    /// Provider-specific rate-limit header overrides.
    fn rate_limit_overrides(&self) -> Option<RateLimitConfig> {
        None
    }

    /// Provider-specific error mapper.
    fn error_mapper(&self) -> &dyn ErrorMapper {
        &DEFAULT_ERROR_MAPPER
    }

    /// Extra request headers for a model.
    fn extra_request_headers(&self, _model: &str) -> HeaderList {
        Vec::new()
    }
}

/// Maps provider error responses into the shared taxonomy.
pub trait ErrorMapper: Send + Sync {
    /// Map a non-success HTTP response.
    fn map_response(
        &self,
        provider: &str,
        status: u16,
        headers: &HeaderList,
        body: &[u8],
        rate_limits: RateLimitSnapshot,
    ) -> OpenAiError;
}

/// Default OpenAI-compatible error mapper.
#[derive(Debug, Clone, Copy)]
pub struct DefaultOpenAiErrorMapper;

#[derive(Debug, serde::Deserialize)]
struct ProviderErrorEnvelope {
    error: Option<ProviderErrorBody>,
}

#[derive(Debug, serde::Deserialize)]
struct ProviderErrorBody {
    #[serde(rename = "type")]
    error_type: Option<String>,
    message: Option<String>,
    param: Option<String>,
    code: Option<String>,
}

impl ErrorMapper for DefaultOpenAiErrorMapper {
    fn map_response(
        &self,
        provider: &str,
        status: u16,
        _headers: &HeaderList,
        body: &[u8],
        rate_limits: RateLimitSnapshot,
    ) -> OpenAiError {
        let body_text = truncate_response_body(body);
        let parsed = serde_json::from_slice::<ProviderErrorEnvelope>(body)
            .ok()
            .and_then(|envelope| envelope.error);
        let message = parsed
            .as_ref()
            .and_then(|error| error.message.clone())
            .filter(|message| !message.trim().is_empty())
            .unwrap_or_else(|| {
                if body_text.trim().is_empty() {
                    format!("HTTP {status}")
                } else {
                    body_text.clone()
                }
            });
        let error_type = parsed
            .as_ref()
            .and_then(|error| error.error_type.as_deref());
        let param = parsed.as_ref().and_then(|error| error.param.clone());
        let code = parsed.as_ref().and_then(|error| error.code.clone());

        match status {
            400 => OpenAiError::InvalidRequest {
                message,
                param,
                code,
            },
            401 => OpenAiError::Authentication { message },
            403 => OpenAiError::PermissionDenied { message },
            404 => OpenAiError::NotFound {
                message,
                resource: param,
            },
            429 => OpenAiError::RateLimited {
                message,
                retry_after: rate_limits.retry_after,
            },
            500 => OpenAiError::InternalError { message },
            503 => OpenAiError::ServiceUnavailable {
                message,
                retry_after: rate_limits.retry_after,
            },
            _ if matches!(error_type, Some("rate_limit" | "rate_limit_error")) => {
                OpenAiError::RateLimited {
                    message,
                    retry_after: rate_limits.retry_after,
                }
            }
            _ => OpenAiError::Provider {
                provider: provider.to_string(),
                status,
                body: body_text,
            },
        }
    }
}

/// Client behavior knobs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenAiCompatClientConfig {
    /// Timeout for non-streaming request/response APIs.
    pub request_timeout: Duration,
    /// Model-list cache time-to-live.
    pub model_cache_ttl: Duration,
    /// Rate-limit retry behavior.
    pub rate_limit_policy: RateLimitPolicy,
}

impl Default for OpenAiCompatClientConfig {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(60),
            model_cache_ttl: Duration::from_secs(60 * 60),
            rate_limit_policy: RateLimitPolicy::FailFast,
        }
    }
}

#[derive(Debug, Clone)]
struct ModelCache {
    fetched_at: Instant,
    models: Vec<ModelInfo>,
}

/// OpenAI-compatible HTTP client.
pub struct OpenAiCompatClient<P: OpenAiCompatProvider> {
    provider: P,
    http_client: Arc<HttpClient>,
    config: OpenAiCompatClientConfig,
    model_cache: fcp_async_core::sync::Mutex<Option<ModelCache>>,
}

impl<P: OpenAiCompatProvider> OpenAiCompatClient<P> {
    /// Create a client from provider policy and injected HTTP client.
    pub fn new(provider: P, http_client: HttpClient) -> Self {
        Self::new_with_config(provider, http_client, OpenAiCompatClientConfig::default())
    }

    /// Create a client with explicit behavior knobs.
    pub fn new_with_config(
        provider: P,
        http_client: HttpClient,
        config: OpenAiCompatClientConfig,
    ) -> Self {
        Self {
            provider,
            http_client: Arc::new(http_client),
            config,
            model_cache: fcp_async_core::sync::Mutex::new(None),
        }
    }

    /// Provider policy.
    pub const fn provider(&self) -> &P {
        &self.provider
    }

    /// Invalidate the model-list cache.
    pub async fn invalidate_model_cache(&self) {
        *self.model_cache.lock().await = None;
    }

    /// Send a non-streaming chat-completions request.
    pub async fn chat_completions(
        &self,
        cx: &Cx,
        mut req: ChatCompletionsRequest,
    ) -> Result<ChatCompletionsResponse, OpenAiError> {
        req.stream = false;
        self.request_json(cx, Method::Post, "/chat/completions", &req.model, &req)
            .await
    }

    /// Send a streaming chat-completions request.
    pub async fn chat_completions_stream(
        &self,
        cx: &Cx,
        mut req: ChatCompletionsRequest,
    ) -> Result<ChatCompletionStream, OpenAiError> {
        req.stream = true;
        let response = self
            .request_streaming(cx, "/chat/completions", &req.model, &req)
            .await?;
        Ok(ChatCompletionStream::new(cx.clone(), response))
    }

    /// Send an embeddings request.
    pub async fn embeddings(
        &self,
        cx: &Cx,
        req: EmbeddingsRequest,
    ) -> Result<EmbeddingsResponse, OpenAiError> {
        self.request_json(cx, Method::Post, "/embeddings", &req.model, &req)
            .await
    }

    /// List models, using the configured in-memory cache.
    pub async fn list_models(&self, cx: &Cx) -> Result<Vec<ModelInfo>, OpenAiError> {
        {
            let guard = self.model_cache.lock().await;
            if let Some(cache) = guard.as_ref() {
                if cache.fetched_at.elapsed() <= self.config.model_cache_ttl {
                    return Ok(cache.models.clone());
                }
            }
        }

        let response: ModelsResponse = self
            .request_json(cx, Method::Get, "/models", "", &())
            .await?;
        *self.model_cache.lock().await = Some(ModelCache {
            fetched_at: Instant::now(),
            models: response.data.clone(),
        });
        Ok(response.data)
    }

    /// Send a legacy completions request.
    pub async fn legacy_completions(
        &self,
        cx: &Cx,
        req: CompletionsRequest,
    ) -> Result<CompletionsResponse, OpenAiError> {
        self.request_json(cx, Method::Post, "/completions", &req.model, &req)
            .await
    }

    async fn request_json<T, R>(
        &self,
        cx: &Cx,
        method: Method,
        path: &str,
        model: &str,
        body: &T,
    ) -> Result<R, OpenAiError>
    where
        T: Serialize + Sync + ?Sized,
        R: DeserializeOwned,
    {
        let mut attempted_rate_limit_retry = false;
        loop {
            checkpoint(cx)?;
            let body_bytes = if matches!(method, Method::Get) {
                Vec::new()
            } else {
                serde_json::to_vec(body).map_err(|err| OpenAiError::InvalidRequest {
                    message: format!("failed to serialize request: {err}"),
                    param: None,
                    code: Some("serialize_request".to_string()),
                })?
            };
            let headers = self.headers_for(model);
            let url = self.url(path);
            let request = self
                .http_client
                .request(cx, method.clone(), &url, headers, body_bytes);
            let response = match time::timeout(self.config.request_timeout, request).await {
                Ok(Ok(response)) => response,
                Ok(Err(err)) => return Err(OpenAiError::Network(err.into())),
                Err(err) => {
                    return Err(OpenAiError::Network(NetworkError::Http {
                        message: err.to_string(),
                    }));
                }
            };

            let status = response.status_code();
            let rate_limits = parse_rate_limit_headers(
                &response.headers,
                self.provider.rate_limit_overrides().as_ref(),
            );
            if !status.is_success() {
                let mapped = self.provider.error_mapper().map_response(
                    self.provider.provider_name(),
                    status.as_u16(),
                    &response.headers,
                    &response.body,
                    rate_limits,
                );
                if !attempted_rate_limit_retry {
                    if let Some(delay) =
                        retry_delay_for_policy(&mapped, self.config.rate_limit_policy)
                    {
                        attempted_rate_limit_retry = true;
                        time::sleep(delay).await;
                        continue;
                    }
                }
                return Err(mapped);
            }

            checkpoint(cx)?;
            return serde_json::from_slice(&response.body).map_err(|err| {
                OpenAiError::InvalidRequest {
                    message: format!("failed to decode provider response: {err}"),
                    param: None,
                    code: Some("decode_response".to_string()),
                }
            });
        }
    }

    async fn request_streaming<T>(
        &self,
        cx: &Cx,
        path: &str,
        model: &str,
        body: &T,
    ) -> Result<ClientIncomingBody<ClientIo>, OpenAiError>
    where
        T: Serialize + Sync + ?Sized,
    {
        checkpoint(cx)?;
        let body_bytes = serde_json::to_vec(body).map_err(|err| OpenAiError::InvalidRequest {
            message: format!("failed to serialize request: {err}"),
            param: None,
            code: Some("serialize_request".to_string()),
        })?;
        let response = self
            .http_client
            .request_streaming(
                cx,
                Method::Post,
                &self.url(path),
                self.headers_for(model),
                body_bytes,
            )
            .await
            .map_err(|err| OpenAiError::Network(err.into()))?;
        if !(200..300).contains(&response.head.status) {
            let rate_limits = parse_rate_limit_headers(
                &response.head.headers,
                self.provider.rate_limit_overrides().as_ref(),
            );
            return Err(self.provider.error_mapper().map_response(
                self.provider.provider_name(),
                response.head.status,
                &response.head.headers,
                response.head.reason.as_bytes(),
                rate_limits,
            ));
        }
        Ok(response.body)
    }

    fn headers_for(&self, model: &str) -> HeaderList {
        let mut request = HttpRequest {
            headers: vec![
                (ACCEPT_HEADER.to_string(), JSON_CONTENT_TYPE.to_string()),
                (
                    CONTENT_TYPE_HEADER.to_string(),
                    JSON_CONTENT_TYPE.to_string(),
                ),
                (
                    USER_AGENT_HEADER.to_string(),
                    self.provider.user_agent().to_string(),
                ),
            ],
        };
        request
            .headers
            .extend(self.provider.extra_request_headers(model));
        self.provider.auth_header(&mut request);
        request.headers
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.provider.base_url().trim_end_matches('/'), path)
    }
}

fn retry_delay_for_policy(error: &OpenAiError, policy: RateLimitPolicy) -> Option<Duration> {
    let retry_after = error.retry_after()?;
    match policy {
        RateLimitPolicy::WaitUpTo(max_wait) if retry_after <= max_wait => Some(retry_after),
        RateLimitPolicy::FailFast | RateLimitPolicy::WaitUpTo(_) => None,
        RateLimitPolicy::WaitForever => Some(retry_after),
    }
}

fn checkpoint(cx: &Cx) -> Result<(), OpenAiError> {
    cx.checkpoint().map_err(|err| {
        OpenAiError::Network(NetworkError::Cancelled {
            message: err.to_string(),
        })
    })
}

/// Streaming chat-completion chunks.
pub struct ChatCompletionStream {
    cx: Cx,
    body: Option<Pin<Box<ClientIncomingBody<ClientIo>>>>,
    decoder: OpenAiSseDecoder,
    pending: VecDeque<Result<ChatChunk, OpenAiError>>,
    finished: bool,
}

impl ChatCompletionStream {
    fn new(cx: Cx, body: ClientIncomingBody<ClientIo>) -> Self {
        Self {
            cx,
            body: Some(Box::pin(body)),
            decoder: OpenAiSseDecoder::new(),
            pending: VecDeque::new(),
            finished: false,
        }
    }

    fn enqueue_events(&mut self, events: Vec<Result<OpenAiStreamEvent, OpenAiError>>) {
        for event in events {
            match event {
                Ok(OpenAiStreamEvent::Chunk(chunk)) => self.pending.push_back(Ok(chunk)),
                Ok(OpenAiStreamEvent::Done) => {
                    self.finished = true;
                    self.body = None;
                }
                Err(err) => {
                    self.finished = true;
                    self.body = None;
                    self.pending.push_back(Err(err));
                }
            }
        }
    }
}

impl Stream for ChatCompletionStream {
    type Item = Result<ChatChunk, OpenAiError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        if let Some(event) = this.pending.pop_front() {
            return Poll::Ready(Some(event));
        }
        if this.finished {
            return Poll::Ready(None);
        }

        loop {
            let Some(body) = this.body.as_mut() else {
                this.finished = true;
                return Poll::Ready(None);
            };

            match ready!(body.as_mut().poll_frame(cx)) {
                Some(Ok(frame)) => {
                    if let Err(err) = checkpoint(&this.cx) {
                        this.finished = true;
                        this.body = None;
                        return Poll::Ready(Some(Err(err)));
                    }
                    if let Some(data) = frame.into_data() {
                        let bytes = Bytes::copy_from_slice(data.chunk());
                        let events = this.decoder.feed(&bytes);
                        this.enqueue_events(events);
                        if let Some(event) = this.pending.pop_front() {
                            return Poll::Ready(Some(event));
                        }
                        if this.finished {
                            return Poll::Ready(None);
                        }
                    }
                }
                Some(Err(error)) => {
                    this.finished = true;
                    this.body = None;
                    return Poll::Ready(Some(Err(OpenAiError::Streaming(
                        StreamingError::MalformedPayload {
                            message: error.to_string(),
                        },
                    ))));
                }
                None => {
                    this.body = None;
                    this.finished = true;
                    return match this.decoder.finish() {
                        Some(Ok(OpenAiStreamEvent::Chunk(chunk))) => Poll::Ready(Some(Ok(chunk))),
                        Some(Ok(OpenAiStreamEvent::Done)) | None => Poll::Ready(None),
                        Some(Err(err)) => Poll::Ready(Some(Err(err))),
                    };
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[derive(Clone)]
    struct TestProvider {
        base_url: String,
    }

    impl OpenAiCompatProvider for TestProvider {
        fn base_url(&self) -> &str {
            &self.base_url
        }

        fn auth_header(&self, req: &mut HttpRequest) {
            req.bearer_auth("test-token");
        }

        fn user_agent(&self) -> &'static str {
            "fcp-openai-compat-test/0.1.0"
        }

        fn provider_name(&self) -> &'static str {
            "test"
        }
    }

    #[test]
    fn provider_headers_include_auth_user_agent_and_content_type() {
        let client = OpenAiCompatClient::new(
            TestProvider {
                base_url: "https://example.test/v1".to_string(),
            },
            fcp_async_core::http::HttpClientBuilder::new().build(),
        );

        let headers = client.headers_for("model");
        assert!(
            headers.iter().any(|(name, value)| {
                name == AUTHORIZATION_HEADER && value == "Bearer test-token"
            })
        );
        assert!(
            headers
                .iter()
                .any(|(name, value)| name == USER_AGENT_HEADER && value.contains("test"))
        );
        assert!(
            headers
                .iter()
                .any(|(name, value)| name == CONTENT_TYPE_HEADER && value == JSON_CONTENT_TYPE)
        );
    }

    #[test]
    fn default_error_mapper_maps_provider_taxonomy() {
        let body = json!({
            "error": {
                "type": "invalid_request_error",
                "message": "bad input",
                "param": "messages",
                "code": "bad_messages"
            }
        })
        .to_string();
        let err = DefaultOpenAiErrorMapper.map_response(
            "test",
            400,
            &Vec::new(),
            body.as_bytes(),
            RateLimitSnapshot::default(),
        );
        assert!(matches!(
            err,
            OpenAiError::InvalidRequest {
                param: Some(_),
                code: Some(_),
                ..
            }
        ));
    }

    #[test]
    fn retry_policy_wait_up_to_honors_budget() {
        let err = OpenAiError::RateLimited {
            message: "slow down".to_string(),
            retry_after: Some(Duration::from_secs(2)),
        };
        assert_eq!(
            retry_delay_for_policy(&err, RateLimitPolicy::WaitUpTo(Duration::from_secs(5))),
            Some(Duration::from_secs(2))
        );
        assert_eq!(
            retry_delay_for_policy(&err, RateLimitPolicy::WaitUpTo(Duration::from_secs(1))),
            None
        );
    }
}
