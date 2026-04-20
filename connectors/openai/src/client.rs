//! OpenAI API client.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use fcp_core::CredentialId;
use fcp_sdk::migration::{
    AttemptOutcome, ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig, RetryLoop,
};
use futures_util::{Stream, StreamExt};
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{OpenAIError, OpenAIResult},
    types::{
        ApiError, Assistant, AssistantListResponse, ChatCompletionChunk, ChatCompletionRequest,
        ChatCompletionResponse, CreateAssistantRequest, CreateFineTuneRequest, EmbeddingInput,
        EmbeddingModel, EmbeddingRequest, EmbeddingResponse, FineTuneEventListResponse,
        FineTuneHyperparameters, FineTuneJob, FineTuneListResponse, ImageGenerationRequest,
        ImageGenerationResponse, ImageModel, ImageQuality, ImageSize, Message, Model, Run,
        RunListResponse, Thread, ThreadMessage, ThreadMessageListResponse, Tool, ToolChoice,
        TranscriptionResponse, TtsModel, TtsRequest, TtsResponseFormat, TtsVoice, Usage,
        WhisperModel,
    },
};

/// Default API base URL.
pub const DEFAULT_BASE_URL: &str = "https://api.openai.com";
const MAX_RETRY_AFTER_MS: u64 = 300_000;
const MAX_ERROR_MESSAGE_CHARS: usize = 512;

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
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
    // Usage tracking
    total_prompt_tokens: AtomicU64,
    total_completion_tokens: AtomicU64,
}

impl OpenAIClient {
    /// Create a new OpenAI client.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be constructed.
    pub fn new(api_key: impl Into<String>) -> OpenAIResult<Self> {
        Self::new_with_auth(OpenAIAuth::ApiKey(api_key.into()))
    }

    /// Create a new OpenAI client with explicit auth mode.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be constructed.
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
            runtime: ConnectorRuntime::new(ConnectorRuntimeConfig::default()),
            retry_config: HttpRetryConfig::default(),
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
        self.retry_config = HttpRetryConfig {
            max_retries,
            initial_delay_ms,
            max_delay_ms,
            ..self.retry_config
        };
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
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails or the API returns a non-success status.
    pub async fn health_check(&self) -> OpenAIResult<()> {
        let url = format!("{}/v1/models", self.base_url);
        let request = self
            .client
            .get(&url)
            .header("Content-Type", "application/json");
        let request = self.apply_auth(request);

        let response = request.send().await?;
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.bytes().await?;
        if status.is_success() {
            Ok(())
        } else {
            Err(parse_error_response(status, &headers, &bytes))
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
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, authentication errors, or invalid request parameters.
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
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, or authentication errors.
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
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, or authentication errors.
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

    /// Create embeddings for the given input text(s).
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, authentication errors,
    /// or if the input exceeds model limits.
    #[instrument(skip(self, input))]
    pub async fn create_embeddings(
        &self,
        model: EmbeddingModel,
        input: EmbeddingInput,
        dimensions: Option<u32>,
    ) -> OpenAIResult<EmbeddingResponse> {
        let request = EmbeddingRequest {
            model: model.as_str().into(),
            input,
            encoding_format: Some("float".into()),
            dimensions,
        };

        self.post("/v1/embeddings", &request).await
    }

    /// Generate images from a text prompt.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, authentication errors,
    /// or if the prompt violates content policy.
    #[instrument(skip(self, prompt))]
    pub async fn generate_image(
        &self,
        model: ImageModel,
        prompt: &str,
        n: Option<u32>,
        size: Option<ImageSize>,
        quality: Option<ImageQuality>,
    ) -> OpenAIResult<ImageGenerationResponse> {
        let request = ImageGenerationRequest {
            model: model.as_str().into(),
            prompt: prompt.to_string(),
            n,
            size,
            quality,
            response_format: "b64_json".into(),
        };

        self.post("/v1/images/generations", &request).await
    }

    /// Transcribe audio using the Whisper model.
    ///
    /// The audio data is sent as a multipart form upload.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, authentication errors,
    /// or if the audio data is invalid.
    #[instrument(skip(self, audio_data))]
    pub async fn create_transcription(
        &self,
        model: WhisperModel,
        audio_data: Vec<u8>,
        filename: &str,
        language: Option<&str>,
    ) -> OpenAIResult<TranscriptionResponse> {
        let url = format!("{}/v1/audio/transcriptions", self.base_url);

        let file_part = reqwest::multipart::Part::bytes(audio_data)
            .file_name(filename.to_string())
            .mime_str("application/octet-stream")
            .map_err(|e| OpenAIError::Api {
                error_type: "multipart_error".into(),
                message: e.to_string(),
                status_code: None,
            })?;

        let mut form = reqwest::multipart::Form::new()
            .text("model", model.as_str().to_string())
            .text("response_format", "json".to_string())
            .part("file", file_part);

        if let Some(lang) = language {
            form = form.text("language", lang.to_string());
        }

        let request = self.client.post(&url);
        let request = self.apply_auth(request);

        let response = request.multipart(form).send().await?;
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.bytes().await?;

        if status.is_success() {
            serde_json::from_slice(&bytes).map_err(OpenAIError::from)
        } else {
            Err(parse_error_response(status, &headers, &bytes))
        }
    }

    /// Generate speech audio from text using TTS models.
    ///
    /// Returns raw audio bytes in the requested format.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, authentication errors,
    /// or if the input text exceeds the 4096 character limit.
    #[instrument(skip(self, input))]
    pub async fn create_speech(
        &self,
        model: TtsModel,
        input: &str,
        voice: TtsVoice,
        response_format: Option<TtsResponseFormat>,
        speed: Option<f64>,
    ) -> OpenAIResult<Vec<u8>> {
        let url = format!("{}/v1/audio/speech", self.base_url);

        let request_body = TtsRequest {
            model: model.as_str().into(),
            input: input.to_string(),
            voice: voice.as_str().into(),
            response_format: response_format.map(|f| f.as_str().into()),
            speed,
        };

        let request = self
            .client
            .post(&url)
            .header("Content-Type", "application/json");
        let request = self.apply_auth(request);

        let response = request.json(&request_body).send().await?;
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.bytes().await?;

        if status.is_success() {
            Ok(bytes.to_vec())
        } else {
            Err(parse_error_response(status, &headers, &bytes))
        }
    }

    /// Create a fine-tuning job.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, or authentication errors.
    #[instrument(skip(self))]
    pub async fn create_fine_tune(
        &self,
        model: &str,
        training_file: &str,
        validation_file: Option<&str>,
        hyperparameters: Option<FineTuneHyperparameters>,
        suffix: Option<&str>,
    ) -> OpenAIResult<FineTuneJob> {
        let request = CreateFineTuneRequest {
            model: model.to_string(),
            training_file: training_file.to_string(),
            validation_file: validation_file.map(String::from),
            hyperparameters,
            suffix: suffix.map(String::from),
        };

        self.post("/v1/fine_tuning/jobs", &request).await
    }

    /// List fine-tuning jobs.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, or authentication errors.
    #[instrument(skip(self))]
    pub async fn list_fine_tunes(
        &self,
        limit: Option<u32>,
        after: Option<&str>,
    ) -> OpenAIResult<FineTuneListResponse> {
        let mut url = format!("{}/v1/fine_tuning/jobs", self.base_url);
        let mut params = Vec::new();
        if let Some(limit) = limit {
            params.push(format!("limit={limit}"));
        }
        if let Some(after) = after {
            params.push(format!("after={after}"));
        }
        if !params.is_empty() {
            url.push('?');
            url.push_str(&params.join("&"));
        }

        self.get(&url).await
    }

    /// Get a fine-tuning job by ID.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, or authentication errors.
    #[instrument(skip(self))]
    pub async fn get_fine_tune(&self, job_id: &str) -> OpenAIResult<FineTuneJob> {
        let url = format!("{}/v1/fine_tuning/jobs/{job_id}", self.base_url);
        self.get(&url).await
    }

    /// Cancel a fine-tuning job.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, or authentication errors.
    #[instrument(skip(self))]
    pub async fn cancel_fine_tune(&self, job_id: &str) -> OpenAIResult<FineTuneJob> {
        let url = format!("{}/v1/fine_tuning/jobs/{job_id}/cancel", self.base_url);

        let request = self
            .client
            .post(&url)
            .header("Content-Type", "application/json");
        let request = self.apply_auth(request);

        let response = request.send().await?;
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.bytes().await?;

        if status.is_success() {
            serde_json::from_slice(&bytes).map_err(OpenAIError::from)
        } else {
            Err(parse_error_response(status, &headers, &bytes))
        }
    }

    /// List events for a fine-tuning job.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, or authentication errors.
    #[instrument(skip(self))]
    pub async fn list_fine_tune_events(
        &self,
        job_id: &str,
        limit: Option<u32>,
        after: Option<&str>,
    ) -> OpenAIResult<FineTuneEventListResponse> {
        let mut url = format!("{}/v1/fine_tuning/jobs/{job_id}/events", self.base_url);
        let mut params = Vec::new();
        if let Some(limit) = limit {
            params.push(format!("limit={limit}"));
        }
        if let Some(after) = after {
            params.push(format!("after={after}"));
        }
        if !params.is_empty() {
            url.push('?');
            url.push_str(&params.join("&"));
        }

        self.get(&url).await
    }

    /// Make a GET request with auth headers.
    async fn get<R>(&self, url: &str) -> OpenAIResult<R>
    where
        R: serde::de::DeserializeOwned + Send,
    {
        let request = self.client.get(url);
        let request = self.apply_auth(request);

        let response = request.send().await?;
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.bytes().await?;

        if status.is_success() {
            serde_json::from_slice(&bytes).map_err(OpenAIError::from)
        } else {
            Err(parse_error_response(status, &headers, &bytes))
        }
    }

    /// Make a POST request with retry via the migration framework.
    async fn post<T, R>(&self, endpoint: &str, body: &T) -> OpenAIResult<R>
    where
        T: serde::Serialize + Sync,
        R: serde::de::DeserializeOwned + Send,
    {
        let url = format!("{}{endpoint}", self.base_url);
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = &url;
            async move {
                debug!(attempt, endpoint, "Making OpenAI API request");

                let request = self
                    .client
                    .post(url)
                    .header("Content-Type", "application/json");

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
                        error: OpenAIError::Http(e),
                        retry_after: None,
                    },
                    Err(e) => AttemptOutcome::Terminal(OpenAIError::Http(e)),
                }
            }
        })
        .await
    }

    /// Make a streaming POST request.
    async fn post_stream<T>(&self, endpoint: &str, body: &T) -> OpenAIResult<Response>
    where
        T: serde::Serialize + Sync,
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
            let headers = response.headers().clone();
            let bytes = response.bytes().await?;
            return Err(parse_error_response(status, &headers, &bytes));
        }

        Ok(response)
    }

    /// Handle a response.
    async fn handle_response<R>(&self, response: Response) -> OpenAIResult<R>
    where
        R: serde::de::DeserializeOwned + Send,
    {
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.bytes().await?;

        if status.is_success() {
            serde_json::from_slice(&bytes).map_err(OpenAIError::from)
        } else {
            Err(parse_error_response(status, &headers, &bytes))
        }
    }

    /// Make a DELETE request with Assistants API v2 header.
    async fn delete_v2<R>(&self, url: &str) -> OpenAIResult<R>
    where
        R: serde::de::DeserializeOwned + Send,
    {
        let request = self
            .client
            .delete(url)
            .header("OpenAI-Beta", "assistants=v2");
        let request = self.apply_auth(request);

        let response = request.send().await?;
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.bytes().await?;

        if status.is_success() {
            serde_json::from_slice(&bytes).map_err(OpenAIError::from)
        } else {
            Err(parse_error_response(status, &headers, &bytes))
        }
    }

    /// Make a GET request with Assistants API v2 header.
    async fn get_v2<R>(&self, url: &str) -> OpenAIResult<R>
    where
        R: serde::de::DeserializeOwned + Send,
    {
        let request = self.client.get(url).header("OpenAI-Beta", "assistants=v2");
        let request = self.apply_auth(request);

        let response = request.send().await?;
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.bytes().await?;

        if status.is_success() {
            serde_json::from_slice(&bytes).map_err(OpenAIError::from)
        } else {
            Err(parse_error_response(status, &headers, &bytes))
        }
    }

    /// Make a POST request without a body, with Assistants API v2 header.
    async fn post_empty_v2<R>(&self, url: &str) -> OpenAIResult<R>
    where
        R: serde::de::DeserializeOwned + Send,
    {
        let request = self
            .client
            .post(url)
            .header("Content-Type", "application/json")
            .header("OpenAI-Beta", "assistants=v2");
        let request = self.apply_auth(request);

        let response = request.send().await?;
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.bytes().await?;

        if status.is_success() {
            serde_json::from_slice(&bytes).map_err(OpenAIError::from)
        } else {
            Err(parse_error_response(status, &headers, &bytes))
        }
    }

    // ─────────────────────── Assistants ───────────────────────

    /// Create an assistant.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, or authentication errors.
    #[instrument(skip(self))]
    pub async fn create_assistant(
        &self,
        request: &CreateAssistantRequest,
    ) -> OpenAIResult<Assistant> {
        let url = format!("{}/v1/assistants", self.base_url);
        self.post_json(&url, request).await
    }

    /// List assistants.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, or authentication errors.
    #[instrument(skip(self))]
    pub async fn list_assistants(
        &self,
        limit: Option<u32>,
        after: Option<&str>,
    ) -> OpenAIResult<AssistantListResponse> {
        let mut url = format!("{}/v1/assistants", self.base_url);
        let mut params = Vec::new();
        if let Some(l) = limit {
            params.push(format!("limit={l}"));
        }
        if let Some(a) = after {
            params.push(format!("after={a}"));
        }
        if !params.is_empty() {
            url.push('?');
            url.push_str(&params.join("&"));
        }
        self.get_v2(&url).await
    }

    /// Get an assistant by ID.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, or authentication errors.
    #[instrument(skip(self))]
    pub async fn get_assistant(&self, assistant_id: &str) -> OpenAIResult<Assistant> {
        let url = format!("{}/v1/assistants/{assistant_id}", self.base_url);
        self.get_v2(&url).await
    }

    /// Delete an assistant.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, or authentication errors.
    #[instrument(skip(self))]
    pub async fn delete_assistant(&self, assistant_id: &str) -> OpenAIResult<serde_json::Value> {
        let url = format!("{}/v1/assistants/{assistant_id}", self.base_url);
        self.delete_v2(&url).await
    }

    // ─────────────────────── Threads ───────────────────────

    /// Create a thread.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, or authentication errors.
    #[instrument(skip(self))]
    pub async fn create_thread(
        &self,
        messages: Option<Vec<serde_json::Value>>,
        metadata: Option<serde_json::Value>,
    ) -> OpenAIResult<Thread> {
        let url = format!("{}/v1/threads", self.base_url);
        let mut body = serde_json::Map::new();
        if let Some(msgs) = messages {
            body.insert("messages".into(), serde_json::Value::Array(msgs));
        }
        if let Some(meta) = metadata {
            body.insert("metadata".into(), meta);
        }
        self.post_json(&url, &serde_json::Value::Object(body)).await
    }

    /// Get a thread by ID.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, or authentication errors.
    #[instrument(skip(self))]
    pub async fn get_thread(&self, thread_id: &str) -> OpenAIResult<Thread> {
        let url = format!("{}/v1/threads/{thread_id}", self.base_url);
        self.get_v2(&url).await
    }

    /// Delete a thread.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, or authentication errors.
    #[instrument(skip(self))]
    pub async fn delete_thread(&self, thread_id: &str) -> OpenAIResult<serde_json::Value> {
        let url = format!("{}/v1/threads/{thread_id}", self.base_url);
        self.delete_v2(&url).await
    }

    // ─────────────────────── Thread Messages ───────────────────────

    /// Create a message in a thread.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, or authentication errors.
    #[instrument(skip(self))]
    pub async fn create_thread_message(
        &self,
        thread_id: &str,
        role: &str,
        content: &str,
        metadata: Option<serde_json::Value>,
    ) -> OpenAIResult<ThreadMessage> {
        let url = format!("{}/v1/threads/{thread_id}/messages", self.base_url);
        let mut body = serde_json::json!({
            "role": role,
            "content": content,
        });
        if let Some(meta) = metadata {
            body["metadata"] = meta;
        }
        self.post_json(&url, &body).await
    }

    /// List messages in a thread.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, or authentication errors.
    #[instrument(skip(self))]
    pub async fn list_thread_messages(
        &self,
        thread_id: &str,
        limit: Option<u32>,
        after: Option<&str>,
    ) -> OpenAIResult<ThreadMessageListResponse> {
        let mut url = format!("{}/v1/threads/{thread_id}/messages", self.base_url);
        let mut params = Vec::new();
        if let Some(l) = limit {
            params.push(format!("limit={l}"));
        }
        if let Some(a) = after {
            params.push(format!("after={a}"));
        }
        if !params.is_empty() {
            url.push('?');
            url.push_str(&params.join("&"));
        }
        self.get_v2(&url).await
    }

    // ─────────────────────── Runs ───────────────────────

    /// Create a run on a thread.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, or authentication errors.
    #[instrument(skip(self))]
    pub async fn create_run(
        &self,
        thread_id: &str,
        assistant_id: &str,
        instructions: Option<&str>,
        metadata: Option<serde_json::Value>,
    ) -> OpenAIResult<Run> {
        let url = format!("{}/v1/threads/{thread_id}/runs", self.base_url);
        let mut body = serde_json::json!({
            "assistant_id": assistant_id,
        });
        if let Some(instr) = instructions {
            body["instructions"] = serde_json::Value::String(instr.into());
        }
        if let Some(meta) = metadata {
            body["metadata"] = meta;
        }
        self.post_json(&url, &body).await
    }

    /// Get a run by ID.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, or authentication errors.
    #[instrument(skip(self))]
    pub async fn get_run(&self, thread_id: &str, run_id: &str) -> OpenAIResult<Run> {
        let url = format!("{}/v1/threads/{thread_id}/runs/{run_id}", self.base_url);
        self.get_v2(&url).await
    }

    /// List runs on a thread.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, or authentication errors.
    #[instrument(skip(self))]
    pub async fn list_runs(
        &self,
        thread_id: &str,
        limit: Option<u32>,
        after: Option<&str>,
    ) -> OpenAIResult<RunListResponse> {
        let mut url = format!("{}/v1/threads/{thread_id}/runs", self.base_url);
        let mut params = Vec::new();
        if let Some(l) = limit {
            params.push(format!("limit={l}"));
        }
        if let Some(a) = after {
            params.push(format!("after={a}"));
        }
        if !params.is_empty() {
            url.push('?');
            url.push_str(&params.join("&"));
        }
        self.get_v2(&url).await
    }

    /// Cancel a run.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, or authentication errors.
    #[instrument(skip(self))]
    pub async fn cancel_run(&self, thread_id: &str, run_id: &str) -> OpenAIResult<Run> {
        let url = format!(
            "{}/v1/threads/{thread_id}/runs/{run_id}/cancel",
            self.base_url
        );
        self.post_empty_v2(&url).await
    }

    /// Generic POST with JSON body (for Assistants API v2).
    async fn post_json<T, R>(&self, url: &str, body: &T) -> OpenAIResult<R>
    where
        T: serde::Serialize + Sync,
        R: serde::de::DeserializeOwned + Send,
    {
        let request = self
            .client
            .post(url)
            .header("Content-Type", "application/json")
            .header("OpenAI-Beta", "assistants=v2");
        let request = self.apply_auth(request);

        let response = request.json(body).send().await?;
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.bytes().await?;

        if status.is_success() {
            serde_json::from_slice(&bytes).map_err(OpenAIError::from)
        } else {
            Err(parse_error_response(status, &headers, &bytes))
        }
    }
}

/// Parse OpenAI's Go-style duration strings (e.g. "1s", "6m0s", "1h30m").
fn parse_openai_reset(s: &str) -> Option<u64> {
    let mut total_ms = 0.0;
    let mut current_num = String::new();
    let mut current_unit = String::new();

    for c in s.chars() {
        if c.is_ascii_digit() || c == '.' {
            if !current_unit.is_empty() {
                if let Ok(val) = current_num.parse::<f64>() {
                    match current_unit.as_str() {
                        "h" => total_ms += val * 3_600_000.0,
                        "m" => total_ms += val * 60_000.0,
                        "s" => total_ms += val * 1000.0,
                        "ms" => total_ms += val,
                        _ => {}
                    }
                }
                current_num.clear();
                current_unit.clear();
            }
            current_num.push(c);
        } else if c.is_ascii_alphabetic() {
            current_unit.push(c);
        }
    }

    if !current_num.is_empty() && !current_unit.is_empty() {
        if let Ok(val) = current_num.parse::<f64>() {
            match current_unit.as_str() {
                "h" => total_ms += val * 3_600_000.0,
                "m" => total_ms += val * 60_000.0,
                "s" => total_ms += val * 1000.0,
                "ms" => total_ms += val,
                _ => {}
            }
        }
    }

    if total_ms > 0.0 {
        Some(total_ms as u64)
    } else {
        None
    }
}

/// Parse an error response.
fn parse_error_response(
    status: StatusCode,
    headers: &reqwest::header::HeaderMap,
    bytes: &Bytes,
) -> OpenAIError {
    let mut retry_after_ms = 30_000; // Default 30s
    if let Some(reset) = headers
        .get("x-ratelimit-reset-requests")
        .and_then(|v| v.to_str().ok())
    {
        if let Some(ms) = parse_openai_reset(reset) {
            retry_after_ms = ms.min(MAX_RETRY_AFTER_MS);
        }
    } else if let Some(retry) = headers.get("retry-after").and_then(|v| v.to_str().ok()) {
        if let Ok(secs) = retry.parse::<f64>() {
            if secs.is_finite() && secs.is_sign_positive() {
                let retry_secs = secs.min(MAX_RETRY_AFTER_MS as f64 / 1000.0);
                retry_after_ms = (retry_secs * 1000.0).round() as u64;
            }
        }
    }

    // Try to parse as API error
    if let Ok(api_error) = serde_json::from_slice::<ApiError>(bytes) {
        let details = api_error.error;

        // Check for specific error types
        if status == StatusCode::TOO_MANY_REQUESTS {
            return OpenAIError::RateLimited { retry_after_ms };
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
            message: sanitize_error_message(&details.message),
            status_code: Some(status.as_u16()),
        };
    }

    // Fallback for unparseable errors
    OpenAIError::Api {
        error_type: "unknown".into(),
        message: sanitize_error_message(&String::from_utf8_lossy(bytes)),
        status_code: Some(status.as_u16()),
    }
}

fn sanitize_error_message(message: &str) -> String {
    let collapsed = message.split_whitespace().collect::<Vec<_>>().join(" ");
    let trimmed = collapsed.trim();
    if trimmed.chars().count() <= MAX_ERROR_MESSAGE_CHARS {
        return trimmed.to_string();
    }
    trimmed
        .chars()
        .take(MAX_ERROR_MESSAGE_CHARS)
        .collect::<String>()
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
    use fcp_testkit::{AsyncTestContext, LogCapture};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path},
    };

    #[fcp_async_core::runtime::test]
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

    #[fcp_async_core::runtime::test]
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

    #[fcp_async_core::runtime::test]
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

    #[fcp_async_core::runtime::test]
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

    #[fcp_async_core::runtime::test]
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

    #[fcp_async_core::runtime::test]
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

    #[fcp_async_core::runtime::test]
    async fn test_logs_redact_api_key_and_prompt() {
        let capture = LogCapture::new();
        let _guard = capture.install_json_with_filter("debug");
        let scenario = AsyncTestContext::for_scenario("openai.client.log_redaction");
        tracing::debug!(
            run_id = %scenario.run_id(),
            scenario_id = %scenario.scenario_id(),
            correlation_id = %scenario.correlation_id(),
            "log_capture_ready"
        );

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
            logs.contains(scenario.correlation_id()),
            "scenario correlation id should be present in logs"
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

    #[fcp_async_core::runtime::test]
    async fn test_model_pricing() {
        assert_eq!(Model::Gpt4o.input_price_per_million(), 2.50);
        assert_eq!(Model::Gpt4o.output_price_per_million(), 10.0);
        assert_eq!(Model::Gpt4oMini.input_price_per_million(), 0.15);
        assert_eq!(Model::Gpt4oMini.output_price_per_million(), 0.60);
        assert_eq!(Model::Gpt35Turbo.input_price_per_million(), 0.50);
        assert_eq!(Model::Gpt35Turbo.output_price_per_million(), 1.50);
    }

    #[fcp_async_core::runtime::test]
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
    fn test_parse_error_response_clamps_retry_after_header() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("retry-after", "999999".parse().unwrap());
        let body = Bytes::from_static(
            br#"{"error":{"message":"Rate limit exceeded","type":"rate_limit_error","param":null,"code":null}}"#,
        );

        let err = parse_error_response(StatusCode::TOO_MANY_REQUESTS, &headers, &body);
        match err {
            OpenAIError::RateLimited { retry_after_ms } => {
                assert_eq!(retry_after_ms, MAX_RETRY_AFTER_MS);
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_error_response_truncates_fallback_body() {
        let headers = reqwest::header::HeaderMap::new();
        let raw = format!("{}\n{}", "x".repeat(MAX_ERROR_MESSAGE_CHARS + 50), "tail");
        let err = parse_error_response(StatusCode::BAD_REQUEST, &headers, &Bytes::from(raw));

        match err {
            OpenAIError::Api { message, .. } => {
                assert!(message.len() <= MAX_ERROR_MESSAGE_CHARS);
                assert!(!message.contains('\n'));
            }
            other => panic!("expected Api error, got {other:?}"),
        }
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
