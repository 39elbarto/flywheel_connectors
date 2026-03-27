//! Google AI (Gemini) REST API client.
//!
//! API key is appended as a `?key=` query parameter to every request URL.
//! When using credential_id mode, the `X-FCP-Credential-ID` header is sent
//! instead so the egress proxy can inject the actual key.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use fcp_core::CredentialId;
use fcp_sdk::migration::{
    AttemptOutcome, ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig, RetryLoop,
};
use parking_lot::Mutex;
use reqwest::{Client, StatusCode, Url};

use crate::{
    error::{GoogleAiError, GoogleAiResult},
    types::{
        ApiErrorResponse, BatchEmbedContentsResponse, CancelTuningOperationRequest,
        CountTokensResponse, CreateTunedModelRequest, EmbedContentResponse,
        GenerateContentResponse, GetTunedModelRequest, GetTuningOperationRequest,
        ListModelsResponse, ListTunedModelsRequest, ListTunedModelsResponse, ModelInfo, TunedModel,
        TuningOperation, UsageCounters, UsageMetadata,
    },
};

/// Default API base URL.
pub const DEFAULT_BASE_URL: &str = "https://generativelanguage.googleapis.com/v1beta";

/// Authentication mode for the Google AI API.
#[derive(Clone)]
pub enum GoogleAiAuth {
    /// Direct API key (appended as `?key=`).
    ApiKey(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl GoogleAiAuth {
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

impl fmt::Debug for GoogleAiAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApiKey(_) => f.debug_tuple("ApiKey").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// Google AI REST API client.
pub struct GoogleAiClient {
    http: Client,
    base_url: String,
    auth: GoogleAiAuth,
    max_retries: u32,
    usage: Arc<Mutex<UsageCounters>>,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl GoogleAiClient {
    /// Create a new Google AI client with an API key (legacy convenience).
    pub fn new(api_key: &str) -> GoogleAiResult<Self> {
        Self::new_with_auth(GoogleAiAuth::ApiKey(api_key.to_string()))
    }

    /// Create a new Google AI client with a specific auth mode.
    pub fn new_with_auth(auth: GoogleAiAuth) -> GoogleAiResult<Self> {
        let http = Client::builder()
            .user_agent("fcp-google-ai/0.1.0")
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(GoogleAiError::Http)?;

        Ok(Self {
            http,
            base_url: DEFAULT_BASE_URL.to_string(),
            auth,
            max_retries: 2,
            usage: Arc::new(Mutex::new(UsageCounters::default())),
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(30)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 2,
                ..HttpRetryConfig::default()
            },
        })
    }

    /// Set a custom base URL (for testing).
    #[must_use]
    pub fn with_base_url(mut self, url: &str) -> Self {
        self.base_url = url.to_string();
        self
    }

    /// Set the maximum number of retries.
    #[must_use]
    pub fn with_retry_config(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self.retry_config = HttpRetryConfig {
            max_retries,
            ..self.retry_config
        };
        self
    }

    /// Build a URL, appending the API key as a query parameter when in direct mode.
    fn url(&self, path: &str) -> String {
        self.url_with_query(path, &[])
    }

    /// Build a URL with additional query pairs.
    fn url_with_query(&self, path: &str, query: &[(&str, String)]) -> String {
        let raw = format!(
            "{}/{}",
            self.base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        );
        if let Ok(mut url) = Url::parse(&raw) {
            {
                let mut pairs = url.query_pairs_mut();
                if let GoogleAiAuth::ApiKey(key) = &self.auth {
                    pairs.append_pair("key", key);
                }
                for (name, value) in query {
                    pairs.append_pair(name, value);
                }
            }
            url.to_string()
        } else {
            let mut url = raw;
            if let GoogleAiAuth::ApiKey(key) = &self.auth {
                url = append_query_param(url, "key", key);
            }
            for (name, value) in query {
                url = append_query_param(url, name, value);
            }
            url
        }
    }

    /// Record token usage from a response.
    fn record_usage(&self, meta: Option<&UsageMetadata>) {
        if let Some(m) = meta {
            let mut u = self.usage.lock();
            u.input_tokens += m.prompt_token_count;
            u.output_tokens += m.candidates_token_count;
        }
    }

    /// Record a request (success or error).
    fn record_request(&self, success: bool) {
        let mut u = self.usage.lock();
        u.requests_total += 1;
        if !success {
            u.requests_error += 1;
        }
    }

    /// Get a snapshot of the current usage counters.
    #[must_use]
    pub fn get_usage(&self) -> UsageCounters {
        self.usage.lock().clone()
    }

    /// Trigger graceful shutdown of request contexts.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    // ── Generate Content ──────────────────────────────────────────

    /// Generate content (non-streaming).
    pub async fn generate_content(
        &self,
        model: &str,
        body: &serde_json::Value,
    ) -> GoogleAiResult<GenerateContentResponse> {
        let resource = normalize_generation_resource(model);
        let url = self.url(&format!("{resource}:generateContent"));
        let data = self.post_json(&url, body).await;
        self.record_request(data.is_ok());
        let data = data?;
        let resp: GenerateContentResponse = serde_json::from_value(data)?;
        self.record_usage(resp.usage_metadata.as_ref());
        Ok(resp)
    }

    /// Generate content with streaming (returns raw JSON chunks).
    pub async fn generate_content_stream(
        &self,
        model: &str,
        body: &serde_json::Value,
    ) -> GoogleAiResult<Vec<GenerateContentResponse>> {
        let resource = normalize_generation_resource(model);
        let url = self.url(&format!("{resource}:streamGenerateContent"));
        // The streaming endpoint returns an array of response chunks when
        // called without SSE (alt=sse). We parse the entire response as JSON array.
        let data = self.post_json(&url, body).await;
        self.record_request(data.is_ok());
        let data = data?;

        // The response could be an array of chunks or a single object
        let chunks: Vec<GenerateContentResponse> = if data.is_array() {
            serde_json::from_value(data)?
        } else {
            let single: GenerateContentResponse = serde_json::from_value(data)?;
            vec![single]
        };

        // Accumulate usage from all chunks
        for chunk in &chunks {
            self.record_usage(chunk.usage_metadata.as_ref());
        }

        Ok(chunks)
    }

    // ── Embeddings ────────────────────────────────────────────────

    /// Embed content.
    pub async fn embed_content(
        &self,
        model: &str,
        body: &serde_json::Value,
    ) -> GoogleAiResult<EmbedContentResponse> {
        let url = self.url(&format!("models/{model}:embedContent"));
        let data = self.post_json(&url, body).await;
        self.record_request(data.is_ok());
        let data = data?;
        Ok(serde_json::from_value(data)?)
    }

    /// Batch embed contents.
    pub async fn batch_embed_contents(
        &self,
        model: &str,
        body: &serde_json::Value,
    ) -> GoogleAiResult<BatchEmbedContentsResponse> {
        let url = self.url(&format!("models/{model}:batchEmbedContents"));
        let data = self.post_json(&url, body).await;
        self.record_request(data.is_ok());
        let data = data?;
        Ok(serde_json::from_value(data)?)
    }

    // ── Token Counting ────────────────────────────────────────────

    /// Count tokens.
    pub async fn count_tokens(
        &self,
        model: &str,
        body: &serde_json::Value,
    ) -> GoogleAiResult<CountTokensResponse> {
        let resource = normalize_generation_resource(model);
        let url = self.url(&format!("{resource}:countTokens"));
        let data = self.post_json(&url, body).await;
        self.record_request(data.is_ok());
        let data = data?;
        Ok(serde_json::from_value(data)?)
    }

    // ── Models ────────────────────────────────────────────────────

    /// List available models.
    pub async fn list_models(
        &self,
        page_size: Option<u32>,
        page_token: Option<&str>,
    ) -> GoogleAiResult<ListModelsResponse> {
        let mut query = Vec::new();
        if let Some(ps) = page_size {
            query.push(("pageSize", ps.to_string()));
        }
        if let Some(pt) = page_token {
            query.push(("pageToken", pt.to_string()));
        }
        let url = self.url_with_query("models", &query);
        let data = self.get(&url).await;
        self.record_request(data.is_ok());
        let data = data?;
        Ok(serde_json::from_value(data)?)
    }

    /// Get a specific model.
    pub async fn get_model(&self, model: &str) -> GoogleAiResult<ModelInfo> {
        let url = self.url(&normalize_model_resource(model));
        let data = self.get(&url).await;
        self.record_request(data.is_ok());
        let data = data?;
        Ok(serde_json::from_value(data)?)
    }

    /// Create a new tuned model training job.
    pub async fn create_tuned_model(
        &self,
        request: &CreateTunedModelRequest,
    ) -> GoogleAiResult<TuningOperation> {
        let query = request
            .tuned_model_id
            .as_ref()
            .map(|id| vec![("tunedModelId", id.clone())])
            .unwrap_or_default();
        let url = self.url_with_query("tunedModels", &query);
        let mut body = serde_json::to_value(request)?;
        if let Some(map) = body.as_object_mut() {
            map.remove("tunedModelId");
        }
        let data = self.post_json(&url, &body).await;
        self.record_request(data.is_ok());
        let data = data?;
        Ok(serde_json::from_value(data)?)
    }

    /// List tuned models.
    pub async fn list_tuned_models(
        &self,
        request: &ListTunedModelsRequest,
    ) -> GoogleAiResult<ListTunedModelsResponse> {
        let mut query = Vec::new();
        if let Some(page_size) = request.page_size {
            query.push(("pageSize", page_size.to_string()));
        }
        if let Some(page_token) = &request.page_token {
            query.push(("pageToken", page_token.clone()));
        }
        let url = self.url_with_query("tunedModels", &query);
        let data = self.get(&url).await;
        self.record_request(data.is_ok());
        let data = data?;
        Ok(serde_json::from_value(data)?)
    }

    /// Fetch one tuned model.
    pub async fn get_tuned_model(
        &self,
        request: &GetTunedModelRequest,
    ) -> GoogleAiResult<TunedModel> {
        let resource = normalize_tuned_model_resource(&request.tuned_model);
        let url = self.url(&resource);
        let data = self.get(&url).await;
        self.record_request(data.is_ok());
        let data = data?;
        Ok(serde_json::from_value(data)?)
    }

    /// Fetch the status of a long-running tuning operation.
    pub async fn get_tuning_operation(
        &self,
        request: &GetTuningOperationRequest,
    ) -> GoogleAiResult<TuningOperation> {
        let resource = normalize_tuning_operation_resource(&request.operation);
        let url = self.url(&resource);
        let data = self.get(&url).await;
        self.record_request(data.is_ok());
        let data = data?;
        Ok(serde_json::from_value(data)?)
    }

    /// Cancel a long-running tuning operation.
    pub async fn cancel_tuning_operation(
        &self,
        request: &CancelTuningOperationRequest,
    ) -> GoogleAiResult<()> {
        let resource = normalize_tuning_operation_resource(&request.operation);
        let url = self.url(&format!("{resource}:cancel"));
        let data = self.post_json(&url, &serde_json::json!({})).await;
        self.record_request(data.is_ok());
        data?;
        Ok(())
    }

    /// Perform a safe, read-only health check by listing models.
    ///
    /// Validates that the API key is valid and the API is reachable
    /// without incurring cost or side effects.
    pub async fn health_check(&self) -> GoogleAiResult<()> {
        let _models = self.list_models(Some(1), None).await?;
        Ok(())
    }

    // ── HTTP helpers ──────────────────────────────────────────────

    async fn get(&self, url: &str) -> GoogleAiResult<serde_json::Value> {
        self.execute(|| {
            let req = self.http.get(url);
            self.apply_auth(req)
        })
        .await
    }

    async fn post_json(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> GoogleAiResult<serde_json::Value> {
        self.execute(|| {
            let req = self.http.post(url).json(body);
            self.apply_auth(req)
        })
        .await
    }

    /// Apply auth headers for credential_id mode.
    fn apply_auth(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            GoogleAiAuth::ApiKey(_) => request, // key is in the URL query param
            GoogleAiAuth::CredentialId(cred_id) => {
                request.header("X-FCP-Credential-ID", cred_id.to_string())
            }
        }
    }

    async fn execute(
        &self,
        build_request: impl Fn() -> reqwest::RequestBuilder,
    ) -> GoogleAiResult<serde_json::Value> {
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |_attempt| {
            let req = build_request();
            async move {
                match req.send().await {
                    Ok(response) => {
                        let status = response.status();

                        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                            let body = response.text().await.unwrap_or_default();
                            return AttemptOutcome::Terminal(GoogleAiError::Api {
                                message: format!("Authentication failed: {body}"),
                                status_code: Some(status.as_u16()),
                                error_type: Some("AUTH_ERROR".into()),
                            });
                        }

                        if status == StatusCode::NOT_FOUND {
                            let body = response.text().await.unwrap_or_default();
                            return AttemptOutcome::Terminal(GoogleAiError::Api {
                                message: format!("Not found: {body}"),
                                status_code: Some(404),
                                error_type: Some("NOT_FOUND".into()),
                            });
                        }

                        if status == StatusCode::TOO_MANY_REQUESTS {
                            let retry_after = response
                                .headers()
                                .get("retry-after")
                                .and_then(|v| v.to_str().ok())
                                .and_then(|v| v.parse::<u64>().ok())
                                .map_or(60_000, |s| s * 1000);

                            let err = GoogleAiError::RateLimit {
                                retry_after_ms: retry_after,
                            };
                            return AttemptOutcome::Retryable {
                                retry_after: err.retry_after(),
                                error: err,
                            };
                        }

                        if status.is_server_error() {
                            let body = response.text().await.unwrap_or_default();
                            let err = GoogleAiError::Api {
                                message: format!("Server error {status}: {body}"),
                                status_code: Some(status.as_u16()),
                                error_type: None,
                            };
                            return AttemptOutcome::Retryable {
                                retry_after: None,
                                error: err,
                            };
                        }

                        if !status.is_success() {
                            let body = response.text().await.unwrap_or_default();
                            let api_err: Option<ApiErrorResponse> =
                                serde_json::from_str(&body).ok();
                            let (message, error_type) = api_err
                                .as_ref()
                                .and_then(|e| e.error.as_ref())
                                .map(|d| {
                                    (
                                        d.message.clone().unwrap_or(format!("HTTP {status}")),
                                        d.status.clone(),
                                    )
                                })
                                .unwrap_or((format!("HTTP {status}: {body}"), None));
                            return AttemptOutcome::Terminal(GoogleAiError::Api {
                                message,
                                status_code: Some(status.as_u16()),
                                error_type,
                            });
                        }

                        match response.text().await {
                            Ok(body) => match serde_json::from_str(&body) {
                                Ok(data) => AttemptOutcome::Success(data),
                                Err(e) => AttemptOutcome::Terminal(GoogleAiError::Serialization(e)),
                            },
                            Err(e) => AttemptOutcome::Terminal(GoogleAiError::Http(e)),
                        }
                    }
                    Err(e) => {
                        let err = GoogleAiError::Http(e);
                        if err.is_retryable() {
                            AttemptOutcome::Retryable {
                                retry_after: None,
                                error: err,
                            }
                        } else {
                            AttemptOutcome::Terminal(err)
                        }
                    }
                }
            }
        })
        .await
    }
}

fn append_query_param(mut url: String, name: &str, value: &str) -> String {
    let separator = if url.contains('?') { '&' } else { '?' };
    url.push(separator);
    url.push_str(name);
    url.push('=');
    url.push_str(value);
    url
}

fn normalize_generation_resource(model: &str) -> String {
    let trimmed = model.trim().trim_start_matches('/');
    if trimmed.starts_with("models/") || trimmed.starts_with("tunedModels/") {
        trimmed.to_string()
    } else {
        format!("models/{trimmed}")
    }
}

fn normalize_model_resource(model: &str) -> String {
    let trimmed = model.trim().trim_start_matches('/');
    if trimmed.starts_with("models/") {
        trimmed.to_string()
    } else {
        format!("models/{trimmed}")
    }
}

fn normalize_tuned_model_resource(name: &str) -> String {
    let trimmed = name.trim().trim_start_matches('/');
    if trimmed.starts_with("tunedModels/") {
        trimmed.to_string()
    } else {
        format!("tunedModels/{trimmed}")
    }
}

fn normalize_tuning_operation_resource(name: &str) -> String {
    name.trim().trim_start_matches('/').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path, query_param},
    };

    #[fcp_async_core::runtime::test]
    async fn test_generate_content() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1beta/models/gemini-2.0-flash:generateContent"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "candidates": [{
                    "content": {
                        "parts": [{"text": "Hello! How can I help?"}],
                        "role": "model"
                    },
                    "finishReason": "STOP",
                    "index": 0
                }],
                "usageMetadata": {
                    "promptTokenCount": 5,
                    "candidatesTokenCount": 10,
                    "totalTokenCount": 15
                }
            })))
            .mount(&mock_server)
            .await;

        let client = GoogleAiClient::new("test-key")
            .unwrap()
            .with_base_url(&format!("{}/v1beta", mock_server.uri()));

        let body = serde_json::json!({
            "contents": [{"role": "user", "parts": [{"text": "Hello"}]}]
        });
        let resp = client
            .generate_content("gemini-2.0-flash", &body)
            .await
            .unwrap();
        assert_eq!(resp.candidates.len(), 1);
        assert_eq!(resp.usage_metadata.as_ref().unwrap().prompt_token_count, 5);

        let usage = client.get_usage();
        assert_eq!(usage.input_tokens, 5);
        assert_eq!(usage.output_tokens, 10);
        assert_eq!(usage.requests_total, 1);
        assert_eq!(usage.requests_error, 0);
    }

    #[fcp_async_core::runtime::test]
    async fn test_embed_content() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1beta/models/text-embedding-004:embedContent"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "embedding": {
                    "values": [0.1, 0.2, 0.3, 0.4]
                }
            })))
            .mount(&mock_server)
            .await;

        let client = GoogleAiClient::new("test-key")
            .unwrap()
            .with_base_url(&format!("{}/v1beta", mock_server.uri()));

        let body = serde_json::json!({
            "content": {"parts": [{"text": "test text"}]}
        });
        let resp = client
            .embed_content("text-embedding-004", &body)
            .await
            .unwrap();
        assert_eq!(resp.embedding.values.len(), 4);
    }

    #[fcp_async_core::runtime::test]
    async fn test_count_tokens() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1beta/models/gemini-2.0-flash:countTokens"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "totalTokens": 42
            })))
            .mount(&mock_server)
            .await;

        let client = GoogleAiClient::new("test-key")
            .unwrap()
            .with_base_url(&format!("{}/v1beta", mock_server.uri()));

        let body = serde_json::json!({
            "contents": [{"role": "user", "parts": [{"text": "Hello world"}]}]
        });
        let resp = client
            .count_tokens("gemini-2.0-flash", &body)
            .await
            .unwrap();
        assert_eq!(resp.total_tokens, 42);
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_models() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1beta/models"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "models": [
                    {
                        "name": "models/gemini-2.0-flash",
                        "displayName": "Gemini 2.0 Flash",
                        "supportedGenerationMethods": ["generateContent", "countTokens"],
                        "inputTokenLimit": 1048576,
                        "outputTokenLimit": 8192
                    },
                    {
                        "name": "models/text-embedding-004",
                        "displayName": "Text Embedding 004",
                        "supportedGenerationMethods": ["embedContent"],
                        "inputTokenLimit": 2048,
                        "outputTokenLimit": 768
                    }
                ]
            })))
            .mount(&mock_server)
            .await;

        let client = GoogleAiClient::new("test-key")
            .unwrap()
            .with_base_url(&format!("{}/v1beta", mock_server.uri()));

        let resp = client.list_models(None, None).await.unwrap();
        assert_eq!(resp.models.len(), 2);
        assert_eq!(resp.models[0].name, "models/gemini-2.0-flash");
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_models_credential_id_uses_proper_query_separator() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1beta/models"))
            .and(query_param("pageSize", "5"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "models": []
            })))
            .mount(&mock_server)
            .await;

        let client = GoogleAiClient::new_with_auth(GoogleAiAuth::CredentialId(CredentialId::new()))
            .unwrap()
            .with_base_url(&format!("{}/v1beta", mock_server.uri()));

        let resp = client.list_models(Some(5), None).await.unwrap();
        assert!(resp.models.is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_model() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1beta/models/gemini-2.0-flash"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "models/gemini-2.0-flash",
                "displayName": "Gemini 2.0 Flash",
                "supportedGenerationMethods": ["generateContent", "countTokens"],
                "inputTokenLimit": 1048576,
                "outputTokenLimit": 8192
            })))
            .mount(&mock_server)
            .await;

        let client = GoogleAiClient::new("test-key")
            .unwrap()
            .with_base_url(&format!("{}/v1beta", mock_server.uri()));

        let model = client.get_model("gemini-2.0-flash").await.unwrap();
        assert_eq!(model.name, "models/gemini-2.0-flash");
        assert_eq!(model.input_token_limit, Some(1_048_576));
    }

    #[fcp_async_core::runtime::test]
    async fn test_generate_content_supports_tuned_model_resources() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1beta/tunedModels/support-bot:generateContent"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "candidates": [{
                    "content": {"parts": [{"text": "hello"}], "role": "model"}
                }]
            })))
            .mount(&mock_server)
            .await;

        let client = GoogleAiClient::new("test-key")
            .unwrap()
            .with_base_url(&format!("{}/v1beta", mock_server.uri()));

        let body = serde_json::json!({
            "contents": [{"role": "user", "parts": [{"text": "hi"}]}]
        });
        let response = client
            .generate_content("tunedModels/support-bot", &body)
            .await
            .unwrap();
        assert_eq!(response.candidates.len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn test_create_tuned_model() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1beta/tunedModels"))
            .and(query_param("tunedModelId", "support-bot"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "tunedModels/support-bot/operations/op-123",
                "done": false,
                "metadata": {
                    "state": "PENDING"
                }
            })))
            .mount(&mock_server)
            .await;

        let client = GoogleAiClient::new("test-key")
            .unwrap()
            .with_base_url(&format!("{}/v1beta", mock_server.uri()));

        let request = CreateTunedModelRequest {
            tuned_model_id: Some("support-bot".into()),
            display_name: Some("Support Bot".into()),
            description: None,
            source_model: "models/gemini-1.5-flash-001".into(),
            tuning_task: crate::types::TuningTaskConfig {
                training_data: crate::types::TuningDataset {
                    examples: vec![crate::types::TuningExample {
                        text_input: "refund request".into(),
                        output: "billing".into(),
                    }],
                },
                hyperparameters: None,
            },
        };

        let operation = client.create_tuned_model(&request).await.unwrap();
        assert_eq!(operation.name, "tunedModels/support-bot/operations/op-123");
        assert!(!operation.done);
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_tuned_models() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1beta/tunedModels"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "tunedModels": [
                    {
                        "name": "tunedModels/support-bot",
                        "displayName": "Support Bot",
                        "state": "ACTIVE"
                    }
                ]
            })))
            .mount(&mock_server)
            .await;

        let client = GoogleAiClient::new("test-key")
            .unwrap()
            .with_base_url(&format!("{}/v1beta", mock_server.uri()));

        let response = client
            .list_tuned_models(&ListTunedModelsRequest::default())
            .await
            .unwrap();
        assert_eq!(response.tuned_models.len(), 1);
        assert_eq!(response.tuned_models[0].name, "tunedModels/support-bot");
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_tuning_operation() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1beta/tunedModels/support-bot/operations/op-123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "tunedModels/support-bot/operations/op-123",
                "done": true,
                "response": {
                    "name": "tunedModels/support-bot"
                }
            })))
            .mount(&mock_server)
            .await;

        let client = GoogleAiClient::new("test-key")
            .unwrap()
            .with_base_url(&format!("{}/v1beta", mock_server.uri()));

        let response = client
            .get_tuning_operation(&GetTuningOperationRequest {
                operation: "tunedModels/support-bot/operations/op-123".into(),
            })
            .await
            .unwrap();
        assert!(response.done);
        assert_eq!(
            response.response.unwrap()["name"],
            "tunedModels/support-bot"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_cancel_tuning_operation() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path(
                "/v1beta/tunedModels/support-bot/operations/op-123:cancel",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&mock_server)
            .await;

        let client = GoogleAiClient::new("test-key")
            .unwrap()
            .with_base_url(&format!("{}/v1beta", mock_server.uri()));

        client
            .cancel_tuning_operation(&CancelTuningOperationRequest {
                operation: "tunedModels/support-bot/operations/op-123".into(),
            })
            .await
            .unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn test_batch_embed_contents() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1beta/models/text-embedding-004:batchEmbedContents"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "embeddings": [
                    {"values": [0.1, 0.2]},
                    {"values": [0.3, 0.4]}
                ]
            })))
            .mount(&mock_server)
            .await;

        let client = GoogleAiClient::new("test-key")
            .unwrap()
            .with_base_url(&format!("{}/v1beta", mock_server.uri()));

        let body = serde_json::json!({
            "requests": [
                {"content": {"parts": [{"text": "doc 1"}]}},
                {"content": {"parts": [{"text": "doc 2"}]}}
            ]
        });
        let resp = client
            .batch_embed_contents("text-embedding-004", &body)
            .await
            .unwrap();
        assert_eq!(resp.embeddings.len(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn test_rate_limited() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1beta/models"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&mock_server)
            .await;

        let client = GoogleAiClient::new("test-key")
            .unwrap()
            .with_base_url(&format!("{}/v1beta", mock_server.uri()))
            .with_retry_config(0);

        let result = client.list_models(None, None).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GoogleAiError::RateLimit { .. }
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_unauthorized() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1beta/models"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&mock_server)
            .await;

        let client = GoogleAiClient::new("bad-key")
            .unwrap()
            .with_base_url(&format!("{}/v1beta", mock_server.uri()))
            .with_retry_config(0);

        let result = client.list_models(None, None).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            GoogleAiError::Api { status_code, .. } => assert_eq!(status_code, Some(401)),
            e => panic!("Expected Api error with 401, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_usage_tracking() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1beta/models/gemini-2.0-flash:generateContent"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "candidates": [{
                    "content": {"parts": [{"text": "response"}], "role": "model"},
                    "finishReason": "STOP"
                }],
                "usageMetadata": {
                    "promptTokenCount": 10,
                    "candidatesTokenCount": 20,
                    "totalTokenCount": 30
                }
            })))
            .mount(&mock_server)
            .await;

        let client = GoogleAiClient::new("test-key")
            .unwrap()
            .with_base_url(&format!("{}/v1beta", mock_server.uri()));

        // Two requests
        let body = serde_json::json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}]});
        client
            .generate_content("gemini-2.0-flash", &body)
            .await
            .unwrap();
        client
            .generate_content("gemini-2.0-flash", &body)
            .await
            .unwrap();

        let usage = client.get_usage();
        assert_eq!(usage.input_tokens, 20);
        assert_eq!(usage.output_tokens, 40);
        assert_eq!(usage.requests_total, 2);
        assert_eq!(usage.requests_error, 0);
    }

    #[test]
    fn test_error_is_retryable() {
        let err = GoogleAiError::RateLimit {
            retry_after_ms: 1000,
        };
        assert!(err.is_retryable());

        let err = GoogleAiError::InvalidConfig("bad config".into());
        assert!(!err.is_retryable());

        let err = GoogleAiError::Api {
            message: "Server error".into(),
            status_code: Some(500),
            error_type: None,
        };
        assert!(err.is_retryable());

        let err = GoogleAiError::Api {
            message: "Bad request".into(),
            status_code: Some(400),
            error_type: None,
        };
        assert!(!err.is_retryable());
    }

    // ── Additional sync client tests ──────────────────────────────

    #[test]
    fn default_base_url_value() {
        assert_eq!(
            DEFAULT_BASE_URL,
            "https://generativelanguage.googleapis.com/v1beta"
        );
    }

    #[test]
    fn default_base_url_starts_with_https() {
        assert!(DEFAULT_BASE_URL.starts_with("https://"));
    }

    #[test]
    fn auth_debug_redacts_api_key() {
        let auth = GoogleAiAuth::ApiKey("AIzaSyB-secret-key".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("AIzaSyB-secret-key"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_credential_id_debug() {
        let id = CredentialId::new();
        let auth = GoogleAiAuth::CredentialId(id);
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn auth_redacted_label_api_key() {
        let auth = GoogleAiAuth::ApiKey("test".into());
        assert_eq!(auth.redacted_label(), "api_key:redacted");
    }

    #[test]
    fn auth_redacted_label_credential_id() {
        let auth = GoogleAiAuth::CredentialId(CredentialId::new());
        assert!(auth.redacted_label().starts_with("credential_id:"));
    }

    #[test]
    fn auth_is_secretless_api_key() {
        let auth = GoogleAiAuth::ApiKey("k".into());
        assert!(!auth.is_secretless());
    }

    #[test]
    fn auth_is_secretless_credential() {
        let auth = GoogleAiAuth::CredentialId(CredentialId::new());
        assert!(auth.is_secretless());
    }

    #[test]
    fn auth_clone_api_key() {
        let auth = GoogleAiAuth::ApiKey("key".into());
        let cloned = auth.clone();
        assert_eq!(cloned.redacted_label(), auth.redacted_label());
    }

    #[test]
    fn client_new_creates_with_default_base_url() {
        let client = GoogleAiClient::new("test-key").unwrap();
        let usage = client.get_usage();
        assert_eq!(usage.requests_total, 0);
        assert_eq!(usage.requests_error, 0);
        assert_eq!(usage.input_tokens, 0);
        assert_eq!(usage.output_tokens, 0);
    }
}
