//! Google AI (Gemini) REST API client.
//!
//! API key is appended as a `?key=` query parameter to every request URL.

use std::sync::Arc;

use parking_lot::Mutex;
use reqwest::{Client, StatusCode};
use tracing::{debug, warn};

use crate::{
    error::{GoogleAiError, GoogleAiResult},
    types::{
        ApiErrorResponse, BatchEmbedContentsResponse, CountTokensResponse,
        EmbedContentResponse, GenerateContentResponse, ListModelsResponse, ModelInfo,
        UsageCounters, UsageMetadata,
    },
};

const DEFAULT_BASE_URL: &str = "https://generativelanguage.googleapis.com/v1beta";

/// Google AI REST API client.
pub struct GoogleAiClient {
    http: Client,
    base_url: String,
    api_key: String,
    max_retries: u32,
    usage: Arc<Mutex<UsageCounters>>,
}

impl GoogleAiClient {
    /// Create a new Google AI client with an API key.
    pub fn new(api_key: &str) -> GoogleAiResult<Self> {
        let http = Client::builder()
            .user_agent("fcp-google-ai/0.1.0")
            .build()
            .map_err(GoogleAiError::Http)?;

        Ok(Self {
            http,
            base_url: DEFAULT_BASE_URL.to_string(),
            api_key: api_key.to_string(),
            max_retries: 2,
            usage: Arc::new(Mutex::new(UsageCounters::default())),
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
        self
    }

    /// Build a URL with the API key query parameter.
    fn url(&self, path: &str) -> String {
        format!("{}/{path}?key={}", self.base_url, self.api_key)
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

    // ── Generate Content ──────────────────────────────────────────

    /// Generate content (non-streaming).
    pub async fn generate_content(
        &self,
        model: &str,
        body: &serde_json::Value,
    ) -> GoogleAiResult<GenerateContentResponse> {
        let url = self.url(&format!("models/{model}:generateContent"));
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
        let url = self.url(&format!("models/{model}:streamGenerateContent"));
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
        let url = self.url(&format!("models/{model}:countTokens"));
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
        let mut url = self.url("models");
        if let Some(ps) = page_size {
            url = format!("{url}&pageSize={ps}");
        }
        if let Some(pt) = page_token {
            url = format!("{url}&pageToken={pt}");
        }
        let data = self.get(&url).await;
        self.record_request(data.is_ok());
        let data = data?;
        Ok(serde_json::from_value(data)?)
    }

    /// Get a specific model.
    pub async fn get_model(&self, model: &str) -> GoogleAiResult<ModelInfo> {
        let url = self.url(&format!("models/{model}"));
        let data = self.get(&url).await;
        self.record_request(data.is_ok());
        let data = data?;
        Ok(serde_json::from_value(data)?)
    }

    // ── HTTP helpers ──────────────────────────────────────────────

    async fn get(&self, url: &str) -> GoogleAiResult<serde_json::Value> {
        self.execute(|| self.http.get(url)).await
    }

    async fn post_json(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> GoogleAiResult<serde_json::Value> {
        self.execute(|| self.http.post(url).json(body)).await
    }

    async fn execute(
        &self,
        build_request: impl Fn() -> reqwest::RequestBuilder,
    ) -> GoogleAiResult<serde_json::Value> {
        let mut last_err = None;

        for attempt in 0..=self.max_retries {
            if attempt > 0 {
                let delay = std::time::Duration::from_millis(500 * u64::from(attempt));
                debug!(attempt, delay_ms = delay.as_millis(), "retrying request");
                fcp_async_core::time::sleep(delay).await;
            }

            let result = build_request().send().await;

            match result {
                Ok(response) => {
                    let status = response.status();

                    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                        let body = response.text().await.unwrap_or_default();
                        return Err(GoogleAiError::Api {
                            message: format!("Authentication failed: {body}"),
                            status_code: Some(status.as_u16()),
                            error_type: Some("AUTH_ERROR".into()),
                        });
                    }

                    if status == StatusCode::NOT_FOUND {
                        let body = response.text().await.unwrap_or_default();
                        return Err(GoogleAiError::Api {
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
                        if attempt < self.max_retries {
                            warn!(attempt, "rate limited, will retry");
                            last_err = Some(err);
                            continue;
                        }
                        return Err(err);
                    }

                    if status.is_server_error() {
                        let body = response.text().await.unwrap_or_default();
                        let err = GoogleAiError::Api {
                            message: format!("Server error {status}: {body}"),
                            status_code: Some(status.as_u16()),
                            error_type: None,
                        };
                        if attempt < self.max_retries {
                            warn!(attempt, status = %status, "server error, will retry");
                            last_err = Some(err);
                            continue;
                        }
                        return Err(err);
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
                        return Err(GoogleAiError::Api {
                            message,
                            status_code: Some(status.as_u16()),
                            error_type,
                        });
                    }

                    let body = response.text().await.map_err(GoogleAiError::Http)?;
                    let data: serde_json::Value = serde_json::from_str(&body)?;
                    return Ok(data);
                }
                Err(e) => {
                    if attempt < self.max_retries {
                        warn!(attempt, error = %e, "request failed, will retry");
                        last_err = Some(GoogleAiError::Http(e));
                        continue;
                    }
                    return Err(GoogleAiError::Http(e));
                }
            }
        }

        Err(last_err.unwrap_or(GoogleAiError::Api {
            message: "Max retries exceeded".into(),
            status_code: None,
            error_type: None,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
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
        let resp = client.generate_content("gemini-2.0-flash", &body).await.unwrap();
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
        let resp = client.embed_content("text-embedding-004", &body).await.unwrap();
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
        let resp = client.count_tokens("gemini-2.0-flash", &body).await.unwrap();
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
        let resp = client.batch_embed_contents("text-embedding-004", &body).await.unwrap();
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
        assert!(matches!(result.unwrap_err(), GoogleAiError::RateLimit { .. }));
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
        client.generate_content("gemini-2.0-flash", &body).await.unwrap();
        client.generate_content("gemini-2.0-flash", &body).await.unwrap();

        let usage = client.get_usage();
        assert_eq!(usage.input_tokens, 20);
        assert_eq!(usage.output_tokens, 40);
        assert_eq!(usage.requests_total, 2);
        assert_eq!(usage.requests_error, 0);
    }

    #[test]
    fn test_error_is_retryable() {
        let err = GoogleAiError::RateLimit { retry_after_ms: 1000 };
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
}
