//! HTTP client for Hugging Face Inference and Hub APIs.

use std::time::Duration;

use reqwest::{Client, RequestBuilder};
use tracing::debug;
use url::Url;

use fcp_sdk::migration::{AttemptOutcome, ConnectorRuntime, HttpRetryConfig, RetryLoop};

use crate::error::{HuggingfaceError, HuggingfaceResult};
use crate::types::{
    HfApiError, ModelInfo, ModelListRequest, SummarizationRequest, SummarizationResponse,
    TextGenerationRequest, TextGenerationResponse,
};

/// Default Inference API base URL.
const DEFAULT_INFERENCE_URL: &str = "https://api-inference.huggingface.co";
/// Default Hub API base URL.
const DEFAULT_HUB_URL: &str = "https://huggingface.co/api";

/// Validate a user-supplied model ID to prevent URL path injection.
fn sanitize_model_id(value: &str) -> HuggingfaceResult<&str> {
    if value.trim().is_empty() {
        return Err(HuggingfaceError::InvalidInput(
            "model_id must not be empty".into(),
        ));
    }
    let lower = value.to_ascii_lowercase();
    if value.contains('\\')
        || value.contains("..")
        || lower.contains("%2f")
        || lower.contains("%5c")
    {
        return Err(HuggingfaceError::InvalidInput(
            "model_id contains path traversal characters".into(),
        ));
    }
    // model_id can contain exactly one `/` for org/model format (e.g. "facebook/bart-large-cnn")
    let slash_count = value.chars().filter(|&c| c == '/').count();
    if slash_count > 1 {
        return Err(HuggingfaceError::InvalidInput(
            "model_id may contain at most one `/` (org/model format)".into(),
        ));
    }
    Ok(value)
}

fn normalize_api_base_url(value: &str, field: &str) -> HuggingfaceResult<String> {
    let trimmed = value.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(HuggingfaceError::InvalidInput(format!(
            "{field} must not be empty"
        )));
    }

    let parsed = Url::parse(trimmed).map_err(|e| {
        HuggingfaceError::InvalidInput(format!("{field} must be an absolute URL: {e}"))
    })?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(HuggingfaceError::InvalidInput(format!(
            "{field} must use http or https"
        )));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(HuggingfaceError::InvalidInput(format!(
            "{field} must not contain query or fragment components"
        )));
    }

    Ok(trimmed.to_string())
}

/// Hugging Face API client with retry support.
pub struct HuggingfaceClient {
    client: Client,
    inference_url: String,
    hub_url: String,
    api_token: String,
    retry_config: HttpRetryConfig,
    pub(crate) timeout: Duration,
}

impl std::fmt::Debug for HuggingfaceClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HuggingfaceClient")
            .field("inference_url", &self.inference_url)
            .field("hub_url", &self.hub_url)
            .field(
                "api_token",
                &if self.api_token.is_empty() {
                    "(empty)"
                } else {
                    "[REDACTED]"
                },
            )
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl HuggingfaceClient {
    /// Create a new Hugging Face API client.
    ///
    /// # Errors
    ///
    /// Returns `HuggingfaceError::Http` if the underlying HTTP client cannot be built.
    pub fn new(
        inference_url: Option<&str>,
        hub_url: Option<&str>,
        api_token: &str,
        retry_config: HttpRetryConfig,
        timeout: Duration,
    ) -> HuggingfaceResult<Self> {
        let client = Client::builder()
            .timeout(timeout)
            .build()
            .map_err(HuggingfaceError::Http)?;

        Ok(Self {
            client,
            inference_url: normalize_api_base_url(
                inference_url.unwrap_or(DEFAULT_INFERENCE_URL),
                "inference_url",
            )?,
            hub_url: normalize_api_base_url(hub_url.unwrap_or(DEFAULT_HUB_URL), "hub_url")?,
            api_token: api_token.to_string(),
            retry_config,
            timeout,
        })
    }

    #[must_use]
    pub fn inference_url(&self) -> &str {
        &self.inference_url
    }

    #[must_use]
    pub fn hub_url(&self) -> &str {
        &self.hub_url
    }

    #[must_use]
    pub fn is_secretless(&self) -> bool {
        self.api_token.trim().is_empty()
    }

    // ── Text Generation ──

    /// Run text generation inference on the given model.
    ///
    /// # Errors
    ///
    /// Returns `HuggingfaceError` on HTTP, auth, rate-limit, or parse failures.
    pub async fn text_generation(
        &self,
        runtime: &ConnectorRuntime,
        model_id: &str,
        request: &TextGenerationRequest,
    ) -> HuggingfaceResult<Vec<TextGenerationResponse>> {
        let model_id = sanitize_model_id(model_id)?;
        let url = format!("{}/models/{model_id}", self.inference_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let body = serde_json::to_value(request).map_err(HuggingfaceError::Json)?;

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let body = body.clone();
            let token = self.api_token.clone();
            async move {
                debug!(attempt, model_id, "Text generation request");
                let req = if token.is_empty() {
                    client.post(&url)
                } else {
                    client.post(&url).bearer_auth(&token)
                };
                let req = req.json(&body);
                handle_inference_response::<Vec<TextGenerationResponse>>(req, attempt).await
            }
        })
        .await
    }

    // ── Summarization ──

    /// Run summarization inference on the given model.
    ///
    /// # Errors
    ///
    /// Returns `HuggingfaceError` on HTTP, auth, rate-limit, or parse failures.
    pub async fn summarization(
        &self,
        runtime: &ConnectorRuntime,
        model_id: &str,
        request: &SummarizationRequest,
    ) -> HuggingfaceResult<Vec<SummarizationResponse>> {
        let model_id = sanitize_model_id(model_id)?;
        let url = format!("{}/models/{model_id}", self.inference_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let body = serde_json::to_value(request).map_err(HuggingfaceError::Json)?;

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let body = body.clone();
            let token = self.api_token.clone();
            async move {
                debug!(attempt, model_id, "Summarization request");
                let req = if token.is_empty() {
                    client.post(&url)
                } else {
                    client.post(&url).bearer_auth(&token)
                };
                let req = req.json(&body);
                handle_inference_response::<Vec<SummarizationResponse>>(req, attempt).await
            }
        })
        .await
    }

    // ── Model Info (Hub API) ──

    /// Fetch model metadata from the Hugging Face Hub API.
    ///
    /// # Errors
    ///
    /// Returns `HuggingfaceError` on HTTP, auth, rate-limit, or parse failures.
    pub async fn model_info(
        &self,
        runtime: &ConnectorRuntime,
        model_id: &str,
    ) -> HuggingfaceResult<ModelInfo> {
        let model_id = sanitize_model_id(model_id)?;
        let url = format!("{}/models/{model_id}", self.hub_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let token = self.api_token.clone();
            async move {
                debug!(attempt, model_id, "Model info request");
                let req = if token.is_empty() {
                    client.get(&url)
                } else {
                    client.get(&url).bearer_auth(&token)
                };
                handle_json_response::<ModelInfo>(req, attempt).await
            }
        })
        .await
    }

    /// List Hub models with bounded catalog filters.
    ///
    /// # Errors
    ///
    /// Returns `HuggingfaceError` on invalid query parameters, HTTP, auth, rate-limit,
    /// or parse failures.
    pub async fn list_models(
        &self,
        runtime: &ConnectorRuntime,
        request: &ModelListRequest,
    ) -> HuggingfaceResult<Vec<ModelInfo>> {
        let mut url = Url::parse(&format!("{}/models", self.hub_url)).map_err(|e| {
            HuggingfaceError::InvalidInput(format!("hub_url cannot form models URL: {e}"))
        })?;
        {
            let mut query = url.query_pairs_mut();
            if let Some(search) = request
                .search
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty())
            {
                query.append_pair("search", search);
            }
            if let Some(pipeline_tag) = request
                .pipeline_tag
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty())
            {
                query.append_pair("pipeline_tag", pipeline_tag);
            }
            if let Some(limit) = request.limit {
                query.append_pair("limit", &limit.to_string());
            }
        }

        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let token = self.api_token.clone();
            async move {
                debug!(attempt, "Model catalog list request");
                let req = if token.is_empty() {
                    client.get(url.clone())
                } else {
                    client.get(url.clone()).bearer_auth(&token)
                };
                handle_json_response::<Vec<ModelInfo>>(req, attempt).await
            }
        })
        .await
    }

    // ── Health check ──

    /// Validate the API token via the whoami endpoint.
    ///
    /// # Errors
    ///
    /// Returns `HuggingfaceError` on HTTP, auth, or parse failures.
    pub async fn whoami(&self, runtime: &ConnectorRuntime) -> HuggingfaceResult<serde_json::Value> {
        // Strip trailing /api or /api/ path segment to get the base HuggingFace URL
        // (hub_url is "https://huggingface.co/api" but whoami lives at "https://huggingface.co/whoami-v2")
        let base = self.hub_url.trim_end_matches('/');
        let base = base.strip_suffix("/api").unwrap_or(base);
        let url = format!("{base}/whoami-v2");
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let token = self.api_token.clone();
            async move {
                debug!(attempt, "Whoami health check");
                let req = if token.is_empty() {
                    client.get(&url)
                } else {
                    client.get(&url).bearer_auth(&token)
                };
                handle_json_response::<serde_json::Value>(req, attempt).await
            }
        })
        .await
    }
}

// ── Response handlers ──

/// Extract retry-after duration from response headers, clamped to u64.
fn extract_retry_after_ms(retry_after: Option<Duration>) -> u64 {
    let millis = retry_after.unwrap_or(Duration::from_secs(30)).as_millis();
    u64::try_from(millis).unwrap_or(u64::MAX)
}

/// Handle the Inference API response, which returns JSON directly (no envelope).
/// The HF Inference API returns 503 with `estimated_time` when the model is loading.
async fn handle_inference_response<T: serde::de::DeserializeOwned>(
    req: RequestBuilder,
    attempt: u32,
) -> AttemptOutcome<T, HuggingfaceError> {
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            return AttemptOutcome::Retryable {
                error: HuggingfaceError::Http(e),
                retry_after: None,
            };
        }
    };

    let status = resp.status().as_u16();

    if status == 429 {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .map(Duration::from_secs);
        return AttemptOutcome::Retryable {
            error: HuggingfaceError::RateLimited {
                retry_after_ms: extract_retry_after_ms(retry_after),
            },
            retry_after,
        };
    }

    if status == 401 || status == 403 {
        return AttemptOutcome::Terminal(HuggingfaceError::Unauthorized(format!(
            "Authentication failed (HTTP {status})"
        )));
    }

    if status == 404 {
        return AttemptOutcome::Terminal(HuggingfaceError::NotFound(format!(
            "Model not found (HTTP {status})"
        )));
    }

    // 503 with estimated_time means the model is loading -- retryable
    if status == 503 {
        let text = resp.text().await.unwrap_or_default();
        if let Ok(hf_err) = serde_json::from_str::<HfApiError>(&text) {
            if hf_err.estimated_time.is_some() {
                let wait = hf_err.estimated_time.map_or(Duration::from_secs(10), |t| {
                    Duration::from_secs_f64(t.clamp(1.0, 120.0))
                });
                return AttemptOutcome::Retryable {
                    error: HuggingfaceError::ModelLoading(hf_err.error),
                    retry_after: Some(wait),
                };
            }
        }
        return AttemptOutcome::Retryable {
            error: HuggingfaceError::Api {
                status: 503,
                message: text,
            },
            retry_after: Some(Duration::from_secs(5)),
        };
    }

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        let err = HuggingfaceError::Api {
            status,
            message: text,
        };
        if status >= 500 {
            return AttemptOutcome::Retryable {
                error: err,
                retry_after: None,
            };
        }
        return AttemptOutcome::Terminal(err);
    }

    let text = match resp.text().await {
        Ok(t) => t,
        Err(e) => return AttemptOutcome::Terminal(HuggingfaceError::Http(e)),
    };

    match serde_json::from_str::<T>(&text) {
        Ok(v) => AttemptOutcome::Success(v),
        Err(e) => {
            debug!(attempt, "Failed to parse inference response: {e}");
            AttemptOutcome::Terminal(HuggingfaceError::Json(e))
        }
    }
}

/// Handle a standard JSON response (e.g., Hub API model info).
async fn handle_json_response<T: serde::de::DeserializeOwned>(
    req: RequestBuilder,
    attempt: u32,
) -> AttemptOutcome<T, HuggingfaceError> {
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            return AttemptOutcome::Retryable {
                error: HuggingfaceError::Http(e),
                retry_after: None,
            };
        }
    };

    let status = resp.status().as_u16();

    if status == 429 {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .map(Duration::from_secs);
        return AttemptOutcome::Retryable {
            error: HuggingfaceError::RateLimited {
                retry_after_ms: extract_retry_after_ms(retry_after),
            },
            retry_after,
        };
    }

    if status == 401 || status == 403 {
        return AttemptOutcome::Terminal(HuggingfaceError::Unauthorized(format!(
            "Authentication failed (HTTP {status})"
        )));
    }

    if status == 404 {
        return AttemptOutcome::Terminal(HuggingfaceError::NotFound(format!(
            "Resource not found (HTTP {status})"
        )));
    }

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        let err = HuggingfaceError::Api {
            status,
            message: text,
        };
        if status >= 500 {
            return AttemptOutcome::Retryable {
                error: err,
                retry_after: None,
            };
        }
        return AttemptOutcome::Terminal(err);
    }

    let text = match resp.text().await {
        Ok(t) => t,
        Err(e) => return AttemptOutcome::Terminal(HuggingfaceError::Http(e)),
    };

    match serde_json::from_str::<T>(&text) {
        Ok(v) => AttemptOutcome::Success(v),
        Err(e) => {
            debug!(attempt, "Failed to parse JSON response: {e}");
            AttemptOutcome::Terminal(HuggingfaceError::Json(e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_debug_redacts_token() {
        let client = HuggingfaceClient::new(
            None,
            None,
            "hf_secret_token",
            HttpRetryConfig::default(),
            Duration::from_secs(30),
        )
        .unwrap();

        let debug = format!("{client:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("hf_secret_token"));
    }

    #[test]
    fn secretless_detection() {
        let secretless = HuggingfaceClient::new(
            None,
            None,
            "",
            HttpRetryConfig::default(),
            Duration::from_secs(30),
        )
        .unwrap();
        assert!(secretless.is_secretless());

        let with_token = HuggingfaceClient::new(
            None,
            None,
            "hf_abc",
            HttpRetryConfig::default(),
            Duration::from_secs(30),
        )
        .unwrap();
        assert!(!with_token.is_secretless());
    }

    #[test]
    fn default_urls() {
        let client = HuggingfaceClient::new(
            None,
            None,
            "t",
            HttpRetryConfig::default(),
            Duration::from_secs(30),
        )
        .unwrap();
        assert_eq!(
            client.inference_url(),
            "https://api-inference.huggingface.co"
        );
        assert_eq!(client.hub_url(), "https://huggingface.co/api");
    }

    #[test]
    fn custom_urls_strip_trailing_slash() {
        let client = HuggingfaceClient::new(
            Some("http://localhost:8080/"),
            Some("http://localhost:8081/"),
            "t",
            HttpRetryConfig::default(),
            Duration::from_secs(30),
        )
        .unwrap();
        assert!(!client.inference_url().ends_with('/'));
        assert!(!client.hub_url().ends_with('/'));
    }

    #[test]
    fn custom_urls_reject_query_or_fragment() {
        let err = HuggingfaceClient::new(
            Some("https://example.test/hf?x=bad"),
            None,
            "t",
            HttpRetryConfig::default(),
            Duration::from_secs(30),
        )
        .expect_err("query strings should be rejected");
        assert!(err.to_string().contains("query or fragment"));
    }

    #[test]
    fn sanitize_model_id_rejects_traversal() {
        assert!(sanitize_model_id("../etc/passwd").is_err());
        assert!(sanitize_model_id("foo\\bar").is_err());
        assert!(sanitize_model_id("foo%2fbar").is_err());
        assert!(sanitize_model_id("foo%5Cbar").is_err());
        assert!(sanitize_model_id("").is_err());
        assert!(sanitize_model_id("  ").is_err());
    }

    #[test]
    fn sanitize_model_id_rejects_multiple_slashes() {
        assert!(sanitize_model_id("org/sub/model").is_err());
    }

    #[test]
    fn sanitize_model_id_accepts_valid() {
        assert_eq!(sanitize_model_id("gpt2").unwrap(), "gpt2");
        assert_eq!(
            sanitize_model_id("facebook/bart-large-cnn").unwrap(),
            "facebook/bart-large-cnn"
        );
        assert_eq!(
            sanitize_model_id("mistralai/Mistral-7B-v0.1").unwrap(),
            "mistralai/Mistral-7B-v0.1"
        );
    }

    #[test]
    fn client_uses_configured_timeout() {
        let client = HuggingfaceClient::new(
            None,
            None,
            "t",
            HttpRetryConfig::default(),
            Duration::from_millis(1_234),
        )
        .unwrap();
        assert_eq!(client.timeout, Duration::from_millis(1_234));
    }
}
