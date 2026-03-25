use std::time::Duration;

use reqwest::{Client, RequestBuilder};
use tracing::debug;

use fcp_sdk::migration::{AttemptOutcome, ConnectorRuntime, HttpRetryConfig, RetryLoop};

use crate::error::{FirecrawlError, FirecrawlResult};
use crate::types::{
    CrawlRequest, CrawlStartResponse, CrawlStatusResponse, ScrapeRequest, ScrapeResponse,
};

/// Firecrawl API client with retry support.
pub struct FirecrawlClient {
    client: Client,
    base_url: String,
    api_key: String,
    retry_config: HttpRetryConfig,
    pub(crate) timeout: Duration,
}

impl std::fmt::Debug for FirecrawlClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FirecrawlClient")
            .field("base_url", &self.base_url)
            .field("api_key", &"[REDACTED]")
            .field("retry_config", &self.retry_config)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

#[allow(clippy::missing_errors_doc, clippy::unused_async)]
impl FirecrawlClient {
    pub async fn new(
        base_url: &str,
        api_key: &str,
        retry_config: HttpRetryConfig,
        timeout: Duration,
    ) -> FirecrawlResult<Self> {
        let client = Client::builder()
            .timeout(timeout)
            .build()
            .map_err(FirecrawlError::Http)?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key: api_key.to_string(),
            retry_config,
            timeout,
        })
    }

    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    #[must_use]
    pub fn is_secretless(&self) -> bool {
        self.api_key.trim().is_empty()
    }

    // ── Scrape ──

    pub async fn scrape(
        &self,
        runtime: &ConnectorRuntime,
        request: &ScrapeRequest,
    ) -> FirecrawlResult<ScrapeResponse> {
        let url = format!("{}/scrape", self.base_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let body = serde_json::to_value(request).map_err(FirecrawlError::Json)?;

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let api_key = self.api_key.clone();
            let body = body.clone();
            async move {
                debug!(attempt, "Scraping URL via Firecrawl");
                let req = authenticate_request(client.post(&url), &api_key).json(&body);
                handle_response::<ScrapeResponse>(req, attempt).await
            }
        })
        .await
    }

    // ── Crawl ──

    pub async fn start_crawl(
        &self,
        runtime: &ConnectorRuntime,
        request: &CrawlRequest,
    ) -> FirecrawlResult<CrawlStartResponse> {
        let url = format!("{}/crawl", self.base_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let body = serde_json::to_value(request).map_err(FirecrawlError::Json)?;

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let api_key = self.api_key.clone();
            let body = body.clone();
            async move {
                debug!(attempt, "Starting crawl via Firecrawl");
                let req = authenticate_request(client.post(&url), &api_key).json(&body);
                handle_response::<CrawlStartResponse>(req, attempt).await
            }
        })
        .await
    }

    pub async fn get_crawl_status(
        &self,
        runtime: &ConnectorRuntime,
        crawl_id: &str,
    ) -> FirecrawlResult<CrawlStatusResponse> {
        validate_crawl_id(crawl_id)?;
        let url = format!("{}/crawl/{crawl_id}", self.base_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let api_key = self.api_key.clone();
            async move {
                debug!(attempt, crawl_id, "Checking crawl status");
                let req = authenticate_request(client.get(&url), &api_key);
                handle_response::<CrawlStatusResponse>(req, attempt).await
            }
        })
        .await
    }
}

// ── Free functions ──

/// Validate a crawl ID to prevent path injection.
fn validate_crawl_id(id: &str) -> FirecrawlResult<()> {
    if id.trim().is_empty() {
        return Err(FirecrawlError::InvalidInput(
            "crawl_id must not be empty".into(),
        ));
    }
    let lower = id.to_ascii_lowercase();
    if id.contains('/')
        || id.contains('\\')
        || id.contains("..")
        || lower.contains("%2f")
        || lower.contains("%5c")
    {
        return Err(FirecrawlError::InvalidInput(
            "crawl_id contains path traversal characters".into(),
        ));
    }
    Ok(())
}

fn authenticate_request(req: RequestBuilder, api_key: &str) -> RequestBuilder {
    if api_key.is_empty() {
        req
    } else {
        req.bearer_auth(api_key)
    }
}

async fn handle_response<T: serde::de::DeserializeOwned>(
    req: RequestBuilder,
    attempt: u32,
) -> AttemptOutcome<T, FirecrawlError> {
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            return AttemptOutcome::Retryable {
                error: FirecrawlError::Http(e),
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
            error: FirecrawlError::RateLimited {
                retry_after_ms: u64::try_from(
                    retry_after.unwrap_or(Duration::from_secs(60)).as_millis(),
                )
                .unwrap_or(u64::MAX),
            },
            retry_after,
        };
    }

    if status == 401 || status == 403 {
        return AttemptOutcome::Terminal(FirecrawlError::Unauthorized(format!(
            "Authentication failed (HTTP {status})"
        )));
    }

    if status == 404 {
        return AttemptOutcome::Terminal(FirecrawlError::NotFound(format!(
            "Resource not found (HTTP {status})"
        )));
    }

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        let err = FirecrawlError::Api {
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

    // Parse response body
    let text = match resp.text().await {
        Ok(t) => t,
        Err(e) => return AttemptOutcome::Terminal(FirecrawlError::Http(e)),
    };

    match serde_json::from_str::<T>(&text) {
        Ok(v) => AttemptOutcome::Success(v),
        Err(e) => {
            debug!(attempt, "Failed to parse Firecrawl response: {e}");
            AttemptOutcome::Terminal(FirecrawlError::Json(e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_debug_redacts_api_key() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            FirecrawlClient::new(
                "https://api.firecrawl.dev/v1",
                "fc-secret-key-123",
                HttpRetryConfig::default(),
                Duration::from_secs(30),
            )
            .await
            .unwrap()
        })
        .unwrap();

        let debug = format!("{rt:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("fc-secret-key-123"));
    }

    #[test]
    fn secretless_detection() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            FirecrawlClient::new(
                "https://api.firecrawl.dev/v1",
                "",
                HttpRetryConfig::default(),
                Duration::from_secs(30),
            )
            .await
            .unwrap()
        })
        .unwrap();
        assert!(rt.is_secretless());

        let rt2 = fcp_async_core::runtime::block_on_sync(async {
            FirecrawlClient::new(
                "https://api.firecrawl.dev/v1",
                "fc-key",
                HttpRetryConfig::default(),
                Duration::from_secs(30),
            )
            .await
            .unwrap()
        })
        .unwrap();
        assert!(!rt2.is_secretless());
    }

    #[test]
    fn base_url_trailing_slash_trimmed() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            FirecrawlClient::new(
                "https://api.firecrawl.dev/v1/",
                "key",
                HttpRetryConfig::default(),
                Duration::from_secs(30),
            )
            .await
            .unwrap()
        })
        .unwrap();
        assert!(!rt.base_url().ends_with('/'));
    }

    #[test]
    fn validate_crawl_id_rejects_traversal() {
        assert!(validate_crawl_id("../admin").is_err());
        assert!(validate_crawl_id("foo/bar").is_err());
        assert!(validate_crawl_id("foo\\bar").is_err());
        assert!(validate_crawl_id("foo%2fbar").is_err());
        assert!(validate_crawl_id("foo%5Cbar").is_err());
        assert!(validate_crawl_id("").is_err());
        assert!(validate_crawl_id("  ").is_err());
    }

    #[test]
    fn validate_crawl_id_accepts_valid() {
        assert!(validate_crawl_id("crawl-abc-123").is_ok());
        assert!(validate_crawl_id("550e8400-e29b-41d4-a716-446655440000").is_ok());
    }

    #[test]
    fn client_uses_configured_timeout() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            FirecrawlClient::new(
                "https://api.firecrawl.dev/v1",
                "key",
                HttpRetryConfig::default(),
                Duration::from_millis(1_234),
            )
            .await
            .unwrap()
        })
        .unwrap();
        assert_eq!(rt.timeout, Duration::from_millis(1_234));
    }
}
