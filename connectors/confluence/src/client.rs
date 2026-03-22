//! Confluence API client with retry support.

use base64::Engine;
use fcp_sdk::migration::{
    AttemptOutcome, ConnectorRuntime, HttpRetryConfig, RetryLoop, classify_http_status,
};
use fcp_sdk::retry::RetryDecision;
use reqwest::Client;
use std::time::Duration;
use tracing::{debug, warn};

use crate::error::{Error, Result};
use crate::types::{ApiErrorResponse, Page, PaginatedResponse, SearchResult, Space};

/// Confluence API client with retry and runtime integration.
pub struct ConfluenceClient {
    client: Client,
    base_url: String,
    email: String,
    api_token: String,
    retry_config: HttpRetryConfig,
}

impl std::fmt::Debug for ConfluenceClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfluenceClient")
            .field("base_url", &self.base_url)
            .field("email", &self.email)
            .field("api_token", &"[REDACTED]")
            .field("retry_config", &self.retry_config)
            .finish()
    }
}

/// Sanitize a path segment to prevent path traversal.
fn sanitize_path_segment(segment: &str) -> Result<&str> {
    if segment.trim().is_empty()
        || segment.contains('/')
        || segment.contains('\\')
        || segment.contains('\0')
        || segment == "."
        || segment == ".."
    {
        return Err(Error::InvalidInput(format!(
            "Invalid path segment: {segment}"
        )));
    }
    Ok(segment)
}

impl ConfluenceClient {
    /// Create a new Confluence client.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be built.
    pub fn new(
        base_url: &str,
        email: &str,
        api_token: &str,
        retry_config: HttpRetryConfig,
    ) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(Error::Http)?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            email: email.to_string(),
            api_token: api_token.to_string(),
            retry_config,
        })
    }

    /// Build Basic auth header value.
    fn auth_header(&self) -> String {
        let creds = format!("{}:{}", self.email, self.api_token);
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(creds.as_bytes())
        )
    }

    /// List spaces.
    pub async fn list_spaces(
        &self,
        runtime: &ConnectorRuntime,
        start: u64,
        limit: u64,
    ) -> Result<PaginatedResponse<Space>> {
        let url = format!("{}/rest/api/space", self.base_url);
        let query = vec![("start", start.to_string()), ("limit", limit.to_string())];
        self.get_with_retry(runtime, &url, &query).await
    }

    /// Get a space by key.
    pub async fn get_space(&self, runtime: &ConnectorRuntime, space_key: &str) -> Result<Space> {
        let key = sanitize_path_segment(space_key)?;
        let url = format!("{}/rest/api/space/{key}", self.base_url);
        self.get_with_retry::<Space>(runtime, &url, &[]).await
    }

    /// List pages in a space.
    pub async fn list_pages(
        &self,
        runtime: &ConnectorRuntime,
        space_key: &str,
        start: u64,
        limit: u64,
    ) -> Result<PaginatedResponse<Page>> {
        let key = sanitize_path_segment(space_key)?;
        let url = format!("{}/rest/api/space/{key}/content/page", self.base_url);
        let query = vec![
            ("start", start.to_string()),
            ("limit", limit.to_string()),
            ("expand", "version,space".to_string()),
        ];
        self.get_with_retry(runtime, &url, &query).await
    }

    /// Get a page by ID.
    pub async fn get_page(&self, runtime: &ConnectorRuntime, page_id: &str) -> Result<Page> {
        let id = sanitize_path_segment(page_id)?;
        let url = format!("{}/rest/api/content/{id}", self.base_url);
        let query = vec![("expand", "body.storage,version,space".to_string())];
        self.get_with_retry::<Page>(runtime, &url, &query).await
    }

    /// Create a page.
    pub async fn create_page(
        &self,
        runtime: &ConnectorRuntime,
        body: &serde_json::Value,
    ) -> Result<Page> {
        let url = format!("{}/rest/api/content", self.base_url);
        self.post_with_retry(runtime, &url, body).await
    }

    /// Update a page.
    pub async fn update_page(
        &self,
        runtime: &ConnectorRuntime,
        page_id: &str,
        body: &serde_json::Value,
    ) -> Result<Page> {
        let id = sanitize_path_segment(page_id)?;
        let url = format!("{}/rest/api/content/{id}", self.base_url);
        self.put_with_retry(runtime, &url, body).await
    }

    /// Delete a page.
    pub async fn delete_page(&self, runtime: &ConnectorRuntime, page_id: &str) -> Result<()> {
        let id = sanitize_path_segment(page_id)?;
        let url = format!("{}/rest/api/content/{id}", self.base_url);
        self.delete_with_retry(runtime, &url).await
    }

    /// Search using CQL.
    pub async fn search(
        &self,
        runtime: &ConnectorRuntime,
        cql: &str,
        start: u64,
        limit: u64,
    ) -> Result<PaginatedResponse<SearchResult>> {
        let url = format!("{}/rest/api/search", self.base_url);
        let query = vec![
            ("cql", cql.to_string()),
            ("start", start.to_string()),
            ("limit", limit.to_string()),
        ];
        self.get_with_retry(runtime, &url, &query).await
    }

    /// Health check: validate API reachability.
    pub async fn health_check(&self) -> Result<()> {
        let url = format!("{}/rest/api/space", self.base_url);
        let resp = self
            .client
            .get(&url)
            .header("Authorization", self.auth_header())
            .query(&[("limit", "1")])
            .send()
            .await
            .map_err(Error::Http)?;
        let status = resp.status().as_u16();

        if resp.status().is_success() {
            Ok(())
        } else if status == 429 {
            let retry_after_ms = resp
                .headers()
                .get("retry-after")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(30)
                * 1000;
            Err(Error::RateLimited { retry_after_ms })
        } else if status == 401 {
            Err(Error::Unauthorized("Invalid credentials".into()))
        } else {
            Err(Error::Api {
                status,
                message: format!("Health check failed with HTTP {status}"),
            })
        }
    }

    /// Get the base URL (for diagnostics).
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Check if using secretless mode.
    pub fn is_secretless(&self) -> bool {
        self.api_token.is_empty()
    }

    /// Generic GET with retry.
    async fn get_with_retry<T: serde::de::DeserializeOwned>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
        query: &[(&str, String)],
    ) -> Result<T> {
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let auth = self.auth_header();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.to_string();
            let client = self.client.clone();
            let auth = auth.clone();
            let query: Vec<(String, String)> = query
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect();
            async move {
                debug!(attempt, "GET {}", url);
                let mut req = client.get(&url).header("Authorization", &auth);
                for (k, v) in &query {
                    req = req.query(&[(k.as_str(), v.as_str())]);
                }
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: Error::Http(e),
                            retry_after: None,
                        };
                    }
                };
                handle_response(resp).await
            }
        })
        .await
    }

    /// Generic POST with retry.
    async fn post_with_retry<T: serde::de::DeserializeOwned>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
        body: &serde_json::Value,
    ) -> Result<T> {
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let body_clone = body.clone();
        let auth = self.auth_header();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.to_string();
            let client = self.client.clone();
            let auth = auth.clone();
            let body = body_clone.clone();
            async move {
                debug!(attempt, "POST {}", url);
                let resp = match client
                    .post(&url)
                    .header("Authorization", &auth)
                    .header("Content-Type", "application/json")
                    .json(&body)
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: Error::Http(e),
                            retry_after: None,
                        };
                    }
                };
                handle_response(resp).await
            }
        })
        .await
    }

    /// Generic PUT with retry.
    async fn put_with_retry<T: serde::de::DeserializeOwned>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
        body: &serde_json::Value,
    ) -> Result<T> {
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let body_clone = body.clone();
        let auth = self.auth_header();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.to_string();
            let client = self.client.clone();
            let auth = auth.clone();
            let body = body_clone.clone();
            async move {
                debug!(attempt, "PUT {}", url);
                let resp = match client
                    .put(&url)
                    .header("Authorization", &auth)
                    .header("Content-Type", "application/json")
                    .json(&body)
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: Error::Http(e),
                            retry_after: None,
                        };
                    }
                };
                handle_response(resp).await
            }
        })
        .await
    }

    /// DELETE with retry.
    async fn delete_with_retry(&self, runtime: &ConnectorRuntime, url: &str) -> Result<()> {
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let auth = self.auth_header();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.to_string();
            let client = self.client.clone();
            let auth = auth.clone();
            async move {
                debug!(attempt, "DELETE {}", url);
                let resp = match client
                    .delete(&url)
                    .header("Authorization", &auth)
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: Error::Http(e),
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
                        error: Error::RateLimited {
                            retry_after_ms: retry_after
                                .unwrap_or(Duration::from_secs(30))
                                .as_millis() as u64,
                        },
                        retry_after,
                    };
                }

                if status == 401 {
                    return AttemptOutcome::Terminal(Error::Unauthorized(
                        "Invalid credentials".into(),
                    ));
                }

                if !resp.status().is_success() && status != 204 {
                    let text = resp.text().await.unwrap_or_default();
                    warn!(status, "Confluence DELETE failed");
                    let message = serde_json::from_str::<ApiErrorResponse>(&text)
                        .map(|e| e.message)
                        .unwrap_or(text);
                    let decision = classify_http_status(status, None);
                    let err = Error::Api { status, message };
                    if !matches!(decision, RetryDecision::Terminal) {
                        return AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        };
                    }
                    return AttemptOutcome::Terminal(err);
                }

                AttemptOutcome::Success(())
            }
        })
        .await
    }
}

/// Handle response: check status, parse JSON.
async fn handle_response<T: serde::de::DeserializeOwned>(
    resp: reqwest::Response,
) -> AttemptOutcome<T, Error> {
    let status = resp.status().as_u16();

    if status == 429 {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .map(Duration::from_secs);
        return AttemptOutcome::Retryable {
            error: Error::RateLimited {
                retry_after_ms: retry_after.unwrap_or(Duration::from_secs(30)).as_millis() as u64,
            },
            retry_after,
        };
    }

    if status == 401 {
        return AttemptOutcome::Terminal(Error::Unauthorized("Invalid credentials".into()));
    }

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        warn!(status, "Confluence request failed");
        let message = serde_json::from_str::<ApiErrorResponse>(&text)
            .map(|e| e.message)
            .unwrap_or(text);
        let decision = classify_http_status(status, None);
        let err = Error::Api { status, message };
        if !matches!(decision, RetryDecision::Terminal) {
            return AttemptOutcome::Retryable {
                error: err,
                retry_after: None,
            };
        }
        return AttemptOutcome::Terminal(err);
    }

    match resp.json::<T>().await {
        Ok(r) => AttemptOutcome::Success(r),
        Err(e) => AttemptOutcome::Terminal(Error::Http(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn client_creation() {
        let client = ConfluenceClient::new(
            "https://example.atlassian.net/wiki",
            "user@example.com",
            "test_token",
            HttpRetryConfig::default(),
        );
        assert!(client.is_ok());
    }

    #[test]
    fn base_url_trimmed() {
        let client = ConfluenceClient::new(
            "https://example.atlassian.net/wiki/",
            "user@example.com",
            "test_token",
            HttpRetryConfig::default(),
        )
        .unwrap();
        assert!(!client.base_url().ends_with('/'));
    }

    #[test]
    fn secretless_detection() {
        let client = ConfluenceClient::new(
            "https://example.atlassian.net/wiki",
            "user@example.com",
            "",
            HttpRetryConfig::default(),
        )
        .unwrap();
        assert!(client.is_secretless());
    }

    #[test]
    fn debug_redacts_api_token() {
        let client = ConfluenceClient::new(
            "https://example.atlassian.net/wiki",
            "user@example.com",
            "super_secret_token",
            HttpRetryConfig::default(),
        )
        .unwrap();
        let debug_output = format!("{client:?}");
        assert!(!debug_output.contains("super_secret_token"));
        assert!(debug_output.contains("[REDACTED]"));
    }

    #[test]
    fn non_secretless() {
        let client = ConfluenceClient::new(
            "https://example.atlassian.net/wiki",
            "user@example.com",
            "real_token",
            HttpRetryConfig::default(),
        )
        .unwrap();
        assert!(!client.is_secretless());
    }

    #[test]
    fn sanitize_path_rejects_traversal() {
        assert!(sanitize_path_segment("..").is_err());
        assert!(sanitize_path_segment(".").is_err());
        assert!(sanitize_path_segment("foo/bar").is_err());
        assert!(sanitize_path_segment("").is_err());
        assert!(sanitize_path_segment("foo\0bar").is_err());
    }

    #[test]
    fn sanitize_path_accepts_valid() {
        assert!(sanitize_path_segment("DEV").is_ok());
        assert!(sanitize_path_segment("12345").is_ok());
        assert!(sanitize_path_segment("my-space").is_ok());
    }

    #[test]
    fn auth_header_format() {
        let client = ConfluenceClient::new(
            "https://example.atlassian.net/wiki",
            "user@example.com",
            "api_token",
            HttpRetryConfig::default(),
        )
        .unwrap();
        let header = client.auth_header();
        assert!(header.starts_with("Basic "));
        // Decode and verify
        let encoded = header.strip_prefix("Basic ").unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();
        let decoded_str = String::from_utf8(decoded).unwrap();
        assert_eq!(decoded_str, "user@example.com:api_token");
    }

    #[fcp_async_core::runtime::test]
    async fn health_check_success() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/rest/api/space"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": [],
                "start": 0,
                "limit": 1,
                "size": 0
            })))
            .mount(&mock_server)
            .await;

        let client = ConfluenceClient::new(
            &mock_server.uri(),
            "user@example.com",
            "test_token",
            HttpRetryConfig::default(),
        )
        .unwrap();
        assert!(client.health_check().await.is_ok());
    }

    #[fcp_async_core::runtime::test]
    async fn health_check_unauthorized() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/rest/api/space"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&mock_server)
            .await;

        let client = ConfluenceClient::new(
            &mock_server.uri(),
            "user@example.com",
            "bad_token",
            HttpRetryConfig::default(),
        )
        .unwrap();
        let err = client.health_check().await.unwrap_err();
        assert!(matches!(err, Error::Unauthorized(_)));
    }

    #[fcp_async_core::runtime::test]
    async fn health_check_rate_limited() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/rest/api/space"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "60"))
            .mount(&mock_server)
            .await;

        let client = ConfluenceClient::new(
            &mock_server.uri(),
            "user@example.com",
            "test_token",
            HttpRetryConfig::default(),
        )
        .unwrap();
        let err = client.health_check().await.unwrap_err();
        assert!(matches!(
            err,
            Error::RateLimited {
                retry_after_ms: 60000
            }
        ));
    }
}
