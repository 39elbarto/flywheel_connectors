//! Notion REST API client.

use fcp_core::CredentialId;
use reqwest::{Client, StatusCode, header};
use tracing::{debug, warn};

use crate::{
    error::{NotionError, NotionResult},
    types::{ApiErrorResponse, Page, PaginatedResponse},
};

/// Default Notion API base URL.
pub const DEFAULT_API_URL: &str = "https://api.notion.com/v1";
const NOTION_VERSION: &str = "2022-06-28";

/// Authentication mode for the Notion connector.
#[derive(Clone)]
pub enum NotionAuth {
    /// Direct integration/OAuth token (Bearer auth).
    Token(String),
    /// Secretless mode – egress proxy injects credentials at runtime.
    CredentialId(CredentialId),
}

impl std::fmt::Debug for NotionAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotionAuth").finish_non_exhaustive()
    }
}

impl NotionAuth {
    /// Human-readable label with secrets redacted.
    #[must_use]
    pub fn redacted_label(&self) -> &'static str {
        match self {
            Self::Token(_) => "token:****",
            Self::CredentialId(_) => "credential_id",
        }
    }

    /// Whether this auth mode is secretless (egress proxy).
    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

/// Notion REST API client.
pub struct NotionClient {
    http: Client,
    api_url: String,
    max_retries: u32,
    auth: NotionAuth,
}

impl std::fmt::Debug for NotionClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotionClient").finish_non_exhaustive()
    }
}

impl NotionClient {
    /// Create a new Notion client with a direct integration token.
    pub fn new(token: &str) -> NotionResult<Self> {
        Self::new_with_auth(NotionAuth::Token(token.to_string()))
    }

    /// Create a new Notion client with the specified auth mode.
    pub fn new_with_auth(auth: NotionAuth) -> NotionResult<Self> {
        let mut headers = header::HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        headers.insert("Notion-Version", NOTION_VERSION.parse().unwrap());

        match &auth {
            NotionAuth::Token(token) => {
                headers.insert(
                    header::AUTHORIZATION,
                    format!("Bearer {token}")
                        .parse()
                        .map_err(|_| NotionError::Api {
                            message: "Invalid token value for header".into(),
                            status_code: None,
                        })?,
                );
            }
            NotionAuth::CredentialId(id) => {
                headers.insert(
                    "X-FCP-Credential-ID",
                    id.to_string().parse().map_err(|_| NotionError::Api {
                        message: "Invalid credential_id value for header".into(),
                        status_code: None,
                    })?,
                );
            }
        }

        let http = Client::builder()
            .default_headers(headers)
            .user_agent("fcp-notion/0.1.0")
            .build()
            .map_err(NotionError::Http)?;

        Ok(Self {
            http,
            api_url: DEFAULT_API_URL.to_string(),
            max_retries: 2,
            auth,
        })
    }

    /// Lightweight connectivity probe – search with no query.
    pub async fn health_check(&self) -> NotionResult<()> {
        let url = format!("{}/search", self.api_url);
        let body = serde_json::json!({ "page_size": 1 });
        self.post(&url, Some(body)).await?;
        Ok(())
    }

    /// Set a custom API URL (for testing).
    #[must_use]
    pub fn with_api_url(mut self, url: &str) -> Self {
        self.api_url = url.to_string();
        self
    }

    /// Set the maximum number of retries.
    #[must_use]
    pub fn with_retry_config(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    // ── Page operations ───────────────────────────────────────────

    /// Create a page.
    pub async fn create_page(&self, body: serde_json::Value) -> NotionResult<Page> {
        let url = format!("{}/pages", self.api_url);
        let data = self.post(&url, Some(body)).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Get a page by ID.
    pub async fn get_page(&self, page_id: &str) -> NotionResult<Page> {
        let url = format!("{}/pages/{page_id}", self.api_url);
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Update a page (PATCH properties).
    pub async fn update_page(&self, page_id: &str, body: serde_json::Value) -> NotionResult<Page> {
        let url = format!("{}/pages/{page_id}", self.api_url);
        let data = self.patch(&url, body).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Archive (soft-delete) a page.
    pub async fn delete_page(&self, page_id: &str) -> NotionResult<Page> {
        let url = format!("{}/pages/{page_id}", self.api_url);
        let body = serde_json::json!({ "archived": true });
        let data = self.patch(&url, body).await?;
        Ok(serde_json::from_value(data)?)
    }

    // ── Database operations ───────────────────────────────────────

    /// Query a database with optional filter and sorts.
    pub async fn query_database(
        &self,
        database_id: &str,
        filter: Option<serde_json::Value>,
        start_cursor: Option<&str>,
    ) -> NotionResult<PaginatedResponse> {
        let url = format!("{}/databases/{database_id}/query", self.api_url);
        let mut body = serde_json::json!({});
        if let Some(f) = filter {
            body["filter"] = f;
        }
        if let Some(cursor) = start_cursor {
            body["start_cursor"] = serde_json::Value::String(cursor.into());
        }
        let data = self.post(&url, Some(body)).await?;
        Ok(serde_json::from_value(data)?)
    }

    // ── Search ────────────────────────────────────────────────────

    /// Search pages and databases.
    pub async fn search(
        &self,
        query: Option<&str>,
        filter: Option<serde_json::Value>,
    ) -> NotionResult<PaginatedResponse> {
        let url = format!("{}/search", self.api_url);
        let mut body = serde_json::json!({});
        if let Some(q) = query {
            body["query"] = serde_json::Value::String(q.into());
        }
        if let Some(f) = filter {
            body["filter"] = f;
        }
        let data = self.post(&url, Some(body)).await?;
        Ok(serde_json::from_value(data)?)
    }

    // ── Block operations ──────────────────────────────────────────

    /// Get child blocks of a block or page.
    pub async fn get_block_children(&self, block_id: &str) -> NotionResult<PaginatedResponse> {
        let url = format!("{}/blocks/{block_id}/children", self.api_url);
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Append child blocks to a page or block.
    pub async fn append_blocks(
        &self,
        block_id: &str,
        children: serde_json::Value,
    ) -> NotionResult<PaginatedResponse> {
        let url = format!("{}/blocks/{block_id}/children", self.api_url);
        let body = serde_json::json!({ "children": children });
        let data = self.patch(&url, body).await?;
        Ok(serde_json::from_value(data)?)
    }

    // ── Comment operations ────────────────────────────────────────

    /// Add a comment to a page.
    pub async fn add_comment(&self, body: serde_json::Value) -> NotionResult<serde_json::Value> {
        let url = format!("{}/comments", self.api_url);
        self.post(&url, Some(body)).await
    }

    /// List comments on a block or page.
    pub async fn list_comments(&self, block_id: &str) -> NotionResult<PaginatedResponse> {
        let url = format!("{}/comments?block_id={block_id}", self.api_url);
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    // ── HTTP helpers ──────────────────────────────────────────────

    async fn get(&self, url: &str) -> NotionResult<serde_json::Value> {
        self.execute(|| self.http.get(url)).await
    }

    async fn post(
        &self,
        url: &str,
        body: Option<serde_json::Value>,
    ) -> NotionResult<serde_json::Value> {
        self.execute(|| {
            let mut req = self.http.post(url);
            if let Some(b) = &body {
                req = req.json(b);
            }
            req
        })
        .await
    }

    async fn patch(&self, url: &str, body: serde_json::Value) -> NotionResult<serde_json::Value> {
        self.execute(|| self.http.patch(url).json(&body)).await
    }

    async fn execute(
        &self,
        build_request: impl Fn() -> reqwest::RequestBuilder,
    ) -> NotionResult<serde_json::Value> {
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
                        return Err(NotionError::Unauthorized);
                    }

                    if status == StatusCode::NOT_FOUND {
                        let body = response.text().await.unwrap_or_default();
                        return Err(NotionError::NotFound { resource: body });
                    }

                    if status == StatusCode::TOO_MANY_REQUESTS {
                        let retry_after = response
                            .headers()
                            .get("retry-after")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.parse::<u64>().ok())
                            .map_or(60_000, |s| s * 1000);

                        let err = NotionError::RateLimited {
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
                        let err = NotionError::Api {
                            message: format!("Server error {status}: {body}"),
                            status_code: Some(status.as_u16()),
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
                        let api_err: Option<ApiErrorResponse> = serde_json::from_str(&body).ok();
                        let message = api_err
                            .as_ref()
                            .and_then(|e| e.message.clone())
                            .unwrap_or(format!("HTTP {status}: {body}"));
                        return Err(NotionError::Api {
                            message,
                            status_code: Some(status.as_u16()),
                        });
                    }

                    let body = response.text().await.map_err(NotionError::Http)?;
                    let data: serde_json::Value = serde_json::from_str(&body)?;
                    return Ok(data);
                }
                Err(e) => {
                    if attempt < self.max_retries {
                        warn!(attempt, error = %e, "request failed, will retry");
                        last_err = Some(NotionError::Http(e));
                        continue;
                    }
                    return Err(NotionError::Http(e));
                }
            }
        }

        Err(last_err.unwrap_or(NotionError::Api {
            message: "Max retries exceeded".into(),
            status_code: None,
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
    async fn test_get_page() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/pages/page-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "page-1",
                "object": "page",
                "archived": false,
                "url": "https://notion.so/page-1",
                "properties": {}
            })))
            .mount(&mock_server)
            .await;

        let client = NotionClient::new("test-token")
            .unwrap()
            .with_api_url(&format!("{}/v1", mock_server.uri()));

        let page = client.get_page("page-1").await.unwrap();
        assert_eq!(page.id, "page-1");
        assert!(!page.archived);
    }

    #[fcp_async_core::runtime::test]
    async fn test_create_page() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/pages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "page-2",
                "object": "page",
                "archived": false,
                "properties": {}
            })))
            .mount(&mock_server)
            .await;

        let client = NotionClient::new("test-token")
            .unwrap()
            .with_api_url(&format!("{}/v1", mock_server.uri()));

        let page = client
            .create_page(serde_json::json!({
                "parent": { "database_id": "db-1" },
                "properties": { "Name": { "title": [{ "text": { "content": "Test" } }] } }
            }))
            .await
            .unwrap();
        assert_eq!(page.id, "page-2");
    }

    #[fcp_async_core::runtime::test]
    async fn test_query_database() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/databases/db-1/query"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "object": "list",
                "results": [
                    { "id": "p1", "object": "page" },
                    { "id": "p2", "object": "page" }
                ],
                "has_more": false,
                "next_cursor": null
            })))
            .mount(&mock_server)
            .await;

        let client = NotionClient::new("test-token")
            .unwrap()
            .with_api_url(&format!("{}/v1", mock_server.uri()));

        let result = client.query_database("db-1", None, None).await.unwrap();
        assert_eq!(result.results.len(), 2);
        assert!(!result.has_more);
    }

    #[fcp_async_core::runtime::test]
    async fn test_search() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/search"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "object": "list",
                "results": [
                    { "id": "p1", "object": "page" }
                ],
                "has_more": false,
                "next_cursor": null
            })))
            .mount(&mock_server)
            .await;

        let client = NotionClient::new("test-token")
            .unwrap()
            .with_api_url(&format!("{}/v1", mock_server.uri()));

        let result = client.search(Some("meeting notes"), None).await.unwrap();
        assert_eq!(result.results.len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_block_children() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/blocks/block-1/children"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "object": "list",
                "results": [
                    { "id": "b1", "object": "block", "type": "paragraph" }
                ],
                "has_more": false,
                "next_cursor": null
            })))
            .mount(&mock_server)
            .await;

        let client = NotionClient::new("test-token")
            .unwrap()
            .with_api_url(&format!("{}/v1", mock_server.uri()));

        let result = client.get_block_children("block-1").await.unwrap();
        assert_eq!(result.results.len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_comments() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/comments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "object": "list",
                "results": [
                    { "id": "c1", "object": "comment", "rich_text": [] }
                ],
                "has_more": false,
                "next_cursor": null
            })))
            .mount(&mock_server)
            .await;

        let client = NotionClient::new("test-token")
            .unwrap()
            .with_api_url(&format!("{}/v1", mock_server.uri()));

        let result = client.list_comments("page-1").await.unwrap();
        assert_eq!(result.results.len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn test_unauthorized() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/pages/page-1"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&mock_server)
            .await;

        let client = NotionClient::new("bad-token")
            .unwrap()
            .with_api_url(&format!("{}/v1", mock_server.uri()))
            .with_retry_config(0);

        let result = client.get_page("page-1").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), NotionError::Unauthorized));
    }

    #[fcp_async_core::runtime::test]
    async fn test_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/pages/missing"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "object": "error",
                "status": 404,
                "code": "object_not_found",
                "message": "Could not find page"
            })))
            .mount(&mock_server)
            .await;

        let client = NotionClient::new("test-token")
            .unwrap()
            .with_api_url(&format!("{}/v1", mock_server.uri()))
            .with_retry_config(0);

        let result = client.get_page("missing").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), NotionError::NotFound { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_rate_limited() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/pages/page-1"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&mock_server)
            .await;

        let client = NotionClient::new("test-token")
            .unwrap()
            .with_api_url(&format!("{}/v1", mock_server.uri()))
            .with_retry_config(0);

        let result = client.get_page("page-1").await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            NotionError::RateLimited { .. }
        ));
    }

    #[test]
    fn test_error_is_retryable() {
        let err = NotionError::RateLimited {
            retry_after_ms: 1000,
        };
        assert!(err.is_retryable());

        let err = NotionError::Unauthorized;
        assert!(!err.is_retryable());

        let err = NotionError::Api {
            message: "Server error".into(),
            status_code: Some(500),
        };
        assert!(err.is_retryable());
    }
}
