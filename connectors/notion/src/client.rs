//! Notion REST API client.

use std::time::Duration;

use fcp_core::CredentialId;
use fcp_sdk::migration::{
    AttemptOutcome, ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig, RetryLoop,
};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::{Client, StatusCode, header};
use tracing::debug;

use crate::{
    error::{NotionError, NotionResult},
    types::{ApiErrorResponse, Page, PaginatedResponse},
};

/// Default Notion API base URL.
pub const DEFAULT_API_URL: &str = "https://api.notion.com/v1";

/// Default Notion API version. Notion uses a date-based version header.
/// This can be overridden via the `config_override` parameter or
/// the `FCP_NOTION_API_VERSION` environment variable.
pub const DEFAULT_NOTION_VERSION: &str = "2022-06-28";

/// Resolve the Notion API version to use: config override > env var > compiled default.
fn resolve_notion_version(config_override: Option<&str>) -> String {
    if let Some(v) = config_override.map(str::trim).filter(|s| !s.is_empty()) {
        return v.to_string();
    }
    if let Ok(v) = std::env::var("FCP_NOTION_API_VERSION") {
        let v = v.trim();
        if !v.is_empty() {
            return v.to_string();
        }
    }
    DEFAULT_NOTION_VERSION.to_string()
}

/// Characters that are NOT percent-encoded in a path segment.
const PATH_SEGMENT_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

/// Characters that are dangerous in URLs: path separators, query string
/// markers, fragment markers, percent signs (double-encoding), ampersands,
/// equals signs, and whitespace.
const FORBIDDEN_ID_CHARS: &[char] = &[
    '/', '\\', '?', '#', '&', '=', '%', ' ', '\t', '\n', '\r', '\0',
];

/// Validate a Notion object ID. Rejects empty strings and strings containing
/// URL-active characters (slashes, query markers, fragments, ampersands,
/// percent signs) that could allow URL injection or path traversal.
fn validate_notion_id(id: &str, label: &str) -> NotionResult<()> {
    if id.is_empty() {
        return Err(NotionError::Validation {
            message: format!("{label} must not be empty"),
        });
    }
    if id.chars().any(|c| FORBIDDEN_ID_CHARS.contains(&c)) {
        return Err(NotionError::Validation {
            message: format!("{label} contains URL-unsafe characters: {id:?}"),
        });
    }
    Ok(())
}

/// Percent-encode a value for safe inclusion in a URL path segment.
fn encode_path_segment(value: &str) -> String {
    utf8_percent_encode(value, PATH_SEGMENT_ENCODE_SET).to_string()
}

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
    notion_version: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
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

    /// Create a new Notion client with specified auth and optional API version override.
    pub fn new_with_version(auth: NotionAuth, version_override: Option<&str>) -> NotionResult<Self> {
        Self::build(auth, version_override)
    }

    /// Create a new Notion client with the specified auth mode.
    pub fn new_with_auth(auth: NotionAuth) -> NotionResult<Self> {
        Self::build(auth, None)
    }

    fn build(auth: NotionAuth, version_override: Option<&str>) -> NotionResult<Self> {
        let notion_version = resolve_notion_version(version_override);
        let mut headers = header::HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        headers.insert("Notion-Version", notion_version.parse().unwrap());

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
            notion_version,
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(30)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 2,
                ..HttpRetryConfig::default()
            },
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
        self.retry_config.max_retries = max_retries;
        self
    }

    /// Trigger graceful shutdown of request contexts.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    /// Get the Notion API version header used for requests.
    #[must_use]
    pub fn notion_version(&self) -> &str {
        &self.notion_version
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
        validate_notion_id(page_id, "page_id")?;
        let seg = encode_path_segment(page_id);
        let url = format!("{}/pages/{seg}", self.api_url);
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Update a page (PATCH properties).
    pub async fn update_page(&self, page_id: &str, body: serde_json::Value) -> NotionResult<Page> {
        validate_notion_id(page_id, "page_id")?;
        let seg = encode_path_segment(page_id);
        let url = format!("{}/pages/{seg}", self.api_url);
        let data = self.patch(&url, body).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Archive (soft-delete) a page.
    pub async fn delete_page(&self, page_id: &str) -> NotionResult<Page> {
        validate_notion_id(page_id, "page_id")?;
        let seg = encode_path_segment(page_id);
        let url = format!("{}/pages/{seg}", self.api_url);
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
        validate_notion_id(database_id, "database_id")?;
        let seg = encode_path_segment(database_id);
        let url = format!("{}/databases/{seg}/query", self.api_url);
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

    /// Get a database by ID.
    pub async fn get_database(&self, database_id: &str) -> NotionResult<serde_json::Value> {
        validate_notion_id(database_id, "database_id")?;
        let seg = encode_path_segment(database_id);
        let url = format!("{}/databases/{seg}", self.api_url);
        self.get(&url).await
    }

    /// Create a database.
    pub async fn create_database(
        &self,
        body: serde_json::Value,
    ) -> NotionResult<serde_json::Value> {
        let url = format!("{}/databases", self.api_url);
        self.post(&url, Some(body)).await
    }

    /// Update a database (PATCH title/properties/description).
    pub async fn update_database(
        &self,
        database_id: &str,
        body: serde_json::Value,
    ) -> NotionResult<serde_json::Value> {
        validate_notion_id(database_id, "database_id")?;
        let seg = encode_path_segment(database_id);
        let url = format!("{}/databases/{seg}", self.api_url);
        self.patch(&url, body).await
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
        validate_notion_id(block_id, "block_id")?;
        let seg = encode_path_segment(block_id);
        let url = format!("{}/blocks/{seg}/children", self.api_url);
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Get a single block by ID.
    pub async fn get_block(&self, block_id: &str) -> NotionResult<serde_json::Value> {
        validate_notion_id(block_id, "block_id")?;
        let seg = encode_path_segment(block_id);
        let url = format!("{}/blocks/{seg}", self.api_url);
        self.get(&url).await
    }

    /// Update a block's content.
    pub async fn update_block(
        &self,
        block_id: &str,
        body: serde_json::Value,
    ) -> NotionResult<serde_json::Value> {
        validate_notion_id(block_id, "block_id")?;
        let seg = encode_path_segment(block_id);
        let url = format!("{}/blocks/{seg}", self.api_url);
        self.patch(&url, body).await
    }

    /// Archive (soft-delete) a block.
    pub async fn delete_block(&self, block_id: &str) -> NotionResult<serde_json::Value> {
        validate_notion_id(block_id, "block_id")?;
        let seg = encode_path_segment(block_id);
        let url = format!("{}/blocks/{seg}", self.api_url);
        let body = serde_json::json!({ "archived": true });
        self.patch(&url, body).await
    }

    /// Append child blocks to a page or block.
    pub async fn append_blocks(
        &self,
        block_id: &str,
        children: serde_json::Value,
    ) -> NotionResult<PaginatedResponse> {
        validate_notion_id(block_id, "block_id")?;
        let seg = encode_path_segment(block_id);
        let url = format!("{}/blocks/{seg}/children", self.api_url);
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
        validate_notion_id(block_id, "block_id")?;
        let encoded_id = utf8_percent_encode(block_id, PATH_SEGMENT_ENCODE_SET).to_string();
        let url = format!("{}/comments?block_id={encoded_id}", self.api_url);
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
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let request = build_request();
            async move {
                debug!(attempt, "Notion API request");

                match request.send().await {
                    Ok(response) => {
                        let status = response.status();

                        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                            return AttemptOutcome::Terminal(NotionError::Unauthorized);
                        }

                        if status == StatusCode::NOT_FOUND {
                            let body = response.text().await.unwrap_or_default();
                            return AttemptOutcome::Terminal(NotionError::NotFound {
                                resource: body,
                            });
                        }

                        if status == StatusCode::TOO_MANY_REQUESTS {
                            let retry_after_secs = response
                                .headers()
                                .get("retry-after")
                                .and_then(|v| v.to_str().ok())
                                .and_then(|v| v.parse::<u64>().ok());
                            let retry_after = retry_after_secs
                                .map_or(Duration::from_secs(60), Duration::from_secs);

                            return AttemptOutcome::Retryable {
                                error: NotionError::RateLimited {
                                    retry_after_ms: retry_after.as_millis() as u64,
                                },
                                retry_after: Some(retry_after),
                            };
                        }

                        if status.is_server_error() {
                            let body = response.text().await.unwrap_or_default();
                            return AttemptOutcome::Retryable {
                                error: NotionError::Api {
                                    message: format!("Server error {status}: {body}"),
                                    status_code: Some(status.as_u16()),
                                },
                                retry_after: None,
                            };
                        }

                        if !status.is_success() {
                            let body = response.text().await.unwrap_or_default();
                            let api_err: Option<ApiErrorResponse> =
                                serde_json::from_str(&body).ok();
                            let message = api_err
                                .as_ref()
                                .and_then(|e| e.message.clone())
                                .unwrap_or(format!("HTTP {status}: {body}"));
                            return AttemptOutcome::Terminal(NotionError::Api {
                                message,
                                status_code: Some(status.as_u16()),
                            });
                        }

                        match response.text().await {
                            Ok(body) => match serde_json::from_str::<serde_json::Value>(&body) {
                                Ok(data) => AttemptOutcome::Success(data),
                                Err(error) => AttemptOutcome::Terminal(NotionError::Json(error)),
                            },
                            Err(error) if error.is_timeout() || error.is_connect() => {
                                AttemptOutcome::Retryable {
                                    error: NotionError::Http(error),
                                    retry_after: None,
                                }
                            }
                            Err(error) => AttemptOutcome::Terminal(NotionError::Http(error)),
                        }
                    }
                    Err(error) if error.is_timeout() || error.is_connect() => {
                        AttemptOutcome::Retryable {
                            error: NotionError::Http(error),
                            retry_after: None,
                        }
                    }
                    Err(error) => AttemptOutcome::Terminal(NotionError::Http(error)),
                }
            }
        })
        .await
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
    async fn test_get_database() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/databases/db-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "db-1",
                "object": "database",
                "title": [{"text": {"content": "Tasks"}, "plain_text": "Tasks"}],
                "properties": {
                    "Name": {"type": "title", "title": {}},
                    "Status": {"type": "select", "select": {}}
                }
            })))
            .mount(&mock_server)
            .await;

        let client = NotionClient::new("test-token")
            .unwrap()
            .with_api_url(&format!("{}/v1", mock_server.uri()));

        let db = client.get_database("db-1").await.unwrap();
        assert_eq!(db["id"], "db-1");
        assert_eq!(db["object"], "database");
    }

    #[fcp_async_core::runtime::test]
    async fn test_create_database() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/databases"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "db-new",
                "object": "database",
                "title": [{"text": {"content": "New DB"}, "plain_text": "New DB"}],
                "properties": {"Name": {"type": "title", "title": {}}}
            })))
            .mount(&mock_server)
            .await;

        let client = NotionClient::new("test-token")
            .unwrap()
            .with_api_url(&format!("{}/v1", mock_server.uri()));

        let db = client
            .create_database(serde_json::json!({
                "parent": {"page_id": "page-1"},
                "title": [{"text": {"content": "New DB"}}],
                "properties": {"Name": {"title": {}}}
            }))
            .await
            .unwrap();
        assert_eq!(db["id"], "db-new");
    }

    #[fcp_async_core::runtime::test]
    async fn test_update_database() {
        let mock_server = MockServer::start().await;

        Mock::given(method("PATCH"))
            .and(path("/v1/databases/db-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "db-1",
                "object": "database",
                "title": [{"text": {"content": "Updated"}, "plain_text": "Updated"}],
                "properties": {"Name": {"type": "title", "title": {}}}
            })))
            .mount(&mock_server)
            .await;

        let client = NotionClient::new("test-token")
            .unwrap()
            .with_api_url(&format!("{}/v1", mock_server.uri()));

        let db = client
            .update_database(
                "db-1",
                serde_json::json!({"title": [{"text": {"content": "Updated"}}]}),
            )
            .await
            .unwrap();
        assert_eq!(db["id"], "db-1");
        assert_eq!(db["title"][0]["plain_text"], "Updated");
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_block() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/blocks/block-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "block-1",
                "object": "block",
                "type": "paragraph",
                "has_children": false,
                "archived": false,
                "paragraph": {
                    "rich_text": [{"text": {"content": "Hello"}, "plain_text": "Hello"}]
                }
            })))
            .mount(&mock_server)
            .await;

        let client = NotionClient::new("test-token")
            .unwrap()
            .with_api_url(&format!("{}/v1", mock_server.uri()));

        let block = client.get_block("block-1").await.unwrap();
        assert_eq!(block["id"], "block-1");
        assert_eq!(block["type"], "paragraph");
    }

    #[fcp_async_core::runtime::test]
    async fn test_update_block() {
        let mock_server = MockServer::start().await;

        Mock::given(method("PATCH"))
            .and(path("/v1/blocks/block-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "block-1",
                "object": "block",
                "type": "paragraph",
                "paragraph": {
                    "rich_text": [{"text": {"content": "Updated"}, "plain_text": "Updated"}]
                }
            })))
            .mount(&mock_server)
            .await;

        let client = NotionClient::new("test-token")
            .unwrap()
            .with_api_url(&format!("{}/v1", mock_server.uri()));

        let block = client
            .update_block(
                "block-1",
                serde_json::json!({
                    "paragraph": {"rich_text": [{"text": {"content": "Updated"}}]}
                }),
            )
            .await
            .unwrap();
        assert_eq!(block["id"], "block-1");
    }

    #[fcp_async_core::runtime::test]
    async fn test_delete_block() {
        let mock_server = MockServer::start().await;

        Mock::given(method("PATCH"))
            .and(path("/v1/blocks/block-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "block-1",
                "object": "block",
                "type": "paragraph",
                "archived": true
            })))
            .mount(&mock_server)
            .await;

        let client = NotionClient::new("test-token")
            .unwrap()
            .with_api_url(&format!("{}/v1", mock_server.uri()));

        let block = client.delete_block("block-1").await.unwrap();
        assert_eq!(block["id"], "block-1");
        assert_eq!(block["archived"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_database_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/databases/missing"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "object": "error",
                "status": 404,
                "code": "object_not_found",
                "message": "Could not find database"
            })))
            .mount(&mock_server)
            .await;

        let client = NotionClient::new("test-token")
            .unwrap()
            .with_api_url(&format!("{}/v1", mock_server.uri()))
            .with_retry_config(0);

        let result = client.get_database("missing").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), NotionError::NotFound { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_block_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/blocks/missing"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "object": "error",
                "status": 404,
                "code": "object_not_found",
                "message": "Could not find block"
            })))
            .mount(&mock_server)
            .await;

        let client = NotionClient::new("test-token")
            .unwrap()
            .with_api_url(&format!("{}/v1", mock_server.uri()))
            .with_retry_config(0);

        let result = client.get_block("missing").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), NotionError::NotFound { .. }));
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

    // ─── URL injection prevention tests ──────────────────────────────

    #[test]
    fn test_validate_notion_id_valid_uuid() {
        assert!(validate_notion_id("a1b2c3d4-e5f6-7890-abcd-ef1234567890", "page_id").is_ok());
    }

    #[test]
    fn test_validate_notion_id_no_hyphens() {
        assert!(validate_notion_id("a1b2c3d4e5f67890abcdef1234567890", "page_id").is_ok());
    }

    #[test]
    fn test_validate_notion_id_short_name() {
        // Notion test IDs like "page-1", "block-1", "db-1" are valid
        assert!(validate_notion_id("page-1", "page_id").is_ok());
        assert!(validate_notion_id("block-1", "block_id").is_ok());
        assert!(validate_notion_id("db-1", "database_id").is_ok());
    }

    #[test]
    fn test_validate_notion_id_rejects_empty() {
        let result = validate_notion_id("", "page_id");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            NotionError::Validation { .. }
        ));
    }

    #[test]
    fn test_validate_notion_id_rejects_slashes() {
        let result = validate_notion_id("../../etc/passwd", "block_id");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            NotionError::Validation { .. }
        ));
    }

    #[test]
    fn test_validate_notion_id_rejects_query_injection() {
        let result = validate_notion_id("abc?admin=true", "block_id");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_notion_id_rejects_spaces() {
        let result = validate_notion_id("abc def", "block_id");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_notion_id_rejects_hash_fragment() {
        let result = validate_notion_id("abc#fragment", "block_id");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_notion_id_rejects_ampersand() {
        let result = validate_notion_id("abc&other=1", "block_id");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_notion_id_rejects_percent_encoding() {
        let result = validate_notion_id("abc%2F..%2Fetc", "page_id");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_notion_id_rejects_backslash() {
        let result = validate_notion_id("abc\\def", "page_id");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_notion_id_rejects_null_byte() {
        let result = validate_notion_id("abc\0def", "page_id");
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_path_segment_safe_chars() {
        let encoded = encode_path_segment("a1b2c3d4-e5f6-7890");
        assert_eq!(encoded, "a1b2c3d4-e5f6-7890");
    }

    #[test]
    fn test_encode_path_segment_special_chars() {
        let encoded = encode_path_segment("abc?foo=bar&x=1");
        assert!(encoded.contains("%3F"));
        assert!(encoded.contains("%3D"));
        assert!(encoded.contains("%26"));
    }

    #[test]
    fn test_encode_path_segment_slash() {
        let encoded = encode_path_segment("../../etc");
        assert!(encoded.contains("%2F"));
        assert!(!encoded.contains('/'));
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_page_rejects_path_traversal() {
        let client = NotionClient::new("test-token")
            .unwrap()
            .with_api_url("http://localhost:1234/v1");

        let result = client.get_page("../../admin").await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            NotionError::Validation { .. }
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_block_rejects_query_injection() {
        let client = NotionClient::new("test-token")
            .unwrap()
            .with_api_url("http://localhost:1234/v1");

        let result = client.get_block("abc?admin=true").await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            NotionError::Validation { .. }
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_comments_rejects_injection() {
        let client = NotionClient::new("test-token")
            .unwrap()
            .with_api_url("http://localhost:1234/v1");

        let result = client.list_comments("abc&admin=true").await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            NotionError::Validation { .. }
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_query_database_rejects_empty_id() {
        let client = NotionClient::new("test-token")
            .unwrap()
            .with_api_url("http://localhost:1234/v1");

        let result = client.query_database("", None, None).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            NotionError::Validation { .. }
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
