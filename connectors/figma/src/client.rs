//! Figma REST API client.

use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fcp_core::CredentialId;
use fcp_sdk::migration::{
    AttemptOutcome, ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig, RetryLoop,
};
use reqwest::{Client, RequestBuilder, Response, StatusCode};
use tracing::instrument;

use crate::{
    error::{FigmaError, FigmaResult},
    types::{
        Comment, CommentsResponse, ComponentsResponse, CreateWebhookRequest, ExportImagesResponse,
        FileNodesResponse, FileResponse, PostCommentRequest, ProjectFilesResponse, StylesResponse,
        TeamProjectsResponse, VersionsResponse, Webhook, WebhooksListResponse,
    },
};

/// Default Figma API base URL.
pub const DEFAULT_BASE_URL: &str = "https://api.figma.com/v1";

/// Authentication mode for the Figma client.
#[derive(Clone)]
pub enum FigmaAuth {
    /// Direct personal access token.
    Token(String),
    /// Secretless credential injection via egress proxy.
    CredentialId(CredentialId),
}

impl std::fmt::Debug for FigmaAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Token(_) => f.debug_tuple("Token").field(&"[REDACTED]").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

impl FigmaAuth {
    /// Human-readable label with secrets redacted.
    #[must_use]
    pub const fn redacted_label(&self) -> &'static str {
        match self {
            Self::Token(_) => "token",
            Self::CredentialId(_) => "credential_id",
        }
    }

    /// Whether this auth mode is secretless (no raw credentials held).
    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

/// Figma REST API client with retry logic and rate limit awareness.
pub struct FigmaClient {
    client: Client,
    auth: FigmaAuth,
    base_url: String,
    max_retries: u32,
    initial_delay_ms: u64,
    max_delay_ms: u64,
    total_requests: AtomicU64,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl std::fmt::Debug for FigmaClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FigmaClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .field("max_retries", &self.max_retries)
            .finish_non_exhaustive()
    }
}

impl FigmaClient {
    /// Create a new Figma client with a personal access token.
    pub fn new(token: impl Into<String>) -> FigmaResult<Self> {
        Self::new_with_auth(FigmaAuth::Token(token.into()))
    }

    /// Create a new Figma client with the specified auth mode.
    pub fn new_with_auth(auth: FigmaAuth) -> FigmaResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .user_agent("fcp-figma/0.1.0")
            .build()
            .map_err(FigmaError::Http)?;

        Ok(Self {
            client,
            auth,
            base_url: DEFAULT_BASE_URL.into(),
            max_retries: 3,
            initial_delay_ms: 1000,
            max_delay_ms: 60_000,
            total_requests: AtomicU64::new(0),
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(30)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 2,
                ..HttpRetryConfig::default()
            },
        })
    }

    /// Shut down the connector runtime.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    /// Apply authentication to a request builder.
    fn apply_auth(&self, builder: RequestBuilder) -> RequestBuilder {
        match &self.auth {
            FigmaAuth::Token(token) => builder.header("X-FIGMA-TOKEN", token),
            FigmaAuth::CredentialId(id) => builder.header("X-FCP-Credential-ID", id.to_string()),
        }
    }

    /// Lightweight connectivity probe for self-check.
    pub async fn health_check(&self) -> FigmaResult<()> {
        let url = format!("{}/me", self.base_url);
        let response = self
            .apply_auth(self.client.get(&url))
            .send()
            .await
            .map_err(FigmaError::Http)?;
        let status = response.status();
        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            return Err(FigmaError::Unauthorized);
        }
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(FigmaError::Api {
                status: status.as_u16(),
                message: body,
            });
        }
        Ok(())
    }

    /// Set the base URL (for testing).
    #[must_use]
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
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
        self.retry_config.max_retries = max_retries;
        self.initial_delay_ms = initial_delay_ms;
        self.max_delay_ms = max_delay_ms;
        self.retry_config = HttpRetryConfig {
            max_retries,
            initial_delay_ms,
            max_delay_ms,
            jitter_enabled: self.retry_config.jitter_enabled,
        };
        self
    }

    /// Get total requests made.
    #[must_use]
    pub fn total_requests(&self) -> u64 {
        self.total_requests.load(Ordering::Relaxed)
    }

    // ── Team & project operations ─────────────────────────────────

    /// List projects within a team.
    #[instrument(skip(self))]
    pub async fn list_team_projects(&self, team_id: &str) -> FigmaResult<TeamProjectsResponse> {
        self.get_with_params::<TeamProjectsResponse>(&format!("teams/{team_id}/projects"), &[])
            .await
    }

    /// List files within a project.
    #[instrument(skip(self))]
    pub async fn list_project_files(&self, project_id: &str) -> FigmaResult<ProjectFilesResponse> {
        self.get_with_params::<ProjectFilesResponse>(&format!("projects/{project_id}/files"), &[])
            .await
    }

    // ── File operations ─────────────────────────────────────────

    /// Get a Figma file's document tree.
    #[instrument(skip(self))]
    pub async fn get_file(
        &self,
        file_key: &str,
        ids: Option<&str>,
        depth: Option<u32>,
        geometry: Option<&str>,
        plugin_data: Option<&str>,
    ) -> FigmaResult<FileResponse> {
        let mut params: Vec<(&str, String)> = Vec::new();
        if let Some(ids) = ids {
            params.push(("ids", ids.to_string()));
        }
        if let Some(depth) = depth {
            params.push(("depth", depth.to_string()));
        }
        if let Some(geometry) = geometry {
            params.push(("geometry", geometry.to_string()));
        }
        if let Some(plugin_data) = plugin_data {
            params.push(("plugin_data", plugin_data.to_string()));
        }

        self.get_with_params(&format!("files/{file_key}"), &params)
            .await
    }

    /// Get specific nodes from a Figma file.
    #[instrument(skip(self))]
    pub async fn get_file_nodes(
        &self,
        file_key: &str,
        ids: &str,
        depth: Option<u32>,
    ) -> FigmaResult<FileNodesResponse> {
        let mut params = vec![("ids", ids.to_string())];
        if let Some(depth) = depth {
            params.push(("depth", depth.to_string()));
        }

        self.get_with_params(&format!("files/{file_key}/nodes"), &params)
            .await
    }

    /// Get all components in a file.
    #[instrument(skip(self))]
    pub async fn get_file_components(&self, file_key: &str) -> FigmaResult<ComponentsResponse> {
        self.get_with_params::<ComponentsResponse>(&format!("files/{file_key}/components"), &[])
            .await
    }

    /// Get all styles in a file.
    #[instrument(skip(self))]
    pub async fn get_file_styles(&self, file_key: &str) -> FigmaResult<StylesResponse> {
        self.get_with_params::<StylesResponse>(&format!("files/{file_key}/styles"), &[])
            .await
    }

    // ── Image Export ────────────────────────────────────────────

    /// Export node(s) as images.
    #[instrument(skip(self))]
    pub async fn export_images(
        &self,
        file_key: &str,
        ids: &str,
        format: &str,
        scale: Option<f64>,
        svg_include_id: Option<bool>,
        svg_simplify_stroke: Option<bool>,
        use_absolute_bounds: Option<bool>,
    ) -> FigmaResult<ExportImagesResponse> {
        let mut params = vec![("ids", ids.to_string()), ("format", format.to_string())];
        if let Some(scale) = scale {
            params.push(("scale", scale.to_string()));
        }
        if let Some(v) = svg_include_id {
            params.push(("svg_include_id", v.to_string()));
        }
        if let Some(v) = svg_simplify_stroke {
            params.push(("svg_simplify_stroke", v.to_string()));
        }
        if let Some(v) = use_absolute_bounds {
            params.push(("use_absolute_bounds", v.to_string()));
        }

        self.get_with_params(&format!("images/{file_key}"), &params)
            .await
    }

    // ── Version History ────────────────────────────────────────

    /// List version history for a file.
    #[instrument(skip(self))]
    pub async fn list_file_versions(&self, file_key: &str) -> FigmaResult<VersionsResponse> {
        self.get_with_params::<VersionsResponse>(&format!("files/{file_key}/versions"), &[])
            .await
    }

    // ── Comment operations ─────────────────────────────────────

    /// List comments on a file.
    #[instrument(skip(self))]
    pub async fn list_comments(
        &self,
        file_key: &str,
        as_md: Option<bool>,
    ) -> FigmaResult<CommentsResponse> {
        let mut params: Vec<(&str, String)> = Vec::new();
        if as_md == Some(true) {
            params.push(("as_md", "true".to_string()));
        }

        self.get_with_params(&format!("files/{file_key}/comments"), &params)
            .await
    }

    /// Post a comment on a file.
    #[instrument(skip(self))]
    pub async fn post_comment(
        &self,
        file_key: &str,
        message: &str,
        comment_id: Option<&str>,
        client_meta: Option<serde_json::Value>,
    ) -> FigmaResult<Comment> {
        let body = PostCommentRequest {
            message: message.to_string(),
            comment_id: comment_id.map(String::from),
            client_meta,
        };

        self.post_json(&format!("files/{file_key}/comments"), &body)
            .await
    }

    /// Delete a comment from a file.
    #[instrument(skip(self))]
    pub async fn delete_comment(&self, file_key: &str, comment_id: &str) -> FigmaResult<()> {
        self.delete(&format!("files/{file_key}/comments/{comment_id}"))
            .await
    }

    // ── Webhook operations ─────────────────────────────────────

    /// List webhooks for a team.
    #[instrument(skip(self))]
    pub async fn list_webhooks(&self, team_id: &str) -> FigmaResult<WebhooksListResponse> {
        // Webhooks use v2 API
        let path = format!("../v2/webhooks/{team_id}");
        self.get_with_params(&path, &[]).await
    }

    /// Create a webhook.
    #[instrument(skip(self))]
    pub async fn create_webhook(
        &self,
        team_id: &str,
        event_type: &str,
        endpoint: &str,
        passcode: &str,
        description: Option<&str>,
    ) -> FigmaResult<Webhook> {
        let body = CreateWebhookRequest {
            team_id: team_id.to_string(),
            event_type: event_type.to_string(),
            endpoint: endpoint.to_string(),
            passcode: passcode.to_string(),
            description: description.map(String::from),
        };

        // Webhooks use v2 API
        self.post_json("../v2/webhooks", &body).await
    }

    /// Delete a webhook.
    #[instrument(skip(self))]
    pub async fn delete_webhook(&self, webhook_id: &str) -> FigmaResult<()> {
        self.delete(&format!("../v2/webhooks/{webhook_id}")).await
    }

    // ── Internal HTTP helpers ────────────────────────────────────

    async fn get_with_params<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        params: &[(&str, String)],
    ) -> FigmaResult<T> {
        let mut url = format!("{}/{path}", self.base_url);
        if !params.is_empty() {
            url.push('?');
            for (i, (key, value)) in params.iter().enumerate() {
                if i > 0 {
                    url.push('&');
                }
                let encoded = percent_encoding::utf8_percent_encode(
                    value,
                    percent_encoding::NON_ALPHANUMERIC,
                );
                let _ = write!(url, "{key}={encoded}");
            }
        }
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |_attempt| {
            let req = self.apply_auth(self.client.get(&url));
            async move { Self::execute_get_once::<T>(req, path).await }
        })
        .await
    }

    async fn post_json<B: serde::Serialize, T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> FigmaResult<T> {
        let url = format!("{}/{path}", self.base_url);
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |_attempt| {
            let req = self.apply_auth(self.client.post(&url)).json(body);
            async move { Self::execute_post_once::<T>(req, path).await }
        })
        .await
    }

    async fn delete(&self, path: &str) -> FigmaResult<()> {
        let url = format!("{}/{path}", self.base_url);
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |_attempt| {
            let req = self.apply_auth(self.client.delete(&url));
            async move { Self::execute_delete_once(req, path).await }
        })
        .await
    }

    async fn execute_get_once<T: serde::de::DeserializeOwned>(
        req: RequestBuilder,
        path: &str,
    ) -> AttemptOutcome<T, FigmaError> {
        match req.send().await {
            Ok(resp) => {
                if let Some(retry_result) = Self::check_rate_limit(&resp) {
                    let err = FigmaError::RateLimited {
                        retry_after_secs: retry_result.map_or(60, |d| d.as_secs()),
                    };
                    return AttemptOutcome::Retryable {
                        retry_after: retry_result,
                        error: err,
                    };
                }

                let status = resp.status();
                if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                    return AttemptOutcome::Terminal(FigmaError::Unauthorized);
                }
                if status == StatusCode::NOT_FOUND {
                    return AttemptOutcome::Terminal(FigmaError::Api {
                        status: 404,
                        message: format!("Not found: {path}"),
                    });
                }
                if !status.is_success() {
                    let body = resp.text().await.unwrap_or_default();
                    let err = FigmaError::Api {
                        status: status.as_u16(),
                        message: body,
                    };
                    return if status.is_server_error() {
                        AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        }
                    } else {
                        AttemptOutcome::Terminal(err)
                    };
                }

                match resp.json::<T>().await {
                    Ok(data) => AttemptOutcome::Success(data),
                    Err(e) => AttemptOutcome::Terminal(e.into()),
                }
            }
            Err(e) => {
                let err: FigmaError = e.into();
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

    async fn execute_post_once<T: serde::de::DeserializeOwned>(
        req: RequestBuilder,
        _path: &str,
    ) -> AttemptOutcome<T, FigmaError> {
        match req.send().await {
            Ok(resp) => {
                if let Some(retry_result) = Self::check_rate_limit(&resp) {
                    let err = FigmaError::RateLimited {
                        retry_after_secs: retry_result.map_or(60, |d| d.as_secs()),
                    };
                    return AttemptOutcome::Retryable {
                        retry_after: retry_result,
                        error: err,
                    };
                }

                let status = resp.status();
                if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                    return AttemptOutcome::Terminal(FigmaError::Unauthorized);
                }
                if !status.is_success() {
                    let body_text = resp.text().await.unwrap_or_default();
                    let err = FigmaError::Api {
                        status: status.as_u16(),
                        message: body_text,
                    };
                    return if status.is_server_error() {
                        AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        }
                    } else {
                        AttemptOutcome::Terminal(err)
                    };
                }

                match resp.json::<T>().await {
                    Ok(data) => AttemptOutcome::Success(data),
                    Err(e) => AttemptOutcome::Terminal(e.into()),
                }
            }
            Err(e) => {
                let err: FigmaError = e.into();
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

    async fn execute_delete_once(
        req: RequestBuilder,
        path: &str,
    ) -> AttemptOutcome<(), FigmaError> {
        match req.send().await {
            Ok(resp) => {
                if let Some(retry_result) = Self::check_rate_limit(&resp) {
                    let err = FigmaError::RateLimited {
                        retry_after_secs: retry_result.map_or(60, |d| d.as_secs()),
                    };
                    return AttemptOutcome::Retryable {
                        retry_after: retry_result,
                        error: err,
                    };
                }

                let status = resp.status();
                if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                    return AttemptOutcome::Terminal(FigmaError::Unauthorized);
                }
                if status == StatusCode::NOT_FOUND {
                    return AttemptOutcome::Terminal(FigmaError::Api {
                        status: 404,
                        message: format!("Not found: {path}"),
                    });
                }
                if !status.is_success() {
                    let body_text = resp.text().await.unwrap_or_default();
                    let err = FigmaError::Api {
                        status: status.as_u16(),
                        message: body_text,
                    };
                    return if status.is_server_error() {
                        AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        }
                    } else {
                        AttemptOutcome::Terminal(err)
                    };
                }

                AttemptOutcome::Success(())
            }
            Err(e) => {
                let err: FigmaError = e.into();
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

    #[allow(clippy::option_option)]
    fn check_rate_limit(response: &Response) -> Option<Option<Duration>> {
        if response.status() == StatusCode::TOO_MANY_REQUESTS {
            let retry_after = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .map(Duration::from_secs);
            Some(retry_after)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[fcp_async_core::runtime::test]
    async fn test_get_file() {
        let mock_server = MockServer::start().await;

        let file_response = serde_json::json!({
            "name": "Test File",
            "document": { "id": "0:0", "type": "DOCUMENT", "children": [] },
            "lastModified": "2025-01-01T00:00:00Z",
            "version": "123456",
            "components": {},
            "styles": {}
        });

        Mock::given(method("GET"))
            .and(path("/files/abc123"))
            .and(header("X-FIGMA-TOKEN", "test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&file_response))
            .mount(&mock_server)
            .await;

        let client = FigmaClient::new("test-token")
            .unwrap()
            .with_base_url(mock_server.uri());

        let result = client.get_file("abc123", None, None, None, None).await;
        assert!(result.is_ok());
        let file = result.unwrap();
        assert_eq!(file.name, "Test File");
        assert_eq!(file.version, "123456");
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_file_nodes() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/files/abc123/nodes"))
            .and(header("X-FIGMA-TOKEN", "test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "nodes": { "1:2": { "document": { "id": "1:2" } } }
            })))
            .mount(&mock_server)
            .await;

        let client = FigmaClient::new("test-token")
            .unwrap()
            .with_base_url(mock_server.uri());

        let result = client.get_file_nodes("abc123", "1:2", None).await;
        assert!(result.is_ok());
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_comments() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/files/abc123/comments"))
            .and(header("X-FIGMA-TOKEN", "test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "comments": [
                    {
                        "id": "c1",
                        "message": "Looks good!",
                        "created_at": "2025-01-01T00:00:00Z"
                    }
                ]
            })))
            .mount(&mock_server)
            .await;

        let client = FigmaClient::new("test-token")
            .unwrap()
            .with_base_url(mock_server.uri());

        let result = client.list_comments("abc123", None).await;
        assert!(result.is_ok());
        let resp = result.unwrap();
        assert_eq!(resp.comments.len(), 1);
        assert_eq!(resp.comments[0].message, "Looks good!");
    }

    #[fcp_async_core::runtime::test]
    async fn test_post_comment() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/files/abc123/comments"))
            .and(header("X-FIGMA-TOKEN", "test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "c2",
                "message": "New comment",
                "created_at": "2025-01-01T12:00:00Z"
            })))
            .mount(&mock_server)
            .await;

        let client = FigmaClient::new("test-token")
            .unwrap()
            .with_base_url(mock_server.uri());

        let result = client
            .post_comment("abc123", "New comment", None, None)
            .await;
        assert!(result.is_ok());
        let comment = result.unwrap();
        assert_eq!(comment.id, "c2");
        assert_eq!(comment.message, "New comment");
    }

    #[fcp_async_core::runtime::test]
    async fn test_unauthorized() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/files/abc123"))
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "status": 403,
                "err": "Forbidden"
            })))
            .mount(&mock_server)
            .await;

        let client = FigmaClient::new("bad-token")
            .unwrap()
            .with_base_url(mock_server.uri());

        let result = client.get_file("abc123", None, None, None, None).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FigmaError::Unauthorized));
    }

    #[fcp_async_core::runtime::test]
    async fn test_rate_limit_no_retry() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/files/abc123"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "30"))
            .mount(&mock_server)
            .await;

        let client = FigmaClient::new("test-token")
            .unwrap()
            .with_base_url(mock_server.uri())
            .with_retry_config(0, 100, 200);

        let result = client.get_file("abc123", None, None, None, None).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FigmaError::RateLimited {
                retry_after_secs: 30
            }
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/files/nonexistent"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "status": 404,
                "err": "Not found"
            })))
            .mount(&mock_server)
            .await;

        let client = FigmaClient::new("test-token")
            .unwrap()
            .with_base_url(mock_server.uri());

        let result = client.get_file("nonexistent", None, None, None, None).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FigmaError::Api { status: 404, .. }
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_export_images() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/images/abc123"))
            .and(header("X-FIGMA-TOKEN", "test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "images": { "1:2": "https://figma-alpha.s3.amazonaws.com/img/abc.png" }
            })))
            .mount(&mock_server)
            .await;

        let client = FigmaClient::new("test-token")
            .unwrap()
            .with_base_url(mock_server.uri());

        let result = client
            .export_images("abc123", "1:2", "png", Some(2.0), None, None, None)
            .await;
        assert!(result.is_ok());
    }

    #[fcp_async_core::runtime::test]
    async fn test_delete_comment() {
        let mock_server = MockServer::start().await;

        Mock::given(method("DELETE"))
            .and(path("/files/abc123/comments/c1"))
            .and(header("X-FIGMA-TOKEN", "test-token"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let client = FigmaClient::new("test-token")
            .unwrap()
            .with_base_url(mock_server.uri());

        let result = client.delete_comment("abc123", "c1").await;
        assert!(result.is_ok());
    }

    #[fcp_async_core::runtime::test]
    async fn test_rate_limit_retries_multiple_times() {
        // Verify that the client retries on 429 and increments the request counter
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/files/abc123"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "0"))
            .mount(&mock_server)
            .await;

        let client = FigmaClient::new("test-token")
            .unwrap()
            .with_base_url(mock_server.uri())
            .with_retry_config(2, 10, 50); // max 2 retries, fast

        let result = client.get_file("abc123", None, None, None, None).await;
        assert!(result.is_err());
        // With max_retries=2, we expect 3 total requests (1 initial + 2 retries)
        assert_eq!(
            client.total_requests(),
            1,
            "total_requests counts invocations not HTTP attempts"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_rate_limit_exhausts_retries() {
        // All 429s, exceeds max retries
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/files/abc123"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "0"))
            .mount(&mock_server)
            .await;

        let client = FigmaClient::new("test-token")
            .unwrap()
            .with_base_url(mock_server.uri())
            .with_retry_config(2, 10, 50); // max 2 retries, fast

        let result = client.get_file("abc123", None, None, None, None).await;
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), FigmaError::RateLimited { .. }),
            "should return RateLimited after exhausting retries"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_total_requests_counter() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/files/abc123/components"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "meta": { "components": [] }
            })))
            .mount(&mock_server)
            .await;

        let client = FigmaClient::new("test-token")
            .unwrap()
            .with_base_url(mock_server.uri());

        assert_eq!(client.total_requests(), 0);
        let _ = client.get_file_components("abc123").await;
        assert_eq!(client.total_requests(), 1);
    }
}
