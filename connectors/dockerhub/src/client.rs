use std::time::Duration;

use reqwest::{Client, RequestBuilder};
use tracing::debug;

use fcp_sdk::migration::{AttemptOutcome, ConnectorRuntime, HttpRetryConfig, RetryLoop};

use crate::error::{DockerHubError, DockerHubResult};
use crate::types::*;

/// Validate a user-supplied path segment to prevent URL path injection.
fn sanitize_path_segment<'a>(value: &'a str, field: &str) -> DockerHubResult<&'a str> {
    if value.trim().is_empty() {
        return Err(DockerHubError::InvalidInput(format!("{field} must not be empty")));
    }
    let lower = value.to_ascii_lowercase();
    if value.contains('/')
        || value.contains('\\')
        || value.contains("..")
        || lower.contains("%2f")
        || lower.contains("%5c")
    {
        return Err(DockerHubError::InvalidInput(format!("{field} contains path traversal characters")));
    }
    Ok(value)
}

/// Docker Hub API client with retry support.
pub struct DockerHubClient {
    client: Client,
    base_url: String,
    auth: DockerHubAuth,
    /// JWT token obtained after login (for credentials-based auth).
    jwt_token: Option<String>,
    retry_config: HttpRetryConfig,
}

impl std::fmt::Debug for DockerHubClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DockerHubClient")
            .field("base_url", &self.base_url)
            .field("auth", &self.auth)
            .field("has_jwt", &self.jwt_token.is_some())
            .finish()
    }
}

impl DockerHubClient {
    pub async fn new(
        base_url: &str,
        auth: DockerHubAuth,
        retry_config: HttpRetryConfig,
    ) -> DockerHubResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(DockerHubError::Http)?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            auth,
            jwt_token: None,
            retry_config,
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn is_secretless(&self) -> bool {
        self.auth.is_secretless()
    }

    fn bearer_token(&self) -> Option<&str> {
        match &self.auth {
            DockerHubAuth::Token { access_token } if !access_token.is_empty() => {
                Some(access_token.as_str())
            }
            DockerHubAuth::Credentials { .. } => self.jwt_token.as_deref(),
            _ => None,
        }
    }

    // ── Login (for credentials-based auth) ──

    pub async fn login(&mut self, runtime: &ConnectorRuntime) -> DockerHubResult<()> {
        if let DockerHubAuth::Credentials { username, password } = &self.auth {
            let url = format!("{}/v2/users/login", self.base_url);
            let login_req = LoginRequest {
                username: username.clone(),
                password: password.clone(),
            };
            let ctx = runtime.request_context();
            let policy = self.retry_config.to_retry_policy();
            let body = serde_json::to_value(&login_req).unwrap_or_default();
            let base_url = self.base_url.clone();
            let client = self.client.clone();

            let resp: LoginResponse = RetryLoop::execute(&ctx, &policy, |attempt| {
                let url = url.clone();
                let client = client.clone();
                let body = body.clone();
                async move {
                    debug!(attempt, "Docker Hub login");
                    let req = client.post(&url).json(&body);
                    handle_response::<LoginResponse>(req, attempt).await
                }
            })
            .await?;

            self.jwt_token = Some(resp.token);
            let _ = base_url;
        }
        Ok(())
    }

    // ── Health check ──

    pub async fn health_check(&self, runtime: &ConnectorRuntime) -> DockerHubResult<User> {
        let url = format!("{}/v2/user", self.base_url);
        self.get_single(runtime, &url).await
    }

    // ── Repositories ──

    pub async fn list_repos(
        &self,
        runtime: &ConnectorRuntime,
        namespace: &str,
    ) -> DockerHubResult<Vec<Repository>> {
        let namespace = sanitize_path_segment(namespace, "namespace")?;
        let url = format!("{}/v2/repositories/{namespace}/", self.base_url);
        self.get_paginated(runtime, &url).await
    }

    pub async fn get_repo(
        &self,
        runtime: &ConnectorRuntime,
        namespace: &str,
        name: &str,
    ) -> DockerHubResult<Repository> {
        let namespace = sanitize_path_segment(namespace, "namespace")?;
        let name = sanitize_path_segment(name, "repository")?;
        let url = format!("{}/v2/repositories/{namespace}/{name}/", self.base_url);
        self.get_single(runtime, &url).await
    }

    pub async fn create_repo(
        &self,
        runtime: &ConnectorRuntime,
        req: &CreateRepositoryRequest,
    ) -> DockerHubResult<Repository> {
        let namespace = sanitize_path_segment(&req.namespace, "namespace")?;
        let url = format!("{}/v2/repositories/{namespace}/", self.base_url);
        let body = serde_json::to_value(req).unwrap_or_default();
        self.post_json(runtime, &url, &body).await
    }

    pub async fn delete_repo(
        &self,
        runtime: &ConnectorRuntime,
        namespace: &str,
        name: &str,
    ) -> DockerHubResult<serde_json::Value> {
        let namespace = sanitize_path_segment(namespace, "namespace")?;
        let name = sanitize_path_segment(name, "repository")?;
        let url = format!("{}/v2/repositories/{namespace}/{name}/", self.base_url);
        self.delete(runtime, &url).await
    }

    // ── Tags ──

    pub async fn list_tags(
        &self,
        runtime: &ConnectorRuntime,
        namespace: &str,
        name: &str,
    ) -> DockerHubResult<Vec<Tag>> {
        let namespace = sanitize_path_segment(namespace, "namespace")?;
        let name = sanitize_path_segment(name, "repository")?;
        let url = format!(
            "{}/v2/repositories/{namespace}/{name}/tags/",
            self.base_url
        );
        self.get_paginated(runtime, &url).await
    }

    pub async fn get_tag(
        &self,
        runtime: &ConnectorRuntime,
        namespace: &str,
        name: &str,
        tag: &str,
    ) -> DockerHubResult<Tag> {
        let namespace = sanitize_path_segment(namespace, "namespace")?;
        let name = sanitize_path_segment(name, "repository")?;
        let tag = sanitize_path_segment(tag, "tag")?;
        let url = format!(
            "{}/v2/repositories/{namespace}/{name}/tags/{tag}/",
            self.base_url
        );
        self.get_single(runtime, &url).await
    }

    pub async fn delete_tag(
        &self,
        runtime: &ConnectorRuntime,
        namespace: &str,
        name: &str,
        tag: &str,
    ) -> DockerHubResult<serde_json::Value> {
        let namespace = sanitize_path_segment(namespace, "namespace")?;
        let name = sanitize_path_segment(name, "repository")?;
        let tag = sanitize_path_segment(tag, "tag")?;
        let url = format!(
            "{}/v2/repositories/{namespace}/{name}/tags/{tag}/",
            self.base_url
        );
        self.delete(runtime, &url).await
    }

    // ── Organizations ──

    pub async fn list_orgs(&self, runtime: &ConnectorRuntime) -> DockerHubResult<Vec<Organization>> {
        let url = format!("{}/v2/user/orgs/", self.base_url);
        self.get_paginated(runtime, &url).await
    }

    // ── Generic HTTP helpers ──

    async fn get_paginated<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
    ) -> DockerHubResult<Vec<T>> {
        let url = url.to_string();
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let token = self.bearer_token().map(String::from);

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let token = token.clone();
            async move {
                debug!(attempt, url = %url, "GET paginated");
                let req = authenticate_request(client.get(&url), token.as_deref());
                handle_paginated_response::<T>(req, attempt).await
            }
        })
        .await
    }

    async fn get_single<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
    ) -> DockerHubResult<T> {
        let url = url.to_string();
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let token = self.bearer_token().map(String::from);

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let token = token.clone();
            async move {
                debug!(attempt, url = %url, "GET single");
                let req = authenticate_request(client.get(&url), token.as_deref());
                handle_response::<T>(req, attempt).await
            }
        })
        .await
    }

    async fn post_json<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
        body: &serde_json::Value,
    ) -> DockerHubResult<T> {
        let url = url.to_string();
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let body = body.clone();
        let token = self.bearer_token().map(String::from);

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let token = token.clone();
            let body = body.clone();
            async move {
                debug!(attempt, url = %url, "POST");
                let req = authenticate_request(client.post(&url), token.as_deref()).json(&body);
                handle_response::<T>(req, attempt).await
            }
        })
        .await
    }

    async fn delete<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
    ) -> DockerHubResult<T> {
        let url = url.to_string();
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let token = self.bearer_token().map(String::from);

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let token = token.clone();
            async move {
                debug!(attempt, url = %url, "DELETE");
                let req = authenticate_request(client.delete(&url), token.as_deref());
                handle_response::<T>(req, attempt).await
            }
        })
        .await
    }
}

// ── Free functions ──

fn authenticate_request(req: RequestBuilder, token: Option<&str>) -> RequestBuilder {
    match token {
        Some(t) if !t.is_empty() => req.bearer_auth(t),
        _ => req,
    }
}

async fn handle_response<T: serde::de::DeserializeOwned>(
    req: RequestBuilder,
    attempt: u32,
) -> AttemptOutcome<T, DockerHubError> {
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            return AttemptOutcome::Retryable {
                error: DockerHubError::Http(e),
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
            error: DockerHubError::RateLimited {
                retry_after_ms: retry_after
                    .unwrap_or(Duration::from_secs(30))
                    .as_millis() as u64,
            },
            retry_after,
        };
    }

    if status == 401 || status == 403 {
        return AttemptOutcome::Terminal(DockerHubError::Unauthorized(format!(
            "Authentication failed (HTTP {status})"
        )));
    }

    if status == 404 {
        return AttemptOutcome::Terminal(DockerHubError::NotFound(format!(
            "Resource not found (HTTP {status})"
        )));
    }

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        let err = DockerHubError::Api {
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
        Err(e) => return AttemptOutcome::Terminal(DockerHubError::Http(e)),
    };

    // Handle empty 204 responses
    if text.is_empty() || text.trim() == "null" {
        if let Ok(v) = serde_json::from_str::<T>("null") {
            return AttemptOutcome::Success(v);
        }
        if let Ok(v) = serde_json::from_str::<T>("{}") {
            return AttemptOutcome::Success(v);
        }
    }

    match serde_json::from_str::<T>(&text) {
        Ok(v) => AttemptOutcome::Success(v),
        Err(e) => {
            debug!(attempt, "Failed to parse response: {e}");
            AttemptOutcome::Terminal(DockerHubError::Json(e))
        }
    }
}

async fn handle_paginated_response<T: serde::de::DeserializeOwned>(
    req: RequestBuilder,
    attempt: u32,
) -> AttemptOutcome<Vec<T>, DockerHubError> {
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            return AttemptOutcome::Retryable {
                error: DockerHubError::Http(e),
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
            error: DockerHubError::RateLimited {
                retry_after_ms: retry_after
                    .unwrap_or(Duration::from_secs(30))
                    .as_millis() as u64,
            },
            retry_after,
        };
    }

    if status == 401 || status == 403 {
        return AttemptOutcome::Terminal(DockerHubError::Unauthorized(format!(
            "Authentication failed (HTTP {status})"
        )));
    }

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        let err = DockerHubError::Api {
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
        Err(e) => return AttemptOutcome::Terminal(DockerHubError::Http(e)),
    };

    // Docker Hub uses paginated responses with { count, results: [...] }
    if let Ok(paginated) = serde_json::from_str::<PaginatedResponse<T>>(&text) {
        return AttemptOutcome::Success(paginated.results);
    }

    // Fallback: try direct array
    match serde_json::from_str::<Vec<T>>(&text) {
        Ok(v) => AttemptOutcome::Success(v),
        Err(e) => {
            debug!(attempt, "Failed to parse paginated response: {e}");
            AttemptOutcome::Terminal(DockerHubError::Json(e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_debug_redacts_auth() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            DockerHubClient::new(
                "https://hub.docker.com",
                DockerHubAuth::Token {
                    access_token: "secret-token".into(),
                },
                HttpRetryConfig::default(),
            )
            .await
            .unwrap()
        })
        .unwrap();

        let debug = format!("{rt:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("secret-token"));
    }

    #[test]
    fn secretless_detection() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            DockerHubClient::new(
                "https://hub.docker.com",
                DockerHubAuth::Token {
                    access_token: String::new(),
                },
                HttpRetryConfig::default(),
            )
            .await
            .unwrap()
        })
        .unwrap();
        assert!(rt.is_secretless());

        let rt2 = fcp_async_core::runtime::block_on_sync(async {
            DockerHubClient::new(
                "https://hub.docker.com",
                DockerHubAuth::Token {
                    access_token: "token".into(),
                },
                HttpRetryConfig::default(),
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
            DockerHubClient::new(
                "https://hub.docker.com/",
                DockerHubAuth::Token {
                    access_token: "t".into(),
                },
                HttpRetryConfig::default(),
            )
            .await
            .unwrap()
        })
        .unwrap();
        assert!(!rt.base_url().ends_with('/'));
    }

    #[test]
    fn bearer_token_from_access_token() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            DockerHubClient::new(
                "https://hub.docker.com",
                DockerHubAuth::Token {
                    access_token: "my-pat".into(),
                },
                HttpRetryConfig::default(),
            )
            .await
            .unwrap()
        })
        .unwrap();
        assert_eq!(rt.bearer_token(), Some("my-pat"));
    }

    #[test]
    fn sanitize_path_segment_rejects_traversal() {
        assert!(sanitize_path_segment("../admin", "namespace").is_err());
        assert!(sanitize_path_segment("foo/bar", "namespace").is_err());
        assert!(sanitize_path_segment("foo\\bar", "namespace").is_err());
        assert!(sanitize_path_segment("foo%2fbar", "namespace").is_err());
        assert!(sanitize_path_segment("foo%5Cbar", "namespace").is_err());
        assert!(sanitize_path_segment("", "namespace").is_err());
        assert!(sanitize_path_segment("  ", "namespace").is_err());
    }

    #[test]
    fn sanitize_path_segment_accepts_valid() {
        assert_eq!(sanitize_path_segment("myuser", "namespace").unwrap(), "myuser");
        assert_eq!(sanitize_path_segment("my-org", "namespace").unwrap(), "my-org");
    }

    #[test]
    fn bearer_token_none_when_empty() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            DockerHubClient::new(
                "https://hub.docker.com",
                DockerHubAuth::Token {
                    access_token: String::new(),
                },
                HttpRetryConfig::default(),
            )
            .await
            .unwrap()
        })
        .unwrap();
        assert!(rt.bearer_token().is_none());
    }
}
