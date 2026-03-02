//! GitHub API client.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use fcp_async_core::time::sleep;
use fcp_core::CredentialId;
use reqwest::{Client, RequestBuilder, Response, StatusCode};
use tracing::{debug, instrument, warn};

use crate::{
    error::{GitHubError, GitHubResult},
    types::{
        ApiErrorResponse, CodeSearchItem, CreateIssueRequest, CreatePullRequestRequest,
        FileContent, Issue, MergePullRequestRequest, MergeResult, PullRequest, Repository,
        SearchResults, WorkflowsResponse,
    },
};

/// Default API base URL.
pub const DEFAULT_BASE_URL: &str = "https://api.github.com";

/// Authentication mode for the GitHub client.
#[derive(Clone)]
pub enum GitHubAuth {
    /// Direct credentials: personal access token or app token (Bearer auth).
    Token(String),
    /// Secretless credential injection via egress proxy.
    CredentialId(CredentialId),
}

impl std::fmt::Debug for GitHubAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Token(_) => f.debug_tuple("Token").field(&"[REDACTED]").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

impl GitHubAuth {
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

/// GitHub API client with retry logic and rate limit awareness.
pub struct GitHubClient {
    client: Client,
    auth: GitHubAuth,
    base_url: String,
    max_retries: u32,
    initial_delay_ms: u64,
    max_delay_ms: u64,
    total_requests: AtomicU64,
}

impl std::fmt::Debug for GitHubClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitHubClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .field("max_retries", &self.max_retries)
            .finish_non_exhaustive()
    }
}

impl GitHubClient {
    /// Create a new GitHub client with a personal access token or app token.
    ///
    /// # Errors
    /// Returns [`GitHubError`] if the HTTP client cannot be constructed.
    pub fn new(token: impl Into<String>) -> GitHubResult<Self> {
        Self::new_with_auth(GitHubAuth::Token(token.into()))
    }

    /// Create a new GitHub client with the given auth mode.
    ///
    /// # Errors
    /// Returns [`GitHubError`] if the HTTP client cannot be constructed.
    pub fn new_with_auth(auth: GitHubAuth) -> GitHubResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-github/0.1.0")
            .build()
            .map_err(GitHubError::Http)?;

        Ok(Self {
            client,
            auth,
            base_url: DEFAULT_BASE_URL.into(),
            max_retries: 3,
            initial_delay_ms: 1000,
            max_delay_ms: 60_000,
            total_requests: AtomicU64::new(0),
        })
    }

    /// Apply auth headers to a request builder.
    fn apply_auth(&self, builder: RequestBuilder) -> RequestBuilder {
        match &self.auth {
            GitHubAuth::Token(token) => builder.header("Authorization", format!("Bearer {token}")),
            GitHubAuth::CredentialId(id) => builder.header("X-FCP-Credential-ID", id.to_string()),
        }
    }

    /// Perform a health check by fetching the authenticated user.
    pub async fn health_check(&self) -> GitHubResult<serde_json::Value> {
        self.get("/user").await
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
        self.max_retries = max_retries;
        self.initial_delay_ms = initial_delay_ms;
        self.max_delay_ms = max_delay_ms;
        self
    }

    /// Get total requests made.
    #[must_use]
    pub fn total_requests(&self) -> u64 {
        self.total_requests.load(Ordering::Relaxed)
    }

    // ── Issue operations ──────────────────────────────────────────

    /// Create an issue.
    ///
    /// # Errors
    /// Returns [`GitHubError`] if the API request fails.
    #[instrument(skip(self, req))]
    pub async fn create_issue(
        &self,
        owner: &str,
        repo: &str,
        req: &CreateIssueRequest,
    ) -> GitHubResult<Issue> {
        self.post(&format!("/repos/{owner}/{repo}/issues"), req)
            .await
    }

    /// Get a single issue.
    ///
    /// # Errors
    /// Returns [`GitHubError`] if the API request fails.
    #[instrument(skip(self))]
    pub async fn get_issue(
        &self,
        owner: &str,
        repo: &str,
        issue_number: u32,
    ) -> GitHubResult<Issue> {
        self.get(&format!("/repos/{owner}/{repo}/issues/{issue_number}"))
            .await
    }

    /// Search issues and pull requests.
    ///
    /// # Errors
    /// Returns [`GitHubError`] if the API request fails.
    #[instrument(skip(self))]
    pub async fn search_issues(&self, query: &str) -> GitHubResult<SearchResults<Issue>> {
        let encoded = urlencoding::encode(query);
        self.get(&format!("/search/issues?q={encoded}")).await
    }

    // ── Pull Request operations ───────────────────────────────────

    /// Create a pull request.
    ///
    /// # Errors
    /// Returns [`GitHubError`] if the API request fails.
    #[instrument(skip(self, req))]
    pub async fn create_pull_request(
        &self,
        owner: &str,
        repo: &str,
        req: &CreatePullRequestRequest,
    ) -> GitHubResult<PullRequest> {
        self.post(&format!("/repos/{owner}/{repo}/pulls"), req)
            .await
    }

    /// Get a single pull request.
    ///
    /// # Errors
    /// Returns [`GitHubError`] if the API request fails.
    #[instrument(skip(self))]
    pub async fn get_pull_request(
        &self,
        owner: &str,
        repo: &str,
        pull_number: u32,
    ) -> GitHubResult<PullRequest> {
        self.get(&format!("/repos/{owner}/{repo}/pulls/{pull_number}"))
            .await
    }

    /// Merge a pull request.
    ///
    /// # Errors
    /// Returns [`GitHubError`] if the API request fails.
    #[instrument(skip(self, req))]
    pub async fn merge_pull_request(
        &self,
        owner: &str,
        repo: &str,
        pull_number: u32,
        req: &MergePullRequestRequest,
    ) -> GitHubResult<MergeResult> {
        self.put(
            &format!("/repos/{owner}/{repo}/pulls/{pull_number}/merge"),
            req,
        )
        .await
    }

    // ── Repository operations ─────────────────────────────────────

    /// Get repository metadata.
    ///
    /// # Errors
    /// Returns [`GitHubError`] if the API request fails.
    #[instrument(skip(self))]
    pub async fn get_repo(&self, owner: &str, repo: &str) -> GitHubResult<Repository> {
        self.get(&format!("/repos/{owner}/{repo}")).await
    }

    /// Search repositories.
    ///
    /// # Errors
    /// Returns [`GitHubError`] if the API request fails.
    #[instrument(skip(self))]
    pub async fn search_repos(&self, query: &str) -> GitHubResult<SearchResults<Repository>> {
        let encoded = urlencoding::encode(query);
        self.get(&format!("/search/repositories?q={encoded}")).await
    }

    // ── Actions operations ────────────────────────────────────────

    /// List workflows in a repository.
    ///
    /// # Errors
    /// Returns [`GitHubError`] if the API request fails.
    #[instrument(skip(self))]
    pub async fn list_workflows(&self, owner: &str, repo: &str) -> GitHubResult<WorkflowsResponse> {
        self.get(&format!("/repos/{owner}/{repo}/actions/workflows"))
            .await
    }

    /// Trigger a workflow dispatch event.
    ///
    /// # Errors
    /// Returns [`GitHubError`] if the API request fails.
    #[instrument(skip(self))]
    pub async fn trigger_workflow(
        &self,
        owner: &str,
        repo: &str,
        workflow_id: &str,
        git_ref: &str,
    ) -> GitHubResult<()> {
        let body = serde_json::json!({ "ref": git_ref });
        let url = format!(
            "{}/repos/{owner}/{repo}/actions/workflows/{workflow_id}/dispatches",
            self.base_url
        );

        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let mut delay = Duration::from_millis(self.initial_delay_ms);
        let mut attempts = 0;

        loop {
            attempts += 1;
            debug!(attempt = attempts, "Triggering workflow dispatch");

            let result = self
                .apply_auth(self.client.post(&url))
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28")
                .json(&body)
                .send()
                .await;

            match result {
                Ok(response) => {
                    let status = response.status();
                    if status == StatusCode::NO_CONTENT {
                        return Ok(());
                    }
                    let bytes = response.bytes().await.map_err(GitHubError::Http)?;
                    let err = parse_error_response(status, &bytes);
                    if err.is_retryable() && attempts < self.max_retries {
                        if let Some(retry_after) = err.retry_after() {
                            delay = retry_after;
                        }
                        warn!(attempt = attempts, delay_ms = delay.as_millis(), "Retrying");
                        sleep(delay).await;
                        delay = std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
                    } else {
                        return Err(err);
                    }
                }
                Err(e) if (e.is_timeout() || e.is_connect()) && attempts < self.max_retries => {
                    warn!(attempt = attempts, error = %e, "Retrying after connection error");
                    sleep(delay).await;
                    delay = std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
                }
                Err(e) => return Err(GitHubError::Http(e)),
            }
        }
    }

    // ── Content operations ────────────────────────────────────────

    /// Get file or directory content.
    ///
    /// # Errors
    /// Returns [`GitHubError`] if the API request fails.
    #[instrument(skip(self))]
    pub async fn get_file_content(
        &self,
        owner: &str,
        repo: &str,
        path: &str,
    ) -> GitHubResult<FileContent> {
        self.get(&format!("/repos/{owner}/{repo}/contents/{path}"))
            .await
    }

    // ── Code Search ───────────────────────────────────────────────

    /// Search code across repositories.
    ///
    /// # Errors
    /// Returns [`GitHubError`] if the API request fails.
    #[instrument(skip(self))]
    pub async fn search_code(&self, query: &str) -> GitHubResult<SearchResults<CodeSearchItem>> {
        let encoded = urlencoding::encode(query);
        self.get(&format!("/search/code?q={encoded}")).await
    }

    // ── HTTP primitives ───────────────────────────────────────────

    /// Make a GET request with retries.
    async fn get<R>(&self, endpoint: &str) -> GitHubResult<R>
    where
        R: serde::de::DeserializeOwned + Send,
    {
        let url = format!("{}{endpoint}", self.base_url);
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let mut delay = Duration::from_millis(self.initial_delay_ms);
        let mut attempts = 0;

        loop {
            attempts += 1;
            debug!(attempt = attempts, endpoint, "GitHub API GET");

            let result = self
                .apply_auth(self.client.get(&url))
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28")
                .send()
                .await;

            match result {
                Ok(response) => match self.handle_response(response).await {
                    Ok(data) => return Ok(data),
                    Err(e) if e.is_retryable() && attempts < self.max_retries => {
                        if let Some(retry_after) = e.retry_after() {
                            delay = retry_after;
                        }
                        warn!(
                            attempt = attempts,
                            delay_ms = delay.as_millis(),
                            error = %e,
                            "Retrying GitHub API request"
                        );
                        sleep(delay).await;
                        delay = std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
                    }
                    Err(e) => return Err(e),
                },
                Err(e) if (e.is_timeout() || e.is_connect()) && attempts < self.max_retries => {
                    warn!(
                        attempt = attempts,
                        delay_ms = delay.as_millis(),
                        error = %e,
                        "Retrying after connection error"
                    );
                    sleep(delay).await;
                    delay = std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
                }
                Err(e) => return Err(GitHubError::Http(e)),
            }
        }
    }

    /// Make a POST request with retries.
    async fn post<T, R>(&self, endpoint: &str, body: &T) -> GitHubResult<R>
    where
        T: serde::Serialize + Sync,
        R: serde::de::DeserializeOwned + Send,
    {
        let url = format!("{}{endpoint}", self.base_url);
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let mut delay = Duration::from_millis(self.initial_delay_ms);
        let mut attempts = 0;

        loop {
            attempts += 1;
            debug!(attempt = attempts, endpoint, "GitHub API POST");

            let result = self
                .apply_auth(self.client.post(&url))
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28")
                .json(body)
                .send()
                .await;

            match result {
                Ok(response) => match self.handle_response(response).await {
                    Ok(data) => return Ok(data),
                    Err(e) if e.is_retryable() && attempts < self.max_retries => {
                        if let Some(retry_after) = e.retry_after() {
                            delay = retry_after;
                        }
                        warn!(attempt = attempts, error = %e, "Retrying");
                        sleep(delay).await;
                        delay = std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
                    }
                    Err(e) => return Err(e),
                },
                Err(e) if (e.is_timeout() || e.is_connect()) && attempts < self.max_retries => {
                    warn!(attempt = attempts, error = %e, "Retrying after connection error");
                    sleep(delay).await;
                    delay = std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
                }
                Err(e) => return Err(GitHubError::Http(e)),
            }
        }
    }

    /// Make a PUT request with retries.
    async fn put<T, R>(&self, endpoint: &str, body: &T) -> GitHubResult<R>
    where
        T: serde::Serialize + Sync,
        R: serde::de::DeserializeOwned + Send,
    {
        let url = format!("{}{endpoint}", self.base_url);
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let mut delay = Duration::from_millis(self.initial_delay_ms);
        let mut attempts = 0;

        loop {
            attempts += 1;
            debug!(attempt = attempts, endpoint, "GitHub API PUT");

            let result = self
                .apply_auth(self.client.put(&url))
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28")
                .json(body)
                .send()
                .await;

            match result {
                Ok(response) => match self.handle_response(response).await {
                    Ok(data) => return Ok(data),
                    Err(e) if e.is_retryable() && attempts < self.max_retries => {
                        if let Some(retry_after) = e.retry_after() {
                            delay = retry_after;
                        }
                        warn!(attempt = attempts, error = %e, "Retrying");
                        sleep(delay).await;
                        delay = std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
                    }
                    Err(e) => return Err(e),
                },
                Err(e) if (e.is_timeout() || e.is_connect()) && attempts < self.max_retries => {
                    warn!(attempt = attempts, error = %e, "Retrying after connection error");
                    sleep(delay).await;
                    delay = std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
                }
                Err(e) => return Err(GitHubError::Http(e)),
            }
        }
    }

    /// Handle a response, deserializing success or parsing errors.
    async fn handle_response<R>(&self, response: Response) -> GitHubResult<R>
    where
        R: serde::de::DeserializeOwned + Send,
    {
        let status = response.status();

        // Extract rate limit headers before consuming body
        let rate_limit_remaining = response
            .headers()
            .get("x-ratelimit-remaining")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u32>().ok());

        let retry_after_secs = response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let bytes = response.bytes().await.map_err(GitHubError::Http)?;

        if status.is_success() {
            serde_json::from_slice(&bytes).map_err(GitHubError::from)
        } else {
            // Check for secondary rate limit (403 with low remaining)
            if status == StatusCode::FORBIDDEN && rate_limit_remaining == Some(0) {
                let retry_ms = retry_after_secs.unwrap_or(60) * 1000;
                return Err(GitHubError::RateLimited {
                    retry_after_ms: retry_ms,
                });
            }
            Err(parse_error_response(status, &bytes))
        }
    }
}

/// Parse an error response body.
fn parse_error_response(status: StatusCode, bytes: &Bytes) -> GitHubError {
    if let Ok(err_resp) = serde_json::from_slice::<ApiErrorResponse>(bytes) {
        if status == StatusCode::TOO_MANY_REQUESTS {
            return GitHubError::RateLimited {
                retry_after_ms: 60_000,
            };
        }
        if status == StatusCode::UNAUTHORIZED {
            return GitHubError::Unauthorized;
        }
        if status == StatusCode::NOT_FOUND {
            return GitHubError::NotFound {
                resource: err_resp.message,
            };
        }
        if status == StatusCode::UNPROCESSABLE_ENTITY {
            return GitHubError::ValidationError {
                message: err_resp.message,
            };
        }
        if status == StatusCode::METHOD_NOT_ALLOWED || status == StatusCode::CONFLICT {
            return GitHubError::MergeConflict {
                message: err_resp.message,
            };
        }

        return GitHubError::Api {
            message: err_resp.message,
            status_code: Some(status.as_u16()),
            documentation_url: err_resp.documentation_url,
        };
    }

    GitHubError::Api {
        message: String::from_utf8_lossy(bytes).into_owned(),
        status_code: Some(status.as_u16()),
        documentation_url: None,
    }
}

/// URL-encode a query string.
mod urlencoding {
    use std::fmt::Write;

    pub fn encode(input: &str) -> String {
        let mut encoded = String::with_capacity(input.len());
        for byte in input.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    encoded.push(byte as char);
                }
                _ => {
                    let _ = write!(encoded, "%{byte:02X}");
                }
            }
        }
        encoded
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_testkit::LogCapture;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path},
    };

    #[fcp_async_core::runtime::test]
    async fn test_get_repo_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/repos/octocat/hello-world"))
            .and(header("Authorization", "Bearer test_token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 1296269,
                "name": "hello-world",
                "full_name": "octocat/hello-world",
                "owner": { "login": "octocat", "id": 1, "avatar_url": "", "type": "User" },
                "description": "Test repo",
                "private": false,
                "fork": false,
                "html_url": "https://github.com/octocat/hello-world",
                "default_branch": "main",
                "language": "Rust",
                "stargazers_count": 42,
                "forks_count": 10,
                "open_issues_count": 5,
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-06-01T00:00:00Z"
            })))
            .mount(&mock_server)
            .await;

        let client = GitHubClient::new("test_token")
            .unwrap()
            .with_base_url(mock_server.uri());

        let repo = client.get_repo("octocat", "hello-world").await.unwrap();
        assert_eq!(repo.name, "hello-world");
        assert_eq!(repo.full_name, "octocat/hello-world");
        assert_eq!(repo.stargazers_count, 42);
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_issue_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/repos/octocat/hello-world/issues/42"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 1,
                "number": 42,
                "title": "Found a bug",
                "state": "open",
                "body": "Bug description",
                "user": { "login": "octocat", "id": 1, "avatar_url": "", "type": "User" },
                "labels": [],
                "assignees": [],
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-01T00:00:00Z",
                "html_url": "https://github.com/octocat/hello-world/issues/42",
                "comments": 3
            })))
            .mount(&mock_server)
            .await;

        let client = GitHubClient::new("test_token")
            .unwrap()
            .with_base_url(mock_server.uri());

        let issue = client
            .get_issue("octocat", "hello-world", 42)
            .await
            .unwrap();
        assert_eq!(issue.number, 42);
        assert_eq!(issue.title, "Found a bug");
        assert_eq!(issue.state, "open");
    }

    #[fcp_async_core::runtime::test]
    async fn test_create_issue_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/repos/octocat/hello-world/issues"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "id": 2,
                "number": 43,
                "title": "New issue",
                "state": "open",
                "user": { "login": "octocat", "id": 1, "avatar_url": "", "type": "User" },
                "labels": [],
                "assignees": [],
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-01T00:00:00Z",
                "html_url": "https://github.com/octocat/hello-world/issues/43",
                "comments": 0
            })))
            .mount(&mock_server)
            .await;

        let client = GitHubClient::new("test_token")
            .unwrap()
            .with_base_url(mock_server.uri());

        let issue = client
            .create_issue(
                "octocat",
                "hello-world",
                &CreateIssueRequest {
                    title: "New issue".into(),
                    body: Some("Description".into()),
                    assignees: None,
                    labels: None,
                    milestone: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(issue.number, 43);
        assert_eq!(issue.title, "New issue");
    }

    #[fcp_async_core::runtime::test]
    async fn test_unauthorized() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/repos/octocat/hello-world"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "message": "Bad credentials",
                "documentation_url": "https://docs.github.com"
            })))
            .mount(&mock_server)
            .await;

        let client = GitHubClient::new("bad_token")
            .unwrap()
            .with_base_url(mock_server.uri())
            .with_retry_config(1, 10, 100);

        let result = client.get_repo("octocat", "hello-world").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GitHubError::Unauthorized));
    }

    #[fcp_async_core::runtime::test]
    async fn test_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/repos/octocat/nonexistent"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "message": "Not Found"
            })))
            .mount(&mock_server)
            .await;

        let client = GitHubClient::new("test_token")
            .unwrap()
            .with_base_url(mock_server.uri())
            .with_retry_config(1, 10, 100);

        let result = client.get_repo("octocat", "nonexistent").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GitHubError::NotFound { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_rate_limited() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/repos/octocat/hello-world"))
            .respond_with(ResponseTemplate::new(429).set_body_json(serde_json::json!({
                "message": "API rate limit exceeded"
            })))
            .mount(&mock_server)
            .await;

        let client = GitHubClient::new("test_token")
            .unwrap()
            .with_base_url(mock_server.uri())
            .with_retry_config(1, 10, 100);

        let result = client.get_repo("octocat", "hello-world").await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GitHubError::RateLimited { .. }
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_pull_request_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/repos/octocat/hello-world/pulls/1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 100,
                "number": 1,
                "title": "Fix typo",
                "state": "open",
                "user": { "login": "octocat", "id": 1, "avatar_url": "", "type": "User" },
                "head": { "label": "octocat:fix-typo", "ref": "fix-typo", "sha": "abc123" },
                "base": { "label": "octocat:main", "ref": "main", "sha": "def456" },
                "labels": [],
                "assignees": [],
                "merged": false,
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-01T00:00:00Z",
                "html_url": "https://github.com/octocat/hello-world/pull/1",
                "draft": false
            })))
            .mount(&mock_server)
            .await;

        let client = GitHubClient::new("test_token")
            .unwrap()
            .with_base_url(mock_server.uri());

        let pr = client
            .get_pull_request("octocat", "hello-world", 1)
            .await
            .unwrap();
        assert_eq!(pr.number, 1);
        assert_eq!(pr.title, "Fix typo");
        assert_eq!(pr.head.ref_name, "fix-typo");
    }

    #[fcp_async_core::runtime::test]
    async fn test_search_issues_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/search/issues"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "total_count": 1,
                "incomplete_results": false,
                "items": [{
                    "id": 1,
                    "number": 42,
                    "title": "Found a bug",
                    "state": "open",
                    "user": { "login": "octocat", "id": 1, "avatar_url": "", "type": "User" },
                    "labels": [],
                    "assignees": [],
                    "created_at": "2024-01-01T00:00:00Z",
                    "updated_at": "2024-01-01T00:00:00Z",
                    "html_url": "https://github.com/octocat/hello-world/issues/42",
                    "comments": 0
                }]
            })))
            .mount(&mock_server)
            .await;

        let client = GitHubClient::new("test_token")
            .unwrap()
            .with_base_url(mock_server.uri());

        let results = client
            .search_issues("is:open is:issue repo:octocat/hello-world")
            .await
            .unwrap();
        assert_eq!(results.total_count, 1);
        assert_eq!(results.items.len(), 1);
        assert_eq!(results.items[0].title, "Found a bug");
    }

    #[fcp_async_core::runtime::test(flavor = "current_thread")]
    async fn test_logs_redact_token() {
        let capture = LogCapture::new();
        let _guard = capture.install_json_with_filter("debug");
        tracing::debug!("log_capture_ready");

        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/repos/octocat/hello-world"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 1, "name": "hello-world", "full_name": "octocat/hello-world",
                "owner": { "login": "octocat", "id": 1, "avatar_url": "", "type": "User" },
                "private": false, "fork": false,
                "html_url": "https://github.com/octocat/hello-world",
                "default_branch": "main",
                "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"
            })))
            .mount(&mock_server)
            .await;

        let client = GitHubClient::new("ghp_SECRET_TOKEN_12345")
            .unwrap()
            .with_base_url(mock_server.uri());
        let _ = client.get_repo("octocat", "hello-world").await.unwrap();

        let logs = capture.jsonl();
        assert!(
            logs.contains("log_capture_ready"),
            "expected debug logs captured"
        );
        assert!(
            !logs.contains("ghp_SECRET_TOKEN_12345"),
            "token should not appear in logs"
        );
    }

    #[test]
    fn test_urlencoding() {
        assert_eq!(urlencoding::encode("hello world"), "hello%20world");
        assert_eq!(
            urlencoding::encode("is:open is:issue"),
            "is%3Aopen%20is%3Aissue"
        );
        assert_eq!(urlencoding::encode("safe-text_here"), "safe-text_here");
    }

    #[test]
    fn test_error_is_retryable() {
        assert!(
            GitHubError::RateLimited {
                retry_after_ms: 1000
            }
            .is_retryable()
        );
        assert!(!GitHubError::Unauthorized.is_retryable());
        assert!(
            !GitHubError::NotFound {
                resource: "test".into()
            }
            .is_retryable()
        );
    }
}
