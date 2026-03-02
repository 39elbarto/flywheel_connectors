//! Jira REST API client.

use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use base64::Engine;
use fcp_core::CredentialId;
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument, warn};

use crate::{
    error::{JiraError, JiraResult},
    types::{
        ApiErrorResponse, CommentListResponse, CreateIssueResponse, JiraAttachment, JiraComment,
        JiraIssue, SearchResult, SprintListResponse, TransitionsResponse,
    },
};

/// Default Jira REST API base URL template (append domain).
pub const DEFAULT_REST_BASE: &str = "https://{domain}.atlassian.net/rest/api/3";

/// Default Jira Agile API base URL template (append domain).
pub const DEFAULT_AGILE_BASE: &str = "https://{domain}.atlassian.net/rest/agile/1.0";

/// Authentication mode for the Jira client.
#[derive(Clone)]
pub enum JiraAuth {
    /// Direct credentials: email + API token (Basic auth).
    Token {
        domain: String,
        email: String,
        api_token: String,
    },
    /// Secretless credential injection via egress proxy.
    CredentialId {
        domain: String,
        credential_id: CredentialId,
    },
}

impl std::fmt::Debug for JiraAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Token { domain, email, .. } => f
                .debug_struct("Token")
                .field("domain", domain)
                .field("email", email)
                .field("api_token", &"[REDACTED]")
                .finish(),
            Self::CredentialId {
                domain,
                credential_id,
            } => f
                .debug_struct("CredentialId")
                .field("domain", domain)
                .field("credential_id", credential_id)
                .finish(),
        }
    }
}

impl JiraAuth {
    /// Human-readable label with secrets redacted.
    #[must_use]
    pub const fn redacted_label(&self) -> &'static str {
        match self {
            Self::Token { .. } => "token",
            Self::CredentialId { .. } => "credential_id",
        }
    }

    /// Whether this auth mode is secretless (no raw credentials held).
    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId { .. })
    }

    /// Get the domain regardless of auth mode.
    #[must_use]
    pub fn domain(&self) -> &str {
        match self {
            Self::Token { domain, .. } | Self::CredentialId { domain, .. } => domain,
        }
    }
}

/// Jira REST API client with retry logic and rate limit awareness.
pub struct JiraClient {
    client: Client,
    auth: JiraAuth,
    base_url: String,
    agile_url: String,
    max_retries: u32,
    initial_delay_ms: u64,
    max_delay_ms: u64,
    total_requests: AtomicU64,
}

impl std::fmt::Debug for JiraClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JiraClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .field("agile_url", &self.agile_url)
            .field("max_retries", &self.max_retries)
            .finish_non_exhaustive()
    }
}

impl JiraClient {
    /// Create a new Jira client with basic auth (email + API token).
    pub fn new(domain: &str, email: &str, api_token: &str) -> JiraResult<Self> {
        Self::new_with_auth(JiraAuth::Token {
            domain: domain.to_string(),
            email: email.to_string(),
            api_token: api_token.to_string(),
        })
    }

    /// Create a new Jira client with the given auth mode.
    pub fn new_with_auth(auth: JiraAuth) -> JiraResult<Self> {
        let mut headers = reqwest::header::HeaderMap::new();

        match &auth {
            JiraAuth::Token {
                email, api_token, ..
            } => {
                let credentials = base64::engine::general_purpose::STANDARD
                    .encode(format!("{email}:{api_token}"));
                headers.insert(
                    reqwest::header::AUTHORIZATION,
                    format!("Basic {credentials}").parse().unwrap(),
                );
            }
            JiraAuth::CredentialId { credential_id, .. } => {
                headers.insert(
                    "X-FCP-Credential-ID",
                    credential_id.to_string().parse().unwrap(),
                );
            }
        }

        headers.insert(
            reqwest::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );
        headers.insert(reqwest::header::ACCEPT, "application/json".parse().unwrap());

        let domain = auth.domain();
        let base_url = format!("https://{domain}.atlassian.net/rest/api/3");
        let agile_url = format!("https://{domain}.atlassian.net/rest/agile/1.0");

        let client = Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-jira/0.1.0")
            .build()
            .map_err(JiraError::Http)?;

        Ok(Self {
            client,
            auth,
            base_url,
            agile_url,
            max_retries: 3,
            initial_delay_ms: 1000,
            max_delay_ms: 60_000,
            total_requests: AtomicU64::new(0),
        })
    }

    /// Perform a health check by fetching the current user.
    pub async fn health_check(&self) -> JiraResult<serde_json::Value> {
        let url = format!("{}/myself", self.base_url);
        self.get(&url).await
    }

    /// Set a custom base URL (for testing).
    #[must_use]
    pub fn with_base_url(mut self, url: &str) -> Self {
        self.base_url = url.to_string();
        self
    }

    /// Set a custom agile URL (for testing).
    #[must_use]
    pub fn with_agile_url(mut self, url: &str) -> Self {
        self.agile_url = url.to_string();
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

    // ── Issue operations ─────────────────────────────────────────

    /// Create a new issue.
    #[instrument(skip(self, input))]
    pub async fn create_issue(&self, input: &serde_json::Value) -> JiraResult<CreateIssueResponse> {
        self.post(&format!("{}/issue", self.base_url), input).await
    }

    /// Get an issue by key or ID.
    #[instrument(skip(self))]
    pub async fn get_issue(
        &self,
        issue_key: &str,
        fields: Option<&str>,
        expand: Option<&str>,
    ) -> JiraResult<JiraIssue> {
        let mut url = format!("{}/issue/{issue_key}", self.base_url);
        let mut sep = '?';
        if let Some(fields) = fields {
            let encoded =
                percent_encoding::utf8_percent_encode(fields, percent_encoding::NON_ALPHANUMERIC);
            let _ = write!(url, "{sep}fields={encoded}");
            sep = '&';
        }
        if let Some(expand) = expand {
            let encoded =
                percent_encoding::utf8_percent_encode(expand, percent_encoding::NON_ALPHANUMERIC);
            let _ = write!(url, "{sep}expand={encoded}");
        }

        self.get(&url).await
    }

    /// Update an issue's fields.
    #[instrument(skip(self, body))]
    pub async fn update_issue(
        &self,
        issue_key: &str,
        body: &serde_json::Value,
        notify_users: bool,
    ) -> JiraResult<()> {
        let mut url = format!("{}/issue/{issue_key}", self.base_url);
        if !notify_users {
            url.push_str("?notifyUsers=false");
        }

        self.put_no_content(&url, body).await
    }

    /// Delete an issue.
    #[instrument(skip(self))]
    pub async fn delete_issue(&self, issue_key: &str, delete_subtasks: bool) -> JiraResult<()> {
        let mut url = format!("{}/issue/{issue_key}", self.base_url);
        if delete_subtasks {
            url.push_str("?deleteSubtasks=true");
        }

        self.delete(&url).await
    }

    // ── Search ───────────────────────────────────────────────────

    /// Search issues using JQL (POST method for complex queries).
    #[instrument(skip(self, body))]
    pub async fn search_jql(&self, body: &serde_json::Value) -> JiraResult<SearchResult> {
        self.post(&format!("{}/search", self.base_url), body).await
    }

    // ── Transitions ──────────────────────────────────────────────

    /// List available transitions for an issue.
    #[instrument(skip(self))]
    pub async fn list_transitions(&self, issue_key: &str) -> JiraResult<TransitionsResponse> {
        self.get(&format!("{}/issue/{issue_key}/transitions", self.base_url))
            .await
    }

    /// Execute a transition on an issue.
    #[instrument(skip(self, body))]
    pub async fn transition_issue(
        &self,
        issue_key: &str,
        body: &serde_json::Value,
    ) -> JiraResult<()> {
        self.post_no_content(
            &format!("{}/issue/{issue_key}/transitions", self.base_url),
            body,
        )
        .await
    }

    // ── Sprint operations ────────────────────────────────────────

    /// List sprints for a board.
    #[instrument(skip(self))]
    pub async fn list_sprints(
        &self,
        board_id: u64,
        state: Option<&str>,
        start_at: Option<u64>,
        max_results: Option<u64>,
    ) -> JiraResult<SprintListResponse> {
        let mut url = format!("{}/board/{board_id}/sprint", self.agile_url);
        let mut sep = '?';
        if let Some(state) = state {
            let encoded =
                percent_encoding::utf8_percent_encode(state, percent_encoding::NON_ALPHANUMERIC);
            let _ = write!(url, "{sep}state={encoded}");
            sep = '&';
        }
        if let Some(start_at) = start_at {
            let _ = write!(url, "{sep}startAt={start_at}");
            sep = '&';
        }
        if let Some(max_results) = max_results {
            let _ = write!(url, "{sep}maxResults={max_results}");
        }

        self.get(&url).await
    }

    /// Move issues to a sprint.
    #[instrument(skip(self, body))]
    pub async fn move_to_sprint(&self, sprint_id: u64, body: &serde_json::Value) -> JiraResult<()> {
        self.post_no_content(
            &format!("{}/sprint/{sprint_id}/issue", self.agile_url),
            body,
        )
        .await
    }

    // ── Comment operations ───────────────────────────────────────

    /// Add a comment to an issue.
    #[instrument(skip(self, body))]
    pub async fn add_comment(
        &self,
        issue_key: &str,
        body: &serde_json::Value,
    ) -> JiraResult<JiraComment> {
        self.post(
            &format!("{}/issue/{issue_key}/comment", self.base_url),
            body,
        )
        .await
    }

    /// List comments on an issue.
    #[instrument(skip(self))]
    pub async fn list_comments(
        &self,
        issue_key: &str,
        start_at: Option<u64>,
        max_results: Option<u64>,
        order_by: Option<&str>,
    ) -> JiraResult<CommentListResponse> {
        let mut url = format!("{}/issue/{issue_key}/comment", self.base_url);
        let mut sep = '?';
        if let Some(start_at) = start_at {
            let _ = write!(url, "{sep}startAt={start_at}");
            sep = '&';
        }
        if let Some(max_results) = max_results {
            let _ = write!(url, "{sep}maxResults={max_results}");
            sep = '&';
        }
        if let Some(order_by) = order_by {
            let encoded =
                percent_encoding::utf8_percent_encode(order_by, percent_encoding::NON_ALPHANUMERIC);
            let _ = write!(url, "{sep}orderBy={encoded}");
        }

        self.get(&url).await
    }

    // ── Attachment operations ────────────────────────────────────

    /// Upload an attachment to an issue (multipart).
    #[instrument(skip(self, data))]
    pub async fn add_attachment(
        &self,
        issue_key: &str,
        filename: &str,
        data: &[u8],
    ) -> JiraResult<Vec<JiraAttachment>> {
        let url = format!("{}/issue/{issue_key}/attachments", self.base_url);
        self.total_requests.fetch_add(1, Ordering::Relaxed);

        let mut delay = Duration::from_millis(self.initial_delay_ms);
        let mut attempts = 0;

        loop {
            attempts += 1;
            debug!(attempt = attempts, "Jira attachment upload");

            let part = reqwest::multipart::Part::bytes(data.to_vec())
                .file_name(filename.to_string())
                .mime_str("application/octet-stream")
                .unwrap();

            let form = reqwest::multipart::Form::new().part("file", part);

            let result = self
                .client
                .post(&url)
                .header("X-Atlassian-Token", "no-check")
                .multipart(form)
                .send()
                .await;

            match result {
                Ok(response) => {
                    let status = response.status();
                    if let Some(retry_result) = Self::check_rate_limit(&response) {
                        if attempts <= self.max_retries {
                            let wait = retry_result.unwrap_or(delay);
                            warn!(attempt = attempts, "Rate limited, waiting {wait:?}");
                            fcp_async_core::time::sleep(wait).await;
                            continue;
                        }
                        return Err(JiraError::RateLimited {
                            retry_after_ms: retry_result.map_or(60_000, |d| d.as_millis() as u64),
                        });
                    }

                    let bytes = response.bytes().await.map_err(JiraError::Http)?;
                    if status.is_success() {
                        return serde_json::from_slice(&bytes).map_err(JiraError::from);
                    }
                    let err = Self::parse_error(status, &bytes);
                    if err.is_retryable() && attempts <= self.max_retries {
                        warn!(attempt = attempts, "Retrying attachment upload");
                        fcp_async_core::time::sleep(delay).await;
                        delay = std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
                        continue;
                    }
                    return Err(err);
                }
                Err(e) if (e.is_timeout() || e.is_connect()) && attempts <= self.max_retries => {
                    warn!(attempt = attempts, error = %e, "Retrying after connection error");
                    fcp_async_core::time::sleep(delay).await;
                    delay = std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
                }
                Err(e) => return Err(JiraError::Http(e)),
            }
        }
    }

    // ── Internal HTTP helpers ────────────────────────────────────

    async fn get<R>(&self, url: &str) -> JiraResult<R>
    where
        R: serde::de::DeserializeOwned + Send,
    {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let mut delay = Duration::from_millis(self.initial_delay_ms);
        let mut attempts = 0;

        loop {
            attempts += 1;
            debug!(attempt = attempts, url, "Jira API GET");

            let result = self.client.get(url).send().await;

            match result {
                Ok(response) => match self.handle_response(response).await {
                    Ok(data) => return Ok(data),
                    Err(e) if e.is_retryable() && attempts <= self.max_retries => {
                        if let Some(retry_after) = e.retry_after() {
                            delay = retry_after;
                        }
                        warn!(attempt = attempts, error = %e, "Retrying Jira API request");
                        fcp_async_core::time::sleep(delay).await;
                        delay = std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
                    }
                    Err(e) => return Err(e),
                },
                Err(e) if (e.is_timeout() || e.is_connect()) && attempts <= self.max_retries => {
                    warn!(attempt = attempts, error = %e, "Retrying after connection error");
                    fcp_async_core::time::sleep(delay).await;
                    delay = std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
                }
                Err(e) => return Err(JiraError::Http(e)),
            }
        }
    }

    async fn post<R>(&self, url: &str, body: &serde_json::Value) -> JiraResult<R>
    where
        R: serde::de::DeserializeOwned + Send,
    {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let mut delay = Duration::from_millis(self.initial_delay_ms);
        let mut attempts = 0;

        loop {
            attempts += 1;
            debug!(attempt = attempts, url, "Jira API POST");

            let result = self.client.post(url).json(body).send().await;

            match result {
                Ok(response) => match self.handle_response(response).await {
                    Ok(data) => return Ok(data),
                    Err(e) if e.is_retryable() && attempts <= self.max_retries => {
                        if let Some(retry_after) = e.retry_after() {
                            delay = retry_after;
                        }
                        warn!(attempt = attempts, error = %e, "Retrying");
                        fcp_async_core::time::sleep(delay).await;
                        delay = std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
                    }
                    Err(e) => return Err(e),
                },
                Err(e) if (e.is_timeout() || e.is_connect()) && attempts <= self.max_retries => {
                    warn!(attempt = attempts, error = %e, "Retrying after connection error");
                    fcp_async_core::time::sleep(delay).await;
                    delay = std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
                }
                Err(e) => return Err(JiraError::Http(e)),
            }
        }
    }

    async fn post_no_content(&self, url: &str, body: &serde_json::Value) -> JiraResult<()> {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let mut delay = Duration::from_millis(self.initial_delay_ms);
        let mut attempts = 0;

        loop {
            attempts += 1;
            debug!(attempt = attempts, url, "Jira API POST (no content)");

            let result = self.client.post(url).json(body).send().await;

            match result {
                Ok(response) => {
                    let status = response.status();
                    if let Some(retry_result) = Self::check_rate_limit(&response) {
                        if attempts <= self.max_retries {
                            let wait = retry_result.unwrap_or(delay);
                            warn!(attempt = attempts, "Rate limited, waiting {wait:?}");
                            fcp_async_core::time::sleep(wait).await;
                            continue;
                        }
                        return Err(JiraError::RateLimited {
                            retry_after_ms: retry_result.map_or(60_000, |d| d.as_millis() as u64),
                        });
                    }
                    if status.is_success() {
                        return Ok(());
                    }
                    let bytes = response.bytes().await.map_err(JiraError::Http)?;
                    let err = Self::parse_error(status, &bytes);
                    if err.is_retryable() && attempts <= self.max_retries {
                        warn!(attempt = attempts, error = %err, "Retrying");
                        fcp_async_core::time::sleep(delay).await;
                        delay = std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
                        continue;
                    }
                    return Err(err);
                }
                Err(e) if (e.is_timeout() || e.is_connect()) && attempts <= self.max_retries => {
                    warn!(attempt = attempts, error = %e, "Retrying after connection error");
                    fcp_async_core::time::sleep(delay).await;
                    delay = std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
                }
                Err(e) => return Err(JiraError::Http(e)),
            }
        }
    }

    async fn put_no_content(&self, url: &str, body: &serde_json::Value) -> JiraResult<()> {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let mut delay = Duration::from_millis(self.initial_delay_ms);
        let mut attempts = 0;

        loop {
            attempts += 1;
            debug!(attempt = attempts, url, "Jira API PUT");

            let result = self.client.put(url).json(body).send().await;

            match result {
                Ok(response) => {
                    let status = response.status();
                    if let Some(retry_result) = Self::check_rate_limit(&response) {
                        if attempts <= self.max_retries {
                            let wait = retry_result.unwrap_or(delay);
                            warn!(attempt = attempts, "Rate limited, waiting {wait:?}");
                            fcp_async_core::time::sleep(wait).await;
                            continue;
                        }
                        return Err(JiraError::RateLimited {
                            retry_after_ms: retry_result.map_or(60_000, |d| d.as_millis() as u64),
                        });
                    }
                    if status.is_success() {
                        return Ok(());
                    }
                    let bytes = response.bytes().await.map_err(JiraError::Http)?;
                    let err = Self::parse_error(status, &bytes);
                    if err.is_retryable() && attempts <= self.max_retries {
                        warn!(attempt = attempts, error = %err, "Retrying");
                        fcp_async_core::time::sleep(delay).await;
                        delay = std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
                        continue;
                    }
                    return Err(err);
                }
                Err(e) if (e.is_timeout() || e.is_connect()) && attempts <= self.max_retries => {
                    warn!(attempt = attempts, error = %e, "Retrying after connection error");
                    fcp_async_core::time::sleep(delay).await;
                    delay = std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
                }
                Err(e) => return Err(JiraError::Http(e)),
            }
        }
    }

    async fn delete(&self, url: &str) -> JiraResult<()> {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let mut delay = Duration::from_millis(self.initial_delay_ms);
        let mut attempts = 0;

        loop {
            attempts += 1;
            debug!(attempt = attempts, url, "Jira API DELETE");

            let result = self.client.delete(url).send().await;

            match result {
                Ok(response) => {
                    let status = response.status();
                    if let Some(retry_result) = Self::check_rate_limit(&response) {
                        if attempts <= self.max_retries {
                            let wait = retry_result.unwrap_or(delay);
                            warn!(attempt = attempts, "Rate limited, waiting {wait:?}");
                            fcp_async_core::time::sleep(wait).await;
                            continue;
                        }
                        return Err(JiraError::RateLimited {
                            retry_after_ms: retry_result.map_or(60_000, |d| d.as_millis() as u64),
                        });
                    }
                    if status.is_success() {
                        return Ok(());
                    }
                    let bytes = response.bytes().await.map_err(JiraError::Http)?;
                    let err = Self::parse_error(status, &bytes);
                    if err.is_retryable() && attempts <= self.max_retries {
                        warn!(attempt = attempts, error = %err, "Retrying");
                        fcp_async_core::time::sleep(delay).await;
                        delay = std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
                        continue;
                    }
                    return Err(err);
                }
                Err(e) if (e.is_timeout() || e.is_connect()) && attempts <= self.max_retries => {
                    warn!(attempt = attempts, error = %e, "Retrying after connection error");
                    fcp_async_core::time::sleep(delay).await;
                    delay = std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
                }
                Err(e) => return Err(JiraError::Http(e)),
            }
        }
    }

    /// Handle a response, deserializing success or parsing errors.
    async fn handle_response<R>(&self, response: Response) -> JiraResult<R>
    where
        R: serde::de::DeserializeOwned + Send,
    {
        let status = response.status();

        if let Some(retry_result) = Self::check_rate_limit(&response) {
            return Err(JiraError::RateLimited {
                retry_after_ms: retry_result.map_or(60_000, |d| d.as_millis() as u64),
            });
        }

        let bytes = response.bytes().await.map_err(JiraError::Http)?;

        if status.is_success() {
            serde_json::from_slice(&bytes).map_err(JiraError::from)
        } else {
            Err(Self::parse_error(status, &bytes))
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

    fn parse_error(status: StatusCode, bytes: &[u8]) -> JiraError {
        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            return JiraError::Unauthorized;
        }
        if status == StatusCode::NOT_FOUND {
            return JiraError::NotFound {
                resource: String::from_utf8_lossy(bytes).into_owned(),
            };
        }
        if status == StatusCode::TOO_MANY_REQUESTS {
            return JiraError::RateLimited {
                retry_after_ms: 60_000,
            };
        }

        if let Ok(err_resp) = serde_json::from_slice::<ApiErrorResponse>(bytes) {
            let messages: Vec<String> = err_resp
                .error_messages
                .unwrap_or_default()
                .into_iter()
                .chain(
                    err_resp
                        .errors
                        .and_then(|e| {
                            if let serde_json::Value::Object(map) = e {
                                Some(
                                    map.into_iter()
                                        .map(|(k, v)| {
                                            format!("{k}: {}", v.as_str().unwrap_or(&v.to_string()))
                                        })
                                        .collect::<Vec<_>>(),
                                )
                            } else {
                                None
                            }
                        })
                        .unwrap_or_default(),
                )
                .collect();

            return JiraError::Api {
                message: if messages.is_empty() {
                    format!("HTTP {status}")
                } else {
                    messages.join("; ")
                },
                status_code: Some(status.as_u16()),
            };
        }

        JiraError::Api {
            message: format!("HTTP {status}: {}", String::from_utf8_lossy(bytes)),
            status_code: Some(status.as_u16()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    fn test_client(base_url: &str) -> JiraClient {
        JiraClient::new("test", "user@example.com", "token")
            .unwrap()
            .with_base_url(base_url)
            .with_agile_url(base_url)
            .with_retry_config(1, 10, 100)
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_issue() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/issue/PROJ-123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "10001",
                "key": "PROJ-123",
                "self": "https://example.atlassian.net/rest/api/3/issue/10001",
                "fields": {
                    "summary": "Test issue",
                    "status": { "name": "Open" }
                }
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&mock_server.uri());
        let issue = client.get_issue("PROJ-123", None, None).await.unwrap();
        assert_eq!(issue.key, "PROJ-123");
        assert_eq!(issue.id, "10001");
    }

    #[fcp_async_core::runtime::test]
    async fn test_create_issue() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/issue"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "id": "10002",
                "key": "PROJ-124",
                "self": "https://example.atlassian.net/rest/api/3/issue/10002"
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&mock_server.uri());
        let resp = client
            .create_issue(&serde_json::json!({
                "fields": {
                    "project": { "key": "PROJ" },
                    "summary": "New issue",
                    "issuetype": { "name": "Task" }
                }
            }))
            .await
            .unwrap();
        assert_eq!(resp.key, "PROJ-124");
    }

    #[fcp_async_core::runtime::test]
    async fn test_search_jql() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/search"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issues": [
                    { "id": "10001", "key": "PROJ-1", "fields": { "summary": "Bug" } },
                    { "id": "10002", "key": "PROJ-2", "fields": { "summary": "Feature" } }
                ],
                "total": 2,
                "maxResults": 50,
                "startAt": 0
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&mock_server.uri());
        let result = client
            .search_jql(&serde_json::json!({ "jql": "project = PROJ" }))
            .await
            .unwrap();
        assert_eq!(result.total, 2);
        assert_eq!(result.issues.len(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_transitions() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/issue/PROJ-1/transitions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "transitions": [
                    { "id": "11", "name": "To Do", "to": { "id": "1", "name": "To Do" } },
                    { "id": "21", "name": "In Progress", "to": { "id": "2", "name": "In Progress" } }
                ]
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&mock_server.uri());
        let result = client.list_transitions("PROJ-1").await.unwrap();
        assert_eq!(result.transitions.len(), 2);
        assert_eq!(result.transitions[0].name, "To Do");
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_sprints() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/board/42/sprint"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "values": [
                    { "id": 1, "name": "Sprint 1", "state": "active" },
                    { "id": 2, "name": "Sprint 2", "state": "future" }
                ],
                "isLast": true,
                "maxResults": 50,
                "startAt": 0
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&mock_server.uri());
        let result = client.list_sprints(42, None, None, None).await.unwrap();
        assert_eq!(result.values.len(), 2);
        assert_eq!(result.values[0].name, "Sprint 1");
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_comments() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/issue/PROJ-1/comment"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "comments": [
                    { "id": "100", "body": { "type": "doc", "content": [] }, "created": "2024-01-01T00:00:00.000+0000" }
                ],
                "total": 1,
                "startAt": 0,
                "maxResults": 50
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&mock_server.uri());
        let result = client
            .list_comments("PROJ-1", None, None, None)
            .await
            .unwrap();
        assert_eq!(result.total, 1);
        assert_eq!(result.comments.len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn test_unauthorized() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/issue/PROJ-1"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&mock_server)
            .await;

        let client = test_client(&mock_server.uri());
        let result = client.get_issue("PROJ-1", None, None).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), JiraError::Unauthorized));
    }

    #[fcp_async_core::runtime::test]
    async fn test_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/issue/PROJ-999"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "errorMessages": ["Issue does not exist or you do not have permission to see it."],
                "errors": {}
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&mock_server.uri());
        let result = client.get_issue("PROJ-999", None, None).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), JiraError::NotFound { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_rate_limited() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/issue/PROJ-1"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "30"))
            .mount(&mock_server)
            .await;

        let client = test_client(&mock_server.uri());
        let result = client.get_issue("PROJ-1", None, None).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), JiraError::RateLimited { .. }));
    }

    #[test]
    fn test_error_is_retryable() {
        let err = JiraError::RateLimited {
            retry_after_ms: 1000,
        };
        assert!(err.is_retryable());

        let err = JiraError::Unauthorized;
        assert!(!err.is_retryable());

        let err = JiraError::Api {
            message: "Server error".into(),
            status_code: Some(500),
        };
        assert!(err.is_retryable());

        let err = JiraError::NotFound {
            resource: "test".into(),
        };
        assert!(!err.is_retryable());
    }
}
