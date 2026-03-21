//! CircleCI API client with retry support.

use fcp_sdk::migration::{
    AttemptOutcome, ConnectorRuntime, HttpRetryConfig, RetryLoop, classify_http_status,
};
use fcp_sdk::retry::RetryDecision;
use reqwest::Client;
use std::time::Duration;
use tracing::{debug, warn};

use crate::error::{Error, Result};
use crate::types::{
    ApiErrorResponse, Job, MessageResponse, PaginatedResponse, Pipeline, Project, Workflow,
};

/// CircleCI API client with retry and runtime integration.
pub struct CircleCiClient {
    client: Client,
    base_url: String,
    api_token: String,
    retry_config: HttpRetryConfig,
}

impl std::fmt::Debug for CircleCiClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CircleCiClient")
            .field("base_url", &self.base_url)
            .field("api_token", &"[REDACTED]")
            .field("retry_config", &self.retry_config)
            .finish()
    }
}

/// Sanitize a path segment to prevent path traversal.
fn sanitize_path_segment(segment: &str) -> Result<&str> {
    if segment.is_empty()
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

impl CircleCiClient {
    /// Create a new CircleCI client.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be built.
    pub fn new(
        base_url: &str,
        api_token: &str,
        retry_config: HttpRetryConfig,
        request_timeout_ms: u64,
    ) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_millis(request_timeout_ms))
            .build()
            .map_err(Error::Http)?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            api_token: api_token.to_string(),
            retry_config,
        })
    }

    /// List pipelines for a project slug (e.g., "gh/org/repo").
    pub async fn list_pipelines(
        &self,
        runtime: &ConnectorRuntime,
        project_slug: &str,
        page_token: Option<&str>,
    ) -> Result<PaginatedResponse<Pipeline>> {
        // project_slug contains slashes by design (gh/org/repo), so we validate parts
        for part in project_slug.split('/') {
            sanitize_path_segment(part)?;
        }
        let url = format!("{}/project/{}/pipeline", self.base_url, project_slug);
        let mut query = Vec::new();
        if let Some(token) = page_token {
            query.push(("page-token", token.to_string()));
        }
        self.get_with_retry(runtime, &url, &query).await
    }

    /// Get a pipeline by ID.
    pub async fn get_pipeline(
        &self,
        runtime: &ConnectorRuntime,
        pipeline_id: &str,
    ) -> Result<Pipeline> {
        let id = sanitize_path_segment(pipeline_id)?;
        let url = format!("{}/pipeline/{id}", self.base_url);
        self.get_with_retry::<Pipeline>(runtime, &url, &[]).await
    }

    /// Trigger a new pipeline.
    pub async fn trigger_pipeline(
        &self,
        runtime: &ConnectorRuntime,
        project_slug: &str,
        body: &serde_json::Value,
    ) -> Result<Pipeline> {
        for part in project_slug.split('/') {
            sanitize_path_segment(part)?;
        }
        let url = format!("{}/project/{}/pipeline", self.base_url, project_slug);
        self.post_with_retry(runtime, &url, body).await
    }

    /// List workflows for a pipeline.
    pub async fn list_workflows(
        &self,
        runtime: &ConnectorRuntime,
        pipeline_id: &str,
        page_token: Option<&str>,
    ) -> Result<PaginatedResponse<Workflow>> {
        let id = sanitize_path_segment(pipeline_id)?;
        let url = format!("{}/pipeline/{id}/workflow", self.base_url);
        let mut query = Vec::new();
        if let Some(token) = page_token {
            query.push(("page-token", token.to_string()));
        }
        self.get_with_retry(runtime, &url, &query).await
    }

    /// Get a workflow by ID.
    pub async fn get_workflow(
        &self,
        runtime: &ConnectorRuntime,
        workflow_id: &str,
    ) -> Result<Workflow> {
        let id = sanitize_path_segment(workflow_id)?;
        let url = format!("{}/workflow/{id}", self.base_url);
        self.get_with_retry::<Workflow>(runtime, &url, &[]).await
    }

    /// Cancel a workflow.
    pub async fn cancel_workflow(
        &self,
        runtime: &ConnectorRuntime,
        workflow_id: &str,
    ) -> Result<MessageResponse> {
        let id = sanitize_path_segment(workflow_id)?;
        let url = format!("{}/workflow/{id}/cancel", self.base_url);
        self.post_with_retry(runtime, &url, &serde_json::json!({}))
            .await
    }

    /// Rerun a workflow.
    pub async fn rerun_workflow(
        &self,
        runtime: &ConnectorRuntime,
        workflow_id: &str,
        from_failed: bool,
    ) -> Result<MessageResponse> {
        let id = sanitize_path_segment(workflow_id)?;
        let url = format!("{}/workflow/{id}/rerun", self.base_url);
        let body = serde_json::json!({ "from_failed": from_failed });
        self.post_with_retry(runtime, &url, &body).await
    }

    /// List jobs for a workflow.
    pub async fn list_jobs(
        &self,
        runtime: &ConnectorRuntime,
        workflow_id: &str,
        page_token: Option<&str>,
    ) -> Result<PaginatedResponse<Job>> {
        let id = sanitize_path_segment(workflow_id)?;
        let url = format!("{}/workflow/{id}/job", self.base_url);
        let mut query = Vec::new();
        if let Some(token) = page_token {
            query.push(("page-token", token.to_string()));
        }
        self.get_with_retry(runtime, &url, &query).await
    }

    /// Get a single job by project slug and job number.
    pub async fn get_job(
        &self,
        runtime: &ConnectorRuntime,
        project_slug: &str,
        job_number: u64,
    ) -> Result<Job> {
        for part in project_slug.split('/') {
            sanitize_path_segment(part)?;
        }
        let url = format!(
            "{}/project/{}/job/{}",
            self.base_url, project_slug, job_number
        );
        self.get_with_retry::<Job>(runtime, &url, &[]).await
    }

    /// List projects the user follows.
    pub async fn list_projects(
        &self,
        runtime: &ConnectorRuntime,
        page_token: Option<&str>,
    ) -> Result<PaginatedResponse<Project>> {
        let url = format!("{}/me/collaborations", self.base_url);
        let mut query = Vec::new();
        if let Some(token) = page_token {
            query.push(("page-token", token.to_string()));
        }
        // /me/collaborations returns a flat array, but we wrap it
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let token = self.api_token.clone();
            let query = query.clone();
            async move {
                debug!(attempt, "GET {}", url);
                let mut req = client.get(&url).header("Circle-Token", &token);
                for (k, v) in &query {
                    req = req.query(&[(k, v)]);
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
                handle_response_as_list(resp).await
            }
        })
        .await
    }

    /// Health check: validate API reachability.
    pub async fn health_check(&self) -> Result<()> {
        let url = format!("{}/me", self.base_url);
        let resp = self
            .client
            .get(&url)
            .header("Circle-Token", &self.api_token)
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
            Err(Error::Unauthorized("Invalid API token".into()))
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

    /// Generic GET with retry, returning deserialized JSON.
    async fn get_with_retry<T: serde::de::DeserializeOwned>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
        query: &[(&str, String)],
    ) -> Result<T> {
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.to_string();
            let client = self.client.clone();
            let token = self.api_token.clone();
            let query: Vec<(String, String)> = query
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect();
            async move {
                debug!(attempt, "GET {}", url);
                let mut req = client.get(&url).header("Circle-Token", &token);
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

    /// Generic POST with retry, returning deserialized JSON.
    async fn post_with_retry<T: serde::de::DeserializeOwned>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
        body: &serde_json::Value,
    ) -> Result<T> {
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let body_clone = body.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.to_string();
            let client = self.client.clone();
            let token = self.api_token.clone();
            let body = body_clone.clone();
            async move {
                debug!(attempt, "POST {}", url);
                let resp = match client
                    .post(&url)
                    .header("Circle-Token", &token)
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
        return AttemptOutcome::Terminal(Error::Unauthorized("Invalid API token".into()));
    }

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        warn!(status, "CircleCI request failed");
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

/// Handle response returning a JSON array and wrapping it in a paginated envelope.
async fn handle_response_as_list<T: serde::de::DeserializeOwned>(
    resp: reqwest::Response,
) -> AttemptOutcome<PaginatedResponse<T>, Error> {
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
        return AttemptOutcome::Terminal(Error::Unauthorized("Invalid API token".into()));
    }

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        warn!(status, "CircleCI request failed");
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

    // Try paginated first, then raw array
    let text = match resp.text().await {
        Ok(t) => t,
        Err(e) => return AttemptOutcome::Terminal(Error::Http(e)),
    };

    if let Ok(paginated) = serde_json::from_str::<PaginatedResponse<T>>(&text) {
        return AttemptOutcome::Success(paginated);
    }

    match serde_json::from_str::<Vec<T>>(&text) {
        Ok(items) => AttemptOutcome::Success(PaginatedResponse {
            items,
            next_page_token: None,
        }),
        Err(e) => AttemptOutcome::Terminal(Error::Json(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn client_creation() {
        let client = CircleCiClient::new(
            "https://circleci.com/api/v2",
            "test_token",
            HttpRetryConfig::default(),
            30_000,
        );
        assert!(client.is_ok());
    }

    #[test]
    fn base_url_trimmed() {
        let client = CircleCiClient::new(
            "https://circleci.com/api/v2/",
            "test_token",
            HttpRetryConfig::default(),
            30_000,
        )
        .unwrap();
        assert!(!client.base_url().ends_with('/'));
    }

    #[test]
    fn secretless_detection() {
        let client = CircleCiClient::new(
            "https://circleci.com/api/v2",
            "",
            HttpRetryConfig::default(),
            30_000,
        )
        .unwrap();
        assert!(client.is_secretless());
    }

    #[test]
    fn debug_redacts_api_token() {
        let client = CircleCiClient::new(
            "https://circleci.com/api/v2",
            "super_secret_token",
            HttpRetryConfig::default(),
            30_000,
        )
        .unwrap();
        let debug_output = format!("{client:?}");
        assert!(!debug_output.contains("super_secret_token"));
        assert!(debug_output.contains("[REDACTED]"));
    }

    #[test]
    fn non_secretless() {
        let client = CircleCiClient::new(
            "https://circleci.com/api/v2",
            "real_token",
            HttpRetryConfig::default(),
            30_000,
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
        assert!(sanitize_path_segment("pipeline-123").is_ok());
        assert!(sanitize_path_segment("abc").is_ok());
        assert!(sanitize_path_segment("gh").is_ok());
    }

    #[fcp_async_core::runtime::test]
    async fn health_check_success() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/me"))
            .and(header("Circle-Token", "test_token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"id": "u1"})))
            .mount(&mock_server)
            .await;

        let client = CircleCiClient::new(
            &mock_server.uri(),
            "test_token",
            HttpRetryConfig::default(),
            30_000,
        )
        .unwrap();
        assert!(client.health_check().await.is_ok());
    }

    #[fcp_async_core::runtime::test]
    async fn health_check_unauthorized() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/me"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&mock_server)
            .await;

        let client = CircleCiClient::new(
            &mock_server.uri(),
            "bad_token",
            HttpRetryConfig::default(),
            30_000,
        )
        .unwrap();
        let err = client.health_check().await.unwrap_err();
        assert!(matches!(err, Error::Unauthorized(_)));
    }

    #[fcp_async_core::runtime::test]
    async fn health_check_rate_limited() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/me"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "60"))
            .mount(&mock_server)
            .await;

        let client = CircleCiClient::new(
            &mock_server.uri(),
            "test_token",
            HttpRetryConfig::default(),
            30_000,
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

    #[fcp_async_core::runtime::test]
    async fn health_check_respects_configured_timeout() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/me"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_millis(250))
                    .set_body_json(serde_json::json!({"id": "u1"})),
            )
            .mount(&mock_server)
            .await;

        let client = CircleCiClient::new(
            &mock_server.uri(),
            "test_token",
            HttpRetryConfig::default(),
            50,
        )
        .unwrap();
        let err = client.health_check().await.unwrap_err();
        assert!(matches!(err, Error::Http(_)));
    }
}
