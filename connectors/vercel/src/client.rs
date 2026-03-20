use std::time::Duration;

use reqwest::{Client, RequestBuilder};
use serde_json::json;
use tracing::debug;

use fcp_sdk::migration::{AttemptOutcome, ConnectorRuntime, HttpRetryConfig, RetryLoop};

use crate::error::{VercelError, VercelResult};
use crate::types::*;

/// Vercel API client with retry support.
pub struct VercelClient {
    client: Client,
    base_url: String,
    auth: VercelAuth,
    team_id: Option<String>,
    retry_config: HttpRetryConfig,
}

impl std::fmt::Debug for VercelClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VercelClient")
            .field("base_url", &self.base_url)
            .field("auth", &self.auth)
            .field("team_id", &self.team_id)
            .finish()
    }
}

impl VercelClient {
    pub async fn new(
        base_url: &str,
        auth: VercelAuth,
        team_id: Option<String>,
        retry_config: HttpRetryConfig,
    ) -> VercelResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(VercelError::Http)?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            auth,
            team_id,
            retry_config,
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn is_secretless(&self) -> bool {
        self.auth.token.is_empty()
    }

    /// Append `?teamId=xxx` or `&teamId=xxx` if team_id is set.
    fn with_team(&self, url: &str) -> String {
        match &self.team_id {
            Some(tid) if !tid.is_empty() => {
                if url.contains('?') {
                    format!("{url}&teamId={tid}")
                } else {
                    format!("{url}?teamId={tid}")
                }
            }
            _ => url.to_string(),
        }
    }

    // ── Health check ──

    pub async fn health_check(&self, runtime: &ConnectorRuntime) -> VercelResult<User> {
        let resp: UserResponse = self
            .get_single(runtime, &format!("{}/v2/user", self.base_url))
            .await?;
        Ok(resp.user)
    }

    // ── Deployments ──

    pub async fn list_deployments(
        &self,
        runtime: &ConnectorRuntime,
        project_id: Option<&str>,
        limit: Option<u32>,
    ) -> VercelResult<Vec<Deployment>> {
        let mut url = format!("{}/v6/deployments", self.base_url);
        let mut params = Vec::new();
        if let Some(pid) = project_id {
            params.push(format!("projectId={pid}"));
        }
        if let Some(lim) = limit {
            params.push(format!("limit={lim}"));
        }
        if !params.is_empty() {
            url = format!("{url}?{}", params.join("&"));
        }
        let url = self.with_team(&url);
        self.get_typed::<DeploymentListResponse>(runtime, &url)
            .await
            .map(|r| r.deployments)
    }

    pub async fn get_deployment(
        &self,
        runtime: &ConnectorRuntime,
        deployment_id: &str,
    ) -> VercelResult<Deployment> {
        let url = format!("{}/v13/deployments/{deployment_id}", self.base_url);
        let url = self.with_team(&url);
        self.get_single(runtime, &url).await
    }

    pub async fn create_deployment(
        &self,
        runtime: &ConnectorRuntime,
        deployment: &CreateDeployment,
    ) -> VercelResult<Deployment> {
        let url = format!("{}/v13/deployments", self.base_url);
        let url = self.with_team(&url);
        let body = serde_json::to_value(deployment).unwrap_or(json!({}));
        self.post_json(runtime, &url, &body).await
    }

    pub async fn delete_deployment(
        &self,
        runtime: &ConnectorRuntime,
        deployment_id: &str,
    ) -> VercelResult<serde_json::Value> {
        let url = format!("{}/v13/deployments/{deployment_id}", self.base_url);
        let url = self.with_team(&url);
        self.delete(runtime, &url).await
    }

    // ── Projects ──

    pub async fn list_projects(
        &self,
        runtime: &ConnectorRuntime,
        limit: Option<u32>,
    ) -> VercelResult<Vec<Project>> {
        let mut url = format!("{}/v9/projects", self.base_url);
        if let Some(lim) = limit {
            url = format!("{url}?limit={lim}");
        }
        let url = self.with_team(&url);
        self.get_typed::<ProjectListResponse>(runtime, &url)
            .await
            .map(|r| r.projects)
    }

    pub async fn get_project(
        &self,
        runtime: &ConnectorRuntime,
        project_id: &str,
    ) -> VercelResult<Project> {
        let url = format!("{}/v9/projects/{project_id}", self.base_url);
        let url = self.with_team(&url);
        self.get_single(runtime, &url).await
    }

    pub async fn create_project(
        &self,
        runtime: &ConnectorRuntime,
        project: &CreateProject,
    ) -> VercelResult<Project> {
        let url = format!("{}/v10/projects", self.base_url);
        let url = self.with_team(&url);
        let body = serde_json::to_value(project).unwrap_or(json!({}));
        self.post_json(runtime, &url, &body).await
    }

    pub async fn delete_project(
        &self,
        runtime: &ConnectorRuntime,
        project_id: &str,
    ) -> VercelResult<serde_json::Value> {
        let url = format!("{}/v9/projects/{project_id}", self.base_url);
        let url = self.with_team(&url);
        self.delete(runtime, &url).await
    }

    // ── Domains ──

    pub async fn list_domains(
        &self,
        runtime: &ConnectorRuntime,
        project_id: &str,
    ) -> VercelResult<Vec<Domain>> {
        let url = format!(
            "{}/v9/projects/{project_id}/domains",
            self.base_url
        );
        let url = self.with_team(&url);
        self.get_typed::<DomainListResponse>(runtime, &url)
            .await
            .map(|r| r.domains)
    }

    pub async fn add_domain(
        &self,
        runtime: &ConnectorRuntime,
        project_id: &str,
        domain: &AddDomain,
    ) -> VercelResult<Domain> {
        let url = format!(
            "{}/v10/projects/{project_id}/domains",
            self.base_url
        );
        let url = self.with_team(&url);
        let body = serde_json::to_value(domain).unwrap_or(json!({}));
        self.post_json(runtime, &url, &body).await
    }

    pub async fn remove_domain(
        &self,
        runtime: &ConnectorRuntime,
        project_id: &str,
        domain_name: &str,
    ) -> VercelResult<serde_json::Value> {
        let url = format!(
            "{}/v9/projects/{project_id}/domains/{domain_name}",
            self.base_url
        );
        let url = self.with_team(&url);
        self.delete(runtime, &url).await
    }

    // ── Environment Variables ──

    pub async fn list_env_vars(
        &self,
        runtime: &ConnectorRuntime,
        project_id: &str,
    ) -> VercelResult<Vec<EnvVar>> {
        let url = format!(
            "{}/v10/projects/{project_id}/env",
            self.base_url
        );
        let url = self.with_team(&url);
        self.get_typed::<EnvVarListResponse>(runtime, &url)
            .await
            .map(|r| r.envs)
    }

    pub async fn create_env_var(
        &self,
        runtime: &ConnectorRuntime,
        project_id: &str,
        env_var: &CreateEnvVar,
    ) -> VercelResult<EnvVar> {
        let url = format!(
            "{}/v10/projects/{project_id}/env",
            self.base_url
        );
        let url = self.with_team(&url);
        let body = serde_json::to_value(env_var).unwrap_or(json!({}));
        self.post_json(runtime, &url, &body).await
    }

    pub async fn delete_env_var(
        &self,
        runtime: &ConnectorRuntime,
        project_id: &str,
        env_id: &str,
    ) -> VercelResult<serde_json::Value> {
        let url = format!(
            "{}/v10/projects/{project_id}/env/{env_id}",
            self.base_url
        );
        let url = self.with_team(&url);
        self.delete(runtime, &url).await
    }

    // ── Generic HTTP helpers ──

    async fn get_typed<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
    ) -> VercelResult<T> {
        let url = url.to_string();
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            async move {
                debug!(attempt, url = %url, "GET typed");
                let req = authenticate_request(client.get(&url), &auth);
                handle_response::<T>(req, attempt).await
            }
        })
        .await
    }

    async fn get_single<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
    ) -> VercelResult<T> {
        let url = url.to_string();
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            async move {
                debug!(attempt, url = %url, "GET single");
                let req = authenticate_request(client.get(&url), &auth);
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
    ) -> VercelResult<T> {
        let url = url.to_string();
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let body = body.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            let body = body.clone();
            async move {
                debug!(attempt, url = %url, "POST");
                let req = authenticate_request(client.post(&url), &auth).json(&body);
                handle_response::<T>(req, attempt).await
            }
        })
        .await
    }

    async fn delete<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
    ) -> VercelResult<T> {
        let url = url.to_string();
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            async move {
                debug!(attempt, url = %url, "DELETE");
                let req = authenticate_request(client.delete(&url), &auth);
                handle_response::<T>(req, attempt).await
            }
        })
        .await
    }
}

// ── Free functions for request handling ──

fn authenticate_request(req: RequestBuilder, auth: &VercelAuth) -> RequestBuilder {
    if auth.token.is_empty() {
        req
    } else {
        req.bearer_auth(&auth.token)
    }
}

async fn handle_response<T: serde::de::DeserializeOwned>(
    req: RequestBuilder,
    attempt: u32,
) -> AttemptOutcome<T, VercelError> {
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            return AttemptOutcome::Retryable {
                error: VercelError::Http(e),
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
            error: VercelError::RateLimited {
                retry_after_ms: retry_after
                    .unwrap_or(Duration::from_secs(60))
                    .as_millis() as u64,
            },
            retry_after,
        };
    }

    if status == 401 || status == 403 {
        return AttemptOutcome::Terminal(VercelError::Unauthorized(format!(
            "Authentication failed (HTTP {status})"
        )));
    }

    if status == 404 {
        return AttemptOutcome::Terminal(VercelError::NotFound(format!(
            "Resource not found (HTTP {status})"
        )));
    }

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        // Try to parse Vercel error envelope
        if let Ok(VercelErrorResponse {
            error: Some(api_err),
        }) = serde_json::from_str::<VercelErrorResponse>(&text)
        {
            let ve = VercelError::Api {
                code: api_err.code.unwrap_or_else(|| status.to_string()),
                message: api_err
                    .message
                    .unwrap_or_else(|| format!("HTTP {status}")),
            };
            if ve.is_retryable() {
                return AttemptOutcome::Retryable {
                    error: ve,
                    retry_after: None,
                };
            }
            return AttemptOutcome::Terminal(ve);
        }
        let err = VercelError::Api {
            code: status.to_string(),
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

    // For 204 No Content (delete responses), return empty JSON
    if status == 204 {
        match serde_json::from_str::<T>("{}") {
            Ok(v) => return AttemptOutcome::Success(v),
            Err(_) => {
                match serde_json::from_str::<T>("null") {
                    Ok(v) => return AttemptOutcome::Success(v),
                    Err(e) => return AttemptOutcome::Terminal(VercelError::Json(e)),
                }
            }
        }
    }

    let text = match resp.text().await {
        Ok(t) => t,
        Err(e) => return AttemptOutcome::Terminal(VercelError::Http(e)),
    };

    // Vercel API returns direct JSON (no envelope wrapper like Cloudflare)
    match serde_json::from_str::<T>(&text) {
        Ok(v) => AttemptOutcome::Success(v),
        Err(e) => {
            debug!(attempt, "Failed to parse response: {e}");
            AttemptOutcome::Terminal(VercelError::Json(e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_debug_redacts_auth() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            VercelClient::new(
                "https://api.vercel.com",
                VercelAuth {
                    token: "secret-token".into(),
                },
                None,
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
            VercelClient::new(
                "https://api.vercel.com",
                VercelAuth {
                    token: String::new(),
                },
                None,
                HttpRetryConfig::default(),
            )
            .await
            .unwrap()
        })
        .unwrap();
        assert!(rt.is_secretless());

        let rt2 = fcp_async_core::runtime::block_on_sync(async {
            VercelClient::new(
                "https://api.vercel.com",
                VercelAuth {
                    token: "token".into(),
                },
                None,
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
            VercelClient::new(
                "https://api.vercel.com/",
                VercelAuth {
                    token: "t".into(),
                },
                None,
                HttpRetryConfig::default(),
            )
            .await
            .unwrap()
        })
        .unwrap();
        assert!(!rt.base_url().ends_with('/'));
    }

    #[test]
    fn with_team_appends_query_param() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            VercelClient::new(
                "https://api.vercel.com",
                VercelAuth {
                    token: "t".into(),
                },
                Some("team_abc".into()),
                HttpRetryConfig::default(),
            )
            .await
            .unwrap()
        })
        .unwrap();
        let url = rt.with_team("https://api.vercel.com/v6/deployments");
        assert_eq!(
            url,
            "https://api.vercel.com/v6/deployments?teamId=team_abc"
        );
    }

    #[test]
    fn with_team_appends_ampersand_when_query_exists() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            VercelClient::new(
                "https://api.vercel.com",
                VercelAuth {
                    token: "t".into(),
                },
                Some("team_abc".into()),
                HttpRetryConfig::default(),
            )
            .await
            .unwrap()
        })
        .unwrap();
        let url = rt.with_team("https://api.vercel.com/v6/deployments?limit=10");
        assert_eq!(
            url,
            "https://api.vercel.com/v6/deployments?limit=10&teamId=team_abc"
        );
    }

    #[test]
    fn with_team_no_team_returns_original() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            VercelClient::new(
                "https://api.vercel.com",
                VercelAuth {
                    token: "t".into(),
                },
                None,
                HttpRetryConfig::default(),
            )
            .await
            .unwrap()
        })
        .unwrap();
        let url = rt.with_team("https://api.vercel.com/v6/deployments");
        assert_eq!(url, "https://api.vercel.com/v6/deployments");
    }

    #[test]
    fn with_team_empty_string_returns_original() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            VercelClient::new(
                "https://api.vercel.com",
                VercelAuth {
                    token: "t".into(),
                },
                Some(String::new()),
                HttpRetryConfig::default(),
            )
            .await
            .unwrap()
        })
        .unwrap();
        let url = rt.with_team("https://api.vercel.com/v6/deployments");
        assert_eq!(url, "https://api.vercel.com/v6/deployments");
    }
}
