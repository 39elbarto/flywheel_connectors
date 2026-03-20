use std::time::Duration;

use reqwest::{Client, RequestBuilder};
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

    fn team_query(&self) -> String {
        self.team_id
            .as_ref()
            .map_or_else(String::new, |id| format!("?teamId={id}"))
    }

    // ── Health check (get authenticated user) ──

    pub async fn health_check(&self, runtime: &ConnectorRuntime) -> VercelResult<User> {
        let url = format!("{}/v2/user", self.base_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        let resp: UserResponse = RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            async move {
                debug!(attempt, "Verifying Vercel token");
                let req = authenticate_request(client.get(&url), &auth);
                handle_response::<UserResponse>(req, attempt).await
            }
        })
        .await?;
        Ok(resp.user)
    }

    // ── Projects ──

    pub async fn list_projects(&self, runtime: &ConnectorRuntime) -> VercelResult<Vec<Project>> {
        let url = format!("{}/v9/projects{}", self.base_url, self.team_query());
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            async move {
                debug!(attempt, "Listing projects");
                let req = authenticate_request(client.get(&url), &auth);
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
                if let Some(outcome) = check_error_status::<Vec<Project>>(status) {
                    return outcome;
                }
                match resp.json::<ProjectsResponse>().await {
                    Ok(resp) => AttemptOutcome::Success(resp.projects),
                    Err(e) => AttemptOutcome::Terminal(VercelError::Http(e)),
                }
            }
        })
        .await
    }

    pub async fn get_project(
        &self,
        runtime: &ConnectorRuntime,
        project_id: &str,
    ) -> VercelResult<Project> {
        let url = format!(
            "{}/v9/projects/{project_id}{}",
            self.base_url,
            self.team_query()
        );
        self.get_single(runtime, &url).await
    }

    // ── Deployments ──

    pub async fn list_deployments(
        &self,
        runtime: &ConnectorRuntime,
        project_id: &str,
    ) -> VercelResult<Vec<Deployment>> {
        let sep = if self.team_id.is_some() { "&" } else { "?" };
        let url = format!(
            "{}/v6/deployments{}{sep}projectId={project_id}",
            self.base_url,
            self.team_query()
        );
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            async move {
                debug!(attempt, "Listing deployments");
                let req = authenticate_request(client.get(&url), &auth);
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
                if let Some(outcome) = check_error_status::<Vec<Deployment>>(status) {
                    return outcome;
                }
                match resp.json::<DeploymentsResponse>().await {
                    Ok(resp) => AttemptOutcome::Success(resp.deployments),
                    Err(e) => AttemptOutcome::Terminal(VercelError::Http(e)),
                }
            }
        })
        .await
    }

    pub async fn get_deployment(
        &self,
        runtime: &ConnectorRuntime,
        deployment_id: &str,
    ) -> VercelResult<Deployment> {
        let url = format!(
            "{}/v13/deployments/{deployment_id}{}",
            self.base_url,
            self.team_query()
        );
        self.get_single(runtime, &url).await
    }

    pub async fn create_deployment(
        &self,
        runtime: &ConnectorRuntime,
        body: &serde_json::Value,
    ) -> VercelResult<Deployment> {
        let url = format!(
            "{}/v13/deployments{}",
            self.base_url,
            self.team_query()
        );
        self.post_json(runtime, &url, body).await
    }

    pub async fn cancel_deployment(
        &self,
        runtime: &ConnectorRuntime,
        deployment_id: &str,
    ) -> VercelResult<Deployment> {
        let url = format!(
            "{}/v12/deployments/{deployment_id}/cancel{}",
            self.base_url,
            self.team_query()
        );
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            async move {
                debug!(attempt, "Cancelling deployment");
                let req = authenticate_request(client.patch(&url), &auth);
                handle_response::<Deployment>(req, attempt).await
            }
        })
        .await
    }

    // ── Domains ──

    pub async fn list_domains(&self, runtime: &ConnectorRuntime) -> VercelResult<Vec<Domain>> {
        let url = format!("{}/v5/domains{}", self.base_url, self.team_query());
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            async move {
                debug!(attempt, "Listing domains");
                let req = authenticate_request(client.get(&url), &auth);
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
                if let Some(outcome) = check_error_status::<Vec<Domain>>(status) {
                    return outcome;
                }
                match resp.json::<DomainsResponse>().await {
                    Ok(resp) => AttemptOutcome::Success(resp.domains),
                    Err(e) => AttemptOutcome::Terminal(VercelError::Http(e)),
                }
            }
        })
        .await
    }

    pub async fn get_domain(
        &self,
        runtime: &ConnectorRuntime,
        domain_name: &str,
    ) -> VercelResult<Domain> {
        let url = format!(
            "{}/v5/domains/{domain_name}{}",
            self.base_url,
            self.team_query()
        );
        self.get_single(runtime, &url).await
    }

    // ── Environment Variables ──

    pub async fn list_env_vars(
        &self,
        runtime: &ConnectorRuntime,
        project_id: &str,
    ) -> VercelResult<Vec<EnvVar>> {
        let url = format!(
            "{}/v9/projects/{project_id}/env{}",
            self.base_url,
            self.team_query()
        );
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            async move {
                debug!(attempt, "Listing env vars");
                let req = authenticate_request(client.get(&url), &auth);
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
                if let Some(outcome) = check_error_status::<Vec<EnvVar>>(status) {
                    return outcome;
                }
                match resp.json::<EnvVarsResponse>().await {
                    Ok(resp) => AttemptOutcome::Success(resp.envs),
                    Err(e) => AttemptOutcome::Terminal(VercelError::Http(e)),
                }
            }
        })
        .await
    }

    pub async fn set_env_var(
        &self,
        runtime: &ConnectorRuntime,
        project_id: &str,
        body: &serde_json::Value,
    ) -> VercelResult<EnvVar> {
        let url = format!(
            "{}/v10/projects/{project_id}/env{}",
            self.base_url,
            self.team_query()
        );
        self.post_json(runtime, &url, body).await
    }

    // ── Generic HTTP helpers ──

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
}

// ── Free functions for request handling ──

fn authenticate_request(req: RequestBuilder, auth: &VercelAuth) -> RequestBuilder {
    if auth.token.is_empty() {
        req
    } else {
        req.bearer_auth(&auth.token)
    }
}

fn check_error_status<T>(status: u16) -> Option<AttemptOutcome<T, VercelError>> {
    if status == 429 {
        return Some(AttemptOutcome::Retryable {
            error: VercelError::RateLimited {
                retry_after_ms: 60_000,
            },
            retry_after: Some(Duration::from_secs(60)),
        });
    }
    if status == 401 || status == 403 {
        return Some(AttemptOutcome::Terminal(VercelError::Unauthorized(
            format!("Authentication failed (HTTP {status})"),
        )));
    }
    if status == 404 {
        return Some(AttemptOutcome::Terminal(VercelError::NotFound(format!(
            "Resource not found (HTTP {status})"
        ))));
    }
    None
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
        let err = VercelError::Api {
            code: u32::from(status),
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
        Err(e) => return AttemptOutcome::Terminal(VercelError::Http(e)),
    };

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
    fn team_query_with_team() {
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
        assert_eq!(rt.team_query(), "?teamId=team_abc");
    }

    #[test]
    fn team_query_without_team() {
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
        assert_eq!(rt.team_query(), "");
    }
}
