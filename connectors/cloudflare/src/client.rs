use std::time::Duration;

use reqwest::{Client, RequestBuilder};
use serde_json::json;
use tracing::debug;

use fcp_sdk::migration::{AttemptOutcome, ConnectorRuntime, HttpRetryConfig, RetryLoop};

use crate::error::{CloudflareError, CloudflareResult};
use crate::types::*;

/// Cloudflare API client with retry support.
pub struct CloudflareClient {
    client: Client,
    base_url: String,
    auth: CloudflareAuth,
    account_id: String,
    retry_config: HttpRetryConfig,
}

impl std::fmt::Debug for CloudflareClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareClient")
            .field("base_url", &self.base_url)
            .field("auth", &self.auth)
            .field("account_id", &self.account_id)
            .finish()
    }
}

impl CloudflareClient {
    pub async fn new(
        base_url: &str,
        auth: CloudflareAuth,
        account_id: &str,
        retry_config: HttpRetryConfig,
    ) -> CloudflareResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(CloudflareError::Http)?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            auth,
            account_id: account_id.to_string(),
            retry_config,
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn is_secretless(&self) -> bool {
        self.auth.is_secretless()
    }

    // ── Health check ──

    pub async fn health_check(&self, runtime: &ConnectorRuntime) -> CloudflareResult<VerifyToken> {
        let url = format!("{}/user/tokens/verify", self.base_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            async move {
                debug!(attempt, "Verifying Cloudflare token");
                let req = authenticate_request(client.get(&url), &auth);
                handle_response::<VerifyToken>(req, attempt).await
            }
        })
        .await
    }

    // ── Zones ──

    pub async fn list_zones(&self, runtime: &ConnectorRuntime) -> CloudflareResult<Vec<Zone>> {
        let url = format!("{}/zones", self.base_url);
        self.get_list(runtime, &url).await
    }

    // ── DNS ──

    pub async fn list_dns_records(
        &self,
        runtime: &ConnectorRuntime,
        zone_id: &str,
    ) -> CloudflareResult<Vec<DnsRecord>> {
        let url = format!("{}/zones/{zone_id}/dns_records", self.base_url);
        self.get_list(runtime, &url).await
    }

    pub async fn create_dns_record(
        &self,
        runtime: &ConnectorRuntime,
        zone_id: &str,
        record: &CreateDnsRecord,
    ) -> CloudflareResult<DnsRecord> {
        let url = format!("{}/zones/{zone_id}/dns_records", self.base_url);
        self.post_json(
            runtime,
            &url,
            &serde_json::to_value(record).unwrap_or(json!({})),
        )
        .await
    }

    pub async fn update_dns_record(
        &self,
        runtime: &ConnectorRuntime,
        zone_id: &str,
        record_id: &str,
        record: &UpdateDnsRecord,
    ) -> CloudflareResult<DnsRecord> {
        let url = format!("{}/zones/{zone_id}/dns_records/{record_id}", self.base_url);
        self.put_json(
            runtime,
            &url,
            &serde_json::to_value(record).unwrap_or(json!({})),
        )
        .await
    }

    pub async fn delete_dns_record(
        &self,
        runtime: &ConnectorRuntime,
        zone_id: &str,
        record_id: &str,
    ) -> CloudflareResult<serde_json::Value> {
        let url = format!("{}/zones/{zone_id}/dns_records/{record_id}", self.base_url);
        self.delete(runtime, &url).await
    }

    // ── Workers ──

    pub async fn list_workers(&self, runtime: &ConnectorRuntime) -> CloudflareResult<Vec<Worker>> {
        let url = format!(
            "{}/accounts/{}/workers/scripts",
            self.base_url, self.account_id
        );
        self.get_list(runtime, &url).await
    }

    pub async fn get_worker(
        &self,
        runtime: &ConnectorRuntime,
        script_name: &str,
    ) -> CloudflareResult<WorkerScript> {
        let url = format!(
            "{}/accounts/{}/workers/scripts/{script_name}",
            self.base_url, self.account_id
        );
        self.get_single(runtime, &url).await
    }

    pub async fn deploy_worker(
        &self,
        runtime: &ConnectorRuntime,
        script_name: &str,
        script_content: &str,
    ) -> CloudflareResult<WorkerScript> {
        let url = format!(
            "{}/accounts/{}/workers/scripts/{script_name}",
            self.base_url, self.account_id
        );
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let content = script_content.to_string();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            let body = content.clone();
            async move {
                debug!(attempt, script_name, "Deploying worker");
                let req = authenticate_request(client.put(&url), &auth)
                    .header("Content-Type", "application/javascript")
                    .body(body);
                handle_response::<WorkerScript>(req, attempt).await
            }
        })
        .await
    }

    pub async fn delete_worker(
        &self,
        runtime: &ConnectorRuntime,
        script_name: &str,
    ) -> CloudflareResult<serde_json::Value> {
        let url = format!(
            "{}/accounts/{}/workers/scripts/{script_name}",
            self.base_url, self.account_id
        );
        self.delete(runtime, &url).await
    }

    // ── Pages ──

    pub async fn list_pages_projects(
        &self,
        runtime: &ConnectorRuntime,
    ) -> CloudflareResult<Vec<PagesProject>> {
        let url = format!(
            "{}/accounts/{}/pages/projects",
            self.base_url, self.account_id
        );
        self.get_list(runtime, &url).await
    }

    pub async fn create_pages_deployment(
        &self,
        runtime: &ConnectorRuntime,
        project_name: &str,
        branch: &str,
    ) -> CloudflareResult<PagesDeployment> {
        let url = format!(
            "{}/accounts/{}/pages/projects/{project_name}/deployments",
            self.base_url, self.account_id
        );
        let body = json!({ "branch": branch });
        self.post_json(runtime, &url, &body).await
    }

    // ── KV ──

    pub async fn kv_get(
        &self,
        runtime: &ConnectorRuntime,
        namespace_id: &str,
        key: &str,
    ) -> CloudflareResult<String> {
        let url = format!(
            "{}/accounts/{}/storage/kv/namespaces/{namespace_id}/values/{key}",
            self.base_url, self.account_id
        );
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            async move {
                debug!(attempt, key, "KV get");
                let req = authenticate_request(client.get(&url), &auth);
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: CloudflareError::Http(e),
                            retry_after: None,
                        };
                    }
                };
                let status = resp.status().as_u16();
                if let Some(outcome) = check_error_status::<String>(status, &resp).await {
                    return outcome;
                }
                match resp.text().await {
                    Ok(text) => AttemptOutcome::Success(text),
                    Err(e) => AttemptOutcome::Terminal(CloudflareError::Http(e)),
                }
            }
        })
        .await
    }

    pub async fn kv_put(
        &self,
        runtime: &ConnectorRuntime,
        namespace_id: &str,
        key: &str,
        value: &str,
    ) -> CloudflareResult<serde_json::Value> {
        let url = format!(
            "{}/accounts/{}/storage/kv/namespaces/{namespace_id}/values/{key}",
            self.base_url, self.account_id
        );
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let val = value.to_string();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            let body = val.clone();
            async move {
                debug!(attempt, key, "KV put");
                let req = authenticate_request(client.put(&url), &auth).body(body);
                handle_response::<serde_json::Value>(req, attempt).await
            }
        })
        .await
    }

    pub async fn kv_delete(
        &self,
        runtime: &ConnectorRuntime,
        namespace_id: &str,
        key: &str,
    ) -> CloudflareResult<serde_json::Value> {
        let url = format!(
            "{}/accounts/{}/storage/kv/namespaces/{namespace_id}/values/{key}",
            self.base_url, self.account_id
        );
        self.delete(runtime, &url).await
    }

    // ── Generic HTTP helpers ──

    async fn get_list<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
    ) -> CloudflareResult<Vec<T>> {
        let url = url.to_string();
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            async move {
                debug!(attempt, url = %url, "GET list");
                let req = authenticate_request(client.get(&url), &auth);
                handle_list_response::<T>(req, attempt).await
            }
        })
        .await
    }

    async fn get_single<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
    ) -> CloudflareResult<T> {
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
    ) -> CloudflareResult<T> {
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

    async fn put_json<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
        body: &serde_json::Value,
    ) -> CloudflareResult<T> {
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
                debug!(attempt, url = %url, "PUT");
                let req = authenticate_request(client.put(&url), &auth).json(&body);
                handle_response::<T>(req, attempt).await
            }
        })
        .await
    }

    async fn delete<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
    ) -> CloudflareResult<T> {
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

fn authenticate_request(req: RequestBuilder, auth: &CloudflareAuth) -> RequestBuilder {
    match auth {
        CloudflareAuth::ApiToken { api_token } => {
            if api_token.is_empty() {
                req
            } else {
                req.bearer_auth(api_token)
            }
        }
        CloudflareAuth::ApiKey { api_key, email } => {
            if api_key.is_empty() {
                req
            } else {
                req.header("X-Auth-Key", api_key.as_str())
                    .header("X-Auth-Email", email.as_str())
            }
        }
    }
}

async fn check_error_status<T>(
    status: u16,
    _resp: &reqwest::Response,
) -> Option<AttemptOutcome<T, CloudflareError>> {
    if status == 429 {
        return Some(AttemptOutcome::Retryable {
            error: CloudflareError::RateLimited {
                retry_after_ms: 30_000,
            },
            retry_after: Some(Duration::from_secs(30)),
        });
    }
    if status == 401 || status == 403 {
        return Some(AttemptOutcome::Terminal(CloudflareError::Unauthorized(
            format!("Authentication failed (HTTP {status})"),
        )));
    }
    if status == 404 {
        return Some(AttemptOutcome::Terminal(CloudflareError::NotFound(
            format!("Resource not found (HTTP {status})"),
        )));
    }
    None
}

async fn handle_response<T: serde::de::DeserializeOwned>(
    req: RequestBuilder,
    attempt: u32,
) -> AttemptOutcome<T, CloudflareError> {
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            return AttemptOutcome::Retryable {
                error: CloudflareError::Http(e),
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
            error: CloudflareError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(Duration::from_secs(30)).as_millis() as u64,
            },
            retry_after,
        };
    }

    if status == 401 || status == 403 {
        return AttemptOutcome::Terminal(CloudflareError::Unauthorized(format!(
            "Authentication failed (HTTP {status})"
        )));
    }

    if status == 404 {
        return AttemptOutcome::Terminal(CloudflareError::NotFound(format!(
            "Resource not found (HTTP {status})"
        )));
    }

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        let err = CloudflareError::Api {
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

    // Parse the Cloudflare API envelope
    let text = match resp.text().await {
        Ok(t) => t,
        Err(e) => return AttemptOutcome::Terminal(CloudflareError::Http(e)),
    };

    // Try to parse as CloudflareResponse<T> first
    if let Ok(cf_resp) = serde_json::from_str::<CloudflareResponse<T>>(&text) {
        if cf_resp.success
            && let Some(result) = cf_resp.result
        {
            return AttemptOutcome::Success(result);
        }
        if !cf_resp.errors.is_empty() {
            let err = &cf_resp.errors[0];
            let cf_err = CloudflareError::Api {
                code: err.code,
                message: err.message.clone(),
            };
            if cf_err.is_retryable() {
                return AttemptOutcome::Retryable {
                    error: cf_err,
                    retry_after: None,
                };
            }
            return AttemptOutcome::Terminal(cf_err);
        }
    }

    // Fallback: try to parse as raw T
    match serde_json::from_str::<T>(&text) {
        Ok(v) => AttemptOutcome::Success(v),
        Err(e) => {
            debug!(attempt, "Failed to parse response: {e}");
            AttemptOutcome::Terminal(CloudflareError::Json(e))
        }
    }
}

async fn handle_list_response<T: serde::de::DeserializeOwned>(
    req: RequestBuilder,
    attempt: u32,
) -> AttemptOutcome<Vec<T>, CloudflareError> {
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            return AttemptOutcome::Retryable {
                error: CloudflareError::Http(e),
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
            error: CloudflareError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(Duration::from_secs(30)).as_millis() as u64,
            },
            retry_after,
        };
    }

    if status == 401 || status == 403 {
        return AttemptOutcome::Terminal(CloudflareError::Unauthorized(format!(
            "Authentication failed (HTTP {status})"
        )));
    }

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        let err = CloudflareError::Api {
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
        Err(e) => return AttemptOutcome::Terminal(CloudflareError::Http(e)),
    };

    if let Ok(cf_resp) = serde_json::from_str::<CloudflareResponse<Vec<T>>>(&text) {
        if cf_resp.success {
            return AttemptOutcome::Success(cf_resp.result.unwrap_or_default());
        }
        if !cf_resp.errors.is_empty() {
            let err = &cf_resp.errors[0];
            return AttemptOutcome::Terminal(CloudflareError::Api {
                code: err.code,
                message: err.message.clone(),
            });
        }
    }

    match serde_json::from_str::<Vec<T>>(&text) {
        Ok(v) => AttemptOutcome::Success(v),
        Err(e) => {
            debug!(attempt, "Failed to parse list response: {e}");
            AttemptOutcome::Terminal(CloudflareError::Json(e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_debug_redacts_auth() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            CloudflareClient::new(
                "https://api.cloudflare.com/client/v4",
                CloudflareAuth::ApiToken {
                    api_token: "secret-token".into(),
                },
                "acc123",
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
            CloudflareClient::new(
                "https://api.cloudflare.com/client/v4",
                CloudflareAuth::ApiToken {
                    api_token: String::new(),
                },
                "acc123",
                HttpRetryConfig::default(),
            )
            .await
            .unwrap()
        })
        .unwrap();
        assert!(rt.is_secretless());

        let rt2 = fcp_async_core::runtime::block_on_sync(async {
            CloudflareClient::new(
                "https://api.cloudflare.com/client/v4",
                CloudflareAuth::ApiToken {
                    api_token: "token".into(),
                },
                "acc123",
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
            CloudflareClient::new(
                "https://api.cloudflare.com/client/v4/",
                CloudflareAuth::ApiToken {
                    api_token: "t".into(),
                },
                "acc123",
                HttpRetryConfig::default(),
            )
            .await
            .unwrap()
        })
        .unwrap();
        assert!(!rt.base_url().ends_with('/'));
    }

    #[test]
    fn api_key_auth_secretless() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            CloudflareClient::new(
                "https://api.cloudflare.com/client/v4",
                CloudflareAuth::ApiKey {
                    api_key: String::new(),
                    email: "user@example.com".into(),
                },
                "acc123",
                HttpRetryConfig::default(),
            )
            .await
            .unwrap()
        })
        .unwrap();
        assert!(rt.is_secretless());
    }
}
