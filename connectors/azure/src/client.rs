use std::time::Duration;

use reqwest::{Client, RequestBuilder};
use tracing::debug;

use fcp_sdk::migration::{AttemptOutcome, ConnectorRuntime, HttpRetryConfig, RetryLoop};

use crate::error::{AzureError, AzureResult};
use crate::types::*;

const API_VERSION_COMPUTE: &str = "2023-09-01";
const API_VERSION_STORAGE: &str = "2023-05-01";
const API_VERSION_WEB: &str = "2023-12-01";
const API_VERSION_SUBSCRIPTION: &str = "2022-12-01";

/// Azure REST API client with retry support.
pub struct AzureClient {
    client: Client,
    management_url: String,
    auth: AzureAuth,
    subscription_id: String,
    retry_config: HttpRetryConfig,
}

impl std::fmt::Debug for AzureClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AzureClient")
            .field("management_url", &self.management_url)
            .field("auth", &self.auth)
            .field("subscription_id", &self.subscription_id)
            .finish()
    }
}

impl AzureClient {
    pub async fn new(
        management_url: &str,
        auth: AzureAuth,
        retry_config: HttpRetryConfig,
    ) -> AzureResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(AzureError::Http)?;

        let subscription_id = auth.subscription_id.clone();

        Ok(Self {
            client,
            management_url: management_url.trim_end_matches('/').to_string(),
            auth,
            subscription_id,
            retry_config,
        })
    }

    pub fn management_url(&self) -> &str {
        &self.management_url
    }

    pub fn is_secretless(&self) -> bool {
        self.auth.is_secretless()
    }

    // ── Health check (subscription get) ──

    pub async fn get_subscription(
        &self,
        runtime: &ConnectorRuntime,
    ) -> AzureResult<Subscription> {
        let url = format!(
            "{}/subscriptions/{}?api-version={}",
            self.management_url, self.subscription_id, API_VERSION_SUBSCRIPTION
        );
        self.get_single(runtime, &url).await
    }

    // ── Virtual Machines ──

    pub async fn list_vms(
        &self,
        runtime: &ConnectorRuntime,
        resource_group: &str,
    ) -> AzureResult<Vec<VirtualMachine>> {
        let url = format!(
            "{}/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Compute/virtualMachines?api-version={}",
            self.management_url, self.subscription_id, resource_group, API_VERSION_COMPUTE
        );
        self.get_value_list(runtime, &url).await
    }

    pub async fn get_vm(
        &self,
        runtime: &ConnectorRuntime,
        resource_group: &str,
        vm_name: &str,
    ) -> AzureResult<VirtualMachine> {
        let url = format!(
            "{}/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Compute/virtualMachines/{}?api-version={}",
            self.management_url, self.subscription_id, resource_group, vm_name, API_VERSION_COMPUTE
        );
        self.get_single(runtime, &url).await
    }

    pub async fn start_vm(
        &self,
        runtime: &ConnectorRuntime,
        resource_group: &str,
        vm_name: &str,
    ) -> AzureResult<serde_json::Value> {
        let url = format!(
            "{}/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Compute/virtualMachines/{}/start?api-version={}",
            self.management_url, self.subscription_id, resource_group, vm_name, API_VERSION_COMPUTE
        );
        self.post_empty(runtime, &url).await
    }

    pub async fn stop_vm(
        &self,
        runtime: &ConnectorRuntime,
        resource_group: &str,
        vm_name: &str,
    ) -> AzureResult<serde_json::Value> {
        let url = format!(
            "{}/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Compute/virtualMachines/{}/powerOff?api-version={}",
            self.management_url, self.subscription_id, resource_group, vm_name, API_VERSION_COMPUTE
        );
        self.post_empty(runtime, &url).await
    }

    pub async fn delete_vm(
        &self,
        runtime: &ConnectorRuntime,
        resource_group: &str,
        vm_name: &str,
    ) -> AzureResult<serde_json::Value> {
        let url = format!(
            "{}/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Compute/virtualMachines/{}?api-version={}",
            self.management_url, self.subscription_id, resource_group, vm_name, API_VERSION_COMPUTE
        );
        self.delete(runtime, &url).await
    }

    // ── Storage (blob via management API) ──

    pub async fn list_containers(
        &self,
        runtime: &ConnectorRuntime,
        resource_group: &str,
        storage_account: &str,
    ) -> AzureResult<Vec<BlobContainer>> {
        let url = format!(
            "{}/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Storage/storageAccounts/{}/blobServices/default/containers?api-version={}",
            self.management_url, self.subscription_id, resource_group, storage_account, API_VERSION_STORAGE
        );
        self.get_value_list(runtime, &url).await
    }

    pub async fn upload_blob(
        &self,
        runtime: &ConnectorRuntime,
        storage_account: &str,
        container: &str,
        blob_name: &str,
        content: &str,
    ) -> AzureResult<serde_json::Value> {
        let url = format!(
            "https://{storage_account}.blob.core.windows.net/{container}/{blob_name}"
        );
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let body = content.to_string();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            let body = body.clone();
            async move {
                debug!(attempt, blob_name, "Uploading blob");
                let req = authenticate_request(client.put(&url), &auth)
                    .header("x-ms-blob-type", "BlockBlob")
                    .header("x-ms-version", "2023-11-03")
                    .body(body);
                handle_response::<serde_json::Value>(req, attempt).await
            }
        })
        .await
    }

    pub async fn download_blob(
        &self,
        runtime: &ConnectorRuntime,
        storage_account: &str,
        container: &str,
        blob_name: &str,
    ) -> AzureResult<String> {
        let url = format!(
            "https://{storage_account}.blob.core.windows.net/{container}/{blob_name}"
        );
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            async move {
                debug!(attempt, blob_name, "Downloading blob");
                let req = authenticate_request(client.get(&url), &auth)
                    .header("x-ms-version", "2023-11-03");
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: AzureError::Http(e),
                            retry_after: None,
                        };
                    }
                };
                let status = resp.status().as_u16();
                if let Some(outcome) = check_error_status::<String>(status) {
                    return outcome;
                }
                match resp.text().await {
                    Ok(text) => AttemptOutcome::Success(text),
                    Err(e) => AttemptOutcome::Terminal(AzureError::Http(e)),
                }
            }
        })
        .await
    }

    pub async fn delete_blob(
        &self,
        runtime: &ConnectorRuntime,
        storage_account: &str,
        container: &str,
        blob_name: &str,
    ) -> AzureResult<serde_json::Value> {
        let url = format!(
            "https://{storage_account}.blob.core.windows.net/{container}/{blob_name}"
        );
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            async move {
                debug!(attempt, blob_name, "Deleting blob");
                let req = authenticate_request(client.delete(&url), &auth)
                    .header("x-ms-version", "2023-11-03");
                handle_response::<serde_json::Value>(req, attempt).await
            }
        })
        .await
    }

    // ── App Service ──

    pub async fn list_apps(
        &self,
        runtime: &ConnectorRuntime,
        resource_group: &str,
    ) -> AzureResult<Vec<WebApp>> {
        let url = format!(
            "{}/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Web/sites?api-version={}",
            self.management_url, self.subscription_id, resource_group, API_VERSION_WEB
        );
        self.get_value_list(runtime, &url).await
    }

    pub async fn deploy_app(
        &self,
        runtime: &ConnectorRuntime,
        resource_group: &str,
        app_name: &str,
        package_url: &str,
    ) -> AzureResult<DeploymentResponse> {
        let url = format!(
            "{}/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Web/sites/{}/extensions/onedeploy?api-version={}",
            self.management_url, self.subscription_id, resource_group, app_name, API_VERSION_WEB
        );
        let body = serde_json::json!({
            "properties": {
                "packageUri": package_url,
                "type": "zip"
            }
        });
        self.put_json(runtime, &url, &body).await
    }

    // ── Generic HTTP helpers ──

    async fn get_single<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
    ) -> AzureResult<T> {
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

    async fn get_value_list<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
    ) -> AzureResult<Vec<T>> {
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

    async fn post_empty(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
    ) -> AzureResult<serde_json::Value> {
        let url = url.to_string();
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            async move {
                debug!(attempt, url = %url, "POST empty");
                let req = authenticate_request(client.post(&url), &auth)
                    .header("Content-Length", "0");
                handle_response::<serde_json::Value>(req, attempt).await
            }
        })
        .await
    }

    async fn put_json<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
        body: &serde_json::Value,
    ) -> AzureResult<T> {
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

    async fn delete(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
    ) -> AzureResult<serde_json::Value> {
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
                handle_response::<serde_json::Value>(req, attempt).await
            }
        })
        .await
    }
}

// ── Free functions for request handling ──

fn authenticate_request(req: RequestBuilder, auth: &AzureAuth) -> RequestBuilder {
    if auth.access_token.is_empty() {
        req
    } else {
        req.bearer_auth(&auth.access_token)
    }
}

fn check_error_status<T>(status: u16) -> Option<AttemptOutcome<T, AzureError>> {
    if status == 429 {
        return Some(AttemptOutcome::Retryable {
            error: AzureError::RateLimited {
                retry_after_ms: 30_000,
            },
            retry_after: Some(Duration::from_secs(30)),
        });
    }
    if status == 401 || status == 403 {
        return Some(AttemptOutcome::Terminal(AzureError::Unauthorized(
            format!("Authentication failed (HTTP {status})"),
        )));
    }
    if status == 404 {
        return Some(AttemptOutcome::Terminal(AzureError::NotFound(
            format!("Resource not found (HTTP {status})"),
        )));
    }
    None
}

async fn handle_response<T: serde::de::DeserializeOwned>(
    req: RequestBuilder,
    attempt: u32,
) -> AttemptOutcome<T, AzureError> {
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            return AttemptOutcome::Retryable {
                error: AzureError::Http(e),
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
            error: AzureError::RateLimited {
                retry_after_ms: retry_after
                    .unwrap_or(Duration::from_secs(30))
                    .as_millis() as u64,
            },
            retry_after,
        };
    }

    if status == 401 || status == 403 {
        return AttemptOutcome::Terminal(AzureError::Unauthorized(format!(
            "Authentication failed (HTTP {status})"
        )));
    }

    if status == 404 {
        return AttemptOutcome::Terminal(AzureError::NotFound(format!(
            "Resource not found (HTTP {status})"
        )));
    }

    let is_success = resp.status().is_success();
    let text = match resp.text().await {
        Ok(t) => t,
        Err(e) => return AttemptOutcome::Terminal(AzureError::Http(e)),
    };

    // Azure async operations return 202 Accepted with empty body
    if status == 202 {
        if text.is_empty()
            && let Ok(val) =
                serde_json::from_str::<T>(&serde_json::json!({"status": "accepted"}).to_string())
        {
            return AttemptOutcome::Success(val);
        }
        match serde_json::from_str::<T>(&text) {
            Ok(v) => return AttemptOutcome::Success(v),
            Err(_) => {
                if let Ok(val) = serde_json::from_str::<T>(
                    &serde_json::json!({"status": "accepted"}).to_string(),
                ) {
                    return AttemptOutcome::Success(val);
                }
            }
        }
    }

    if !is_success {
        // Try to parse Azure error envelope
        if let Ok(azure_err) = serde_json::from_str::<AzureErrorResponse>(&text)
            && let Some(detail) = azure_err.error
        {
            let code = detail.code.unwrap_or_else(|| status.to_string());
            let message = detail
                .message
                .unwrap_or_else(|| format!("HTTP {status}"));
            let err = AzureError::Api {
                code: code.clone(),
                message,
            };
            if err.is_retryable() {
                return AttemptOutcome::Retryable {
                    error: err,
                    retry_after: None,
                };
            }
            return AttemptOutcome::Terminal(err);
        }
        let err = AzureError::Api {
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

    // Empty successful response (e.g., 204 No Content)
    if text.is_empty()
        && let Ok(val) =
            serde_json::from_str::<T>(&serde_json::json!({"status": "ok"}).to_string())
    {
        return AttemptOutcome::Success(val);
    }

    match serde_json::from_str::<T>(&text) {
        Ok(v) => AttemptOutcome::Success(v),
        Err(e) => {
            debug!(attempt, "Failed to parse response: {e}");
            AttemptOutcome::Terminal(AzureError::Json(e))
        }
    }
}

/// Azure list responses have a `value` array at the top level.
#[derive(serde::Deserialize)]
struct ValueWrapper<T> {
    value: Vec<T>,
}

async fn handle_list_response<T: serde::de::DeserializeOwned>(
    req: RequestBuilder,
    attempt: u32,
) -> AttemptOutcome<Vec<T>, AzureError> {
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            return AttemptOutcome::Retryable {
                error: AzureError::Http(e),
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
            error: AzureError::RateLimited {
                retry_after_ms: retry_after
                    .unwrap_or(Duration::from_secs(30))
                    .as_millis() as u64,
            },
            retry_after,
        };
    }

    if status == 401 || status == 403 {
        return AttemptOutcome::Terminal(AzureError::Unauthorized(format!(
            "Authentication failed (HTTP {status})"
        )));
    }

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        let err = AzureError::Api {
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

    let text = match resp.text().await {
        Ok(t) => t,
        Err(e) => return AttemptOutcome::Terminal(AzureError::Http(e)),
    };

    // Azure REST API uses { "value": [...] } envelope
    if let Ok(wrapper) = serde_json::from_str::<ValueWrapper<T>>(&text) {
        return AttemptOutcome::Success(wrapper.value);
    }

    // Fallback: try raw array
    match serde_json::from_str::<Vec<T>>(&text) {
        Ok(v) => AttemptOutcome::Success(v),
        Err(e) => {
            debug!(attempt, "Failed to parse list response: {e}");
            AttemptOutcome::Terminal(AzureError::Json(e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_debug_redacts_auth() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            AzureClient::new(
                "https://management.azure.com",
                AzureAuth {
                    access_token: "secret-token".into(),
                    subscription_id: "sub-123".into(),
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
            AzureClient::new(
                "https://management.azure.com",
                AzureAuth {
                    access_token: String::new(),
                    subscription_id: "sub-123".into(),
                },
                HttpRetryConfig::default(),
            )
            .await
            .unwrap()
        })
        .unwrap();
        assert!(rt.is_secretless());

        let rt2 = fcp_async_core::runtime::block_on_sync(async {
            AzureClient::new(
                "https://management.azure.com",
                AzureAuth {
                    access_token: "token".into(),
                    subscription_id: "sub-123".into(),
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
    fn management_url_trailing_slash_trimmed() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            AzureClient::new(
                "https://management.azure.com/",
                AzureAuth {
                    access_token: "t".into(),
                    subscription_id: "sub-123".into(),
                },
                HttpRetryConfig::default(),
            )
            .await
            .unwrap()
        })
        .unwrap();
        assert!(!rt.management_url().ends_with('/'));
    }

    #[test]
    fn check_error_status_429_is_retryable() {
        let outcome: Option<AttemptOutcome<String, AzureError>> = check_error_status(429);
        assert!(outcome.is_some());
        match outcome.unwrap() {
            AttemptOutcome::Retryable { error, .. } => {
                assert!(matches!(error, AzureError::RateLimited { .. }));
            }
            _ => panic!("Expected Retryable"),
        }
    }

    #[test]
    fn check_error_status_401_is_terminal() {
        let outcome: Option<AttemptOutcome<String, AzureError>> = check_error_status(401);
        assert!(outcome.is_some());
        match outcome.unwrap() {
            AttemptOutcome::Terminal(AzureError::Unauthorized(_)) => {}
            _ => panic!("Expected Terminal Unauthorized"),
        }
    }

    #[test]
    fn check_error_status_404_is_terminal() {
        let outcome: Option<AttemptOutcome<String, AzureError>> = check_error_status(404);
        assert!(outcome.is_some());
        match outcome.unwrap() {
            AttemptOutcome::Terminal(AzureError::NotFound(_)) => {}
            _ => panic!("Expected Terminal NotFound"),
        }
    }

    #[test]
    fn check_error_status_200_is_none() {
        let outcome: Option<AttemptOutcome<String, AzureError>> = check_error_status(200);
        assert!(outcome.is_none());
    }
}
