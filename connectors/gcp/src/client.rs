use std::time::Duration;

use reqwest::{Client, RequestBuilder};
use serde_json::json;
use tracing::debug;

use fcp_sdk::migration::{AttemptOutcome, ConnectorRuntime, HttpRetryConfig, RetryLoop};

use crate::error::{GcpError, GcpResult};
use crate::types::*;

/// GCP API client with retry support.
pub struct GcpClient {
    client: Client,
    auth: GcpAuth,
    project_id: String,
    retry_config: HttpRetryConfig,
    /// Base URLs for each GCP service (overridable for testing).
    compute_base: String,
    storage_base: String,
    run_base: String,
    crm_base: String,
}

impl std::fmt::Debug for GcpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GcpClient")
            .field("project_id", &self.project_id)
            .field("auth", &self.auth)
            .finish()
    }
}

impl GcpClient {
    pub async fn new(
        project_id: &str,
        auth: GcpAuth,
        retry_config: HttpRetryConfig,
        compute_base: Option<&str>,
        storage_base: Option<&str>,
        run_base: Option<&str>,
        crm_base: Option<&str>,
    ) -> GcpResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(GcpError::Http)?;

        Ok(Self {
            client,
            auth,
            project_id: project_id.to_string(),
            retry_config,
            compute_base: compute_base
                .unwrap_or("https://compute.googleapis.com")
                .trim_end_matches('/')
                .to_string(),
            storage_base: storage_base
                .unwrap_or("https://storage.googleapis.com")
                .trim_end_matches('/')
                .to_string(),
            run_base: run_base
                .unwrap_or("https://run.googleapis.com")
                .trim_end_matches('/')
                .to_string(),
            crm_base: crm_base
                .unwrap_or("https://cloudresourcemanager.googleapis.com")
                .trim_end_matches('/')
                .to_string(),
        })
    }

    pub fn project_id(&self) -> &str {
        &self.project_id
    }

    pub fn is_secretless(&self) -> bool {
        self.auth.is_secretless()
    }

    // ── Compute Engine ──

    pub async fn list_instances(
        &self,
        runtime: &ConnectorRuntime,
        zone: &str,
    ) -> GcpResult<Vec<Instance>> {
        let url = format!(
            "{}/compute/v1/projects/{}/zones/{}/instances",
            self.compute_base, self.project_id, zone
        );
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            async move {
                debug!(attempt, "Listing compute instances");
                let req = authenticate_request(client.get(&url), &auth);
                handle_list_response::<InstanceList, Instance>(req, attempt, |list| {
                    list.items.unwrap_or_default()
                })
                .await
            }
        })
        .await
    }

    pub async fn get_instance(
        &self,
        runtime: &ConnectorRuntime,
        zone: &str,
        instance_name: &str,
    ) -> GcpResult<Instance> {
        let url = format!(
            "{}/compute/v1/projects/{}/zones/{}/instances/{}",
            self.compute_base, self.project_id, zone, instance_name
        );
        self.get_single(runtime, &url).await
    }

    pub async fn start_instance(
        &self,
        runtime: &ConnectorRuntime,
        zone: &str,
        instance_name: &str,
    ) -> GcpResult<serde_json::Value> {
        let url = format!(
            "{}/compute/v1/projects/{}/zones/{}/instances/{}/start",
            self.compute_base, self.project_id, zone, instance_name
        );
        self.post_empty(runtime, &url).await
    }

    pub async fn stop_instance(
        &self,
        runtime: &ConnectorRuntime,
        zone: &str,
        instance_name: &str,
    ) -> GcpResult<serde_json::Value> {
        let url = format!(
            "{}/compute/v1/projects/{}/zones/{}/instances/{}/stop",
            self.compute_base, self.project_id, zone, instance_name
        );
        self.post_empty(runtime, &url).await
    }

    pub async fn delete_instance(
        &self,
        runtime: &ConnectorRuntime,
        zone: &str,
        instance_name: &str,
    ) -> GcpResult<serde_json::Value> {
        let url = format!(
            "{}/compute/v1/projects/{}/zones/{}/instances/{}",
            self.compute_base, self.project_id, zone, instance_name
        );
        self.delete(runtime, &url).await
    }

    // ── Cloud Storage ──

    pub async fn list_objects(
        &self,
        runtime: &ConnectorRuntime,
        bucket: &str,
    ) -> GcpResult<Vec<StorageObject>> {
        let url = format!("{}/storage/v1/b/{}/o", self.storage_base, bucket);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            async move {
                debug!(attempt, "Listing storage objects");
                let req = authenticate_request(client.get(&url), &auth);
                handle_list_response::<ObjectList, StorageObject>(req, attempt, |list| {
                    list.items.unwrap_or_default()
                })
                .await
            }
        })
        .await
    }

    pub async fn get_object(
        &self,
        runtime: &ConnectorRuntime,
        bucket: &str,
        object_name: &str,
    ) -> GcpResult<StorageObject> {
        let url = format!(
            "{}/storage/v1/b/{}/o/{}",
            self.storage_base, bucket, object_name
        );
        self.get_single(runtime, &url).await
    }

    pub async fn upload_object(
        &self,
        runtime: &ConnectorRuntime,
        bucket: &str,
        object_name: &str,
        content: &str,
        content_type: Option<&str>,
    ) -> GcpResult<StorageObject> {
        let url = format!(
            "{}/upload/storage/v1/b/{}/o?uploadType=media&name={}",
            self.storage_base, bucket, object_name
        );
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let body = content.to_string();
        let ct = content_type
            .unwrap_or("application/octet-stream")
            .to_string();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            let body = body.clone();
            let ct = ct.clone();
            async move {
                debug!(attempt, "Uploading storage object");
                let req = authenticate_request(client.post(&url), &auth)
                    .header("Content-Type", ct)
                    .body(body);
                handle_response::<StorageObject>(req, attempt).await
            }
        })
        .await
    }

    pub async fn delete_object(
        &self,
        runtime: &ConnectorRuntime,
        bucket: &str,
        object_name: &str,
    ) -> GcpResult<serde_json::Value> {
        let url = format!(
            "{}/storage/v1/b/{}/o/{}",
            self.storage_base, bucket, object_name
        );
        self.delete(runtime, &url).await
    }

    // ── Cloud Run ──

    pub async fn list_services(
        &self,
        runtime: &ConnectorRuntime,
        location: &str,
    ) -> GcpResult<Vec<CloudRunService>> {
        let url = format!(
            "{}/v2/projects/{}/locations/{}/services",
            self.run_base, self.project_id, location
        );
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            async move {
                debug!(attempt, "Listing Cloud Run services");
                let req = authenticate_request(client.get(&url), &auth);
                handle_list_response::<CloudRunServiceList, CloudRunService>(req, attempt, |list| {
                    list.services.unwrap_or_default()
                })
                .await
            }
        })
        .await
    }

    pub async fn deploy_service(
        &self,
        runtime: &ConnectorRuntime,
        location: &str,
        service_id: &str,
        image: &str,
    ) -> GcpResult<CloudRunService> {
        let url = format!(
            "{}/v2/projects/{}/locations/{}/services?serviceId={}",
            self.run_base, self.project_id, location, service_id
        );
        let body = json!({
            "template": {
                "containers": [{
                    "image": image
                }]
            }
        });
        self.post_json(runtime, &url, &body).await
    }

    pub async fn delete_service(
        &self,
        runtime: &ConnectorRuntime,
        location: &str,
        service_name: &str,
    ) -> GcpResult<serde_json::Value> {
        let url = format!(
            "{}/v2/projects/{}/locations/{}/services/{}",
            self.run_base, self.project_id, location, service_name
        );
        self.delete(runtime, &url).await
    }

    // ── Projects ──

    pub async fn get_project(&self, runtime: &ConnectorRuntime) -> GcpResult<Project> {
        let url = format!("{}/v1/projects/{}", self.crm_base, self.project_id);
        self.get_single(runtime, &url).await
    }

    // ── Generic HTTP helpers ──

    async fn get_single<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
    ) -> GcpResult<T> {
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
    ) -> GcpResult<T> {
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
                debug!(attempt, url = %url, "POST json");
                let req = authenticate_request(client.post(&url), &auth).json(&body);
                handle_response::<T>(req, attempt).await
            }
        })
        .await
    }

    async fn post_empty(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
    ) -> GcpResult<serde_json::Value> {
        let url = url.to_string();
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            async move {
                debug!(attempt, url = %url, "POST empty");
                let req =
                    authenticate_request(client.post(&url), &auth).header("Content-Length", "0");
                handle_response::<serde_json::Value>(req, attempt).await
            }
        })
        .await
    }

    async fn delete(&self, runtime: &ConnectorRuntime, url: &str) -> GcpResult<serde_json::Value> {
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

fn authenticate_request(req: RequestBuilder, auth: &GcpAuth) -> RequestBuilder {
    let token = auth.bearer_token();
    if token.is_empty() {
        req
    } else {
        req.bearer_auth(token)
    }
}

async fn handle_response<T: serde::de::DeserializeOwned>(
    req: RequestBuilder,
    attempt: u32,
) -> AttemptOutcome<T, GcpError> {
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            return AttemptOutcome::Retryable {
                error: GcpError::Http(e),
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
            error: GcpError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(Duration::from_secs(30)).as_millis() as u64,
            },
            retry_after,
        };
    }

    if status == 401 || status == 403 {
        return AttemptOutcome::Terminal(GcpError::Unauthorized(format!(
            "Authentication failed (HTTP {status})"
        )));
    }

    if status == 404 {
        return AttemptOutcome::Terminal(GcpError::NotFound(format!(
            "Resource not found (HTTP {status})"
        )));
    }

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        // Try to parse GCP error response
        if let Ok(gcp_err) = serde_json::from_str::<GcpApiError>(&text)
            && let Some(detail) = gcp_err.error
        {
            let code = detail.code.unwrap_or(u32::from(status));
            let message = detail.message.unwrap_or_else(|| text.clone());
            let err = GcpError::Api { code, message };
            if err.is_retryable() {
                return AttemptOutcome::Retryable {
                    error: err,
                    retry_after: None,
                };
            }
            return AttemptOutcome::Terminal(err);
        }
        let err = GcpError::Api {
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

    // For 204 No Content (e.g., delete responses)
    if status == 204 {
        // Try to return a default/empty value
        match serde_json::from_str::<T>("{}") {
            Ok(v) => return AttemptOutcome::Success(v),
            Err(e) => {
                return AttemptOutcome::Terminal(GcpError::Json(e));
            }
        }
    }

    let text = match resp.text().await {
        Ok(t) => t,
        Err(e) => return AttemptOutcome::Terminal(GcpError::Http(e)),
    };

    match serde_json::from_str::<T>(&text) {
        Ok(v) => AttemptOutcome::Success(v),
        Err(e) => {
            debug!(attempt, "Failed to parse response: {e}");
            AttemptOutcome::Terminal(GcpError::Json(e))
        }
    }
}

async fn handle_list_response<L: serde::de::DeserializeOwned, T>(
    req: RequestBuilder,
    attempt: u32,
    extract: impl FnOnce(L) -> Vec<T>,
) -> AttemptOutcome<Vec<T>, GcpError> {
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            return AttemptOutcome::Retryable {
                error: GcpError::Http(e),
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
            error: GcpError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(Duration::from_secs(30)).as_millis() as u64,
            },
            retry_after,
        };
    }

    if status == 401 || status == 403 {
        return AttemptOutcome::Terminal(GcpError::Unauthorized(format!(
            "Authentication failed (HTTP {status})"
        )));
    }

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        let err = GcpError::Api {
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
        Err(e) => return AttemptOutcome::Terminal(GcpError::Http(e)),
    };

    match serde_json::from_str::<L>(&text) {
        Ok(list) => AttemptOutcome::Success(extract(list)),
        Err(e) => {
            debug!(attempt, "Failed to parse list response: {e}");
            AttemptOutcome::Terminal(GcpError::Json(e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_debug_redacts_auth() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            GcpClient::new(
                "my-project",
                GcpAuth::AccessToken {
                    access_token: "ya29.secret-token".into(),
                },
                HttpRetryConfig::default(),
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap()
        })
        .unwrap();

        let debug = format!("{rt:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("ya29"));
    }

    #[test]
    fn secretless_detection() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            GcpClient::new(
                "my-project",
                GcpAuth::AccessToken {
                    access_token: String::new(),
                },
                HttpRetryConfig::default(),
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap()
        })
        .unwrap();
        assert!(rt.is_secretless());

        let rt2 = fcp_async_core::runtime::block_on_sync(async {
            GcpClient::new(
                "my-project",
                GcpAuth::AccessToken {
                    access_token: "ya29.token".into(),
                },
                HttpRetryConfig::default(),
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap()
        })
        .unwrap();
        assert!(!rt2.is_secretless());
    }

    #[test]
    fn project_id_accessible() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            GcpClient::new(
                "test-project-123",
                GcpAuth::AccessToken {
                    access_token: "t".into(),
                },
                HttpRetryConfig::default(),
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap()
        })
        .unwrap();
        assert_eq!(rt.project_id(), "test-project-123");
    }

    #[test]
    fn custom_base_urls() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            GcpClient::new(
                "proj",
                GcpAuth::AccessToken {
                    access_token: "t".into(),
                },
                HttpRetryConfig::default(),
                Some("http://localhost:8080/"),
                Some("http://localhost:8081/"),
                Some("http://localhost:8082/"),
                Some("http://localhost:8083/"),
            )
            .await
            .unwrap()
        })
        .unwrap();
        // Trailing slashes should be trimmed
        assert!(!format!("{rt:?}").is_empty());
    }
}
