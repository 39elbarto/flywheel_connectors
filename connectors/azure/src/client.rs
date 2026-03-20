//! Azure API client primitives and shared request logic.

use std::time::Duration;

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use fcp_sdk::migration::{
    AttemptOutcome, ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig, RetryLoop,
};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::{Client, RequestBuilder, Response, StatusCode};
use serde::de::DeserializeOwned;
use tracing::debug;

use crate::{
    error::{AzureError, AzureResult},
    types::{
        ApiErrorResponse, AzureAuth, BlobContainerListResponse, BlobGetResponse,
        BlobListResponse, BlobPutResponse, ResourceGroupListResponse, ResourceListResponse,
        SecretBundle, SecretListResponse, SetSecretRequest, SubscriptionListResponse,
    },
};

/// Percent-encode a value for safe inclusion in a URL path segment.
/// Encodes all characters except ASCII alphanumerics, preventing path traversal
/// and injection via slashes, dots, or other special characters.
fn encode_path_segment(s: &str) -> String {
    utf8_percent_encode(s, NON_ALPHANUMERIC).to_string()
}

/// Validate that a hostname component (storage account or vault name) contains
/// only characters valid in Azure resource names (alphanumeric and hyphens).
/// This prevents SSRF via hostname injection.
fn validate_hostname_component(name: &str, label: &str) -> AzureResult<()> {
    if name.is_empty() {
        return Err(AzureError::Validation(format!("{label} must not be empty")));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Err(AzureError::Validation(format!(
            "{label} contains invalid characters (only alphanumeric and hyphens allowed): {name}"
        )));
    }
    Ok(())
}

pub const DEFAULT_MANAGEMENT_URL: &str = "https://management.azure.com";
const ARM_API_VERSION: &str = "2022-12-01";
const KEYVAULT_API_VERSION: &str = "7.4";
const BLOB_API_VERSION: &str = "2023-11-03";

pub struct AzureClient {
    http: Client,
    auth: AzureAuth,
    management_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl std::fmt::Debug for AzureClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AzureClient")
            .field("auth", &self.auth)
            .field("management_url", &self.management_url)
            .field("retry_config", &self.retry_config)
            .finish_non_exhaustive()
    }
}

impl AzureClient {
    pub fn new(
        auth: AzureAuth,
        retry_config: HttpRetryConfig,
        request_timeout: Duration,
    ) -> AzureResult<Self> {
        let http = Client::builder()
            .timeout(request_timeout)
            .user_agent("fcp-azure/0.1.0")
            .build()
            .map_err(AzureError::Http)?;

        Ok(Self {
            http,
            auth,
            management_url: DEFAULT_MANAGEMENT_URL.into(),
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(request_timeout),
            ),
            retry_config,
        })
    }

    #[must_use]
    pub fn with_management_url(mut self, url: &str) -> Self {
        self.management_url = url.trim_end_matches('/').to_string();
        self
    }

    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    #[must_use]
    pub const fn auth(&self) -> &AzureAuth {
        &self.auth
    }

    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        self.auth.is_secretless()
    }

    // -----------------------------------------------------------------------
    // Azure Resource Manager endpoints
    // -----------------------------------------------------------------------

    pub async fn list_subscriptions(&self) -> AzureResult<SubscriptionListResponse> {
        self.arm_get("/subscriptions", &[("api-version", ARM_API_VERSION)])
            .await
    }

    pub async fn list_resource_groups(
        &self,
        subscription_id: &str,
    ) -> AzureResult<ResourceGroupListResponse> {
        let safe_sub = encode_path_segment(subscription_id);
        let endpoint = format!("/subscriptions/{safe_sub}/resourcegroups");
        self.arm_get(&endpoint, &[("api-version", ARM_API_VERSION)])
            .await
    }

    pub async fn list_resources(
        &self,
        subscription_id: &str,
        resource_group: &str,
    ) -> AzureResult<ResourceListResponse> {
        let safe_sub = encode_path_segment(subscription_id);
        let safe_rg = encode_path_segment(resource_group);
        let endpoint = format!(
            "/subscriptions/{safe_sub}/resourceGroups/{safe_rg}/resources"
        );
        self.arm_get(&endpoint, &[("api-version", ARM_API_VERSION)])
            .await
    }

    pub async fn health_check(&self) -> AzureResult<()> {
        let _ = self.list_subscriptions().await?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Blob Storage endpoints
    // -----------------------------------------------------------------------

    pub async fn blob_list_containers(
        &self,
        storage_account: &str,
        blob_base_url: Option<&str>,
    ) -> AzureResult<BlobContainerListResponse> {
        validate_hostname_component(storage_account, "storage_account")?;
        let base = blob_base_url
            .unwrap_or("https://{account}.blob.core.windows.net")
            .replace("{account}", storage_account);
        let url = format!("{base}/");
        let query = [
            ("comp", "list"),
            ("x-ms-version", BLOB_API_VERSION),
        ];
        self.blob_get_json(&url, &query).await
    }

    pub async fn blob_list_blobs(
        &self,
        storage_account: &str,
        container: &str,
        blob_base_url: Option<&str>,
    ) -> AzureResult<BlobListResponse> {
        validate_hostname_component(storage_account, "storage_account")?;
        let base = blob_base_url
            .unwrap_or("https://{account}.blob.core.windows.net")
            .replace("{account}", storage_account);
        let safe_container = encode_path_segment(container);
        let url = format!("{base}/{safe_container}");
        let query = [
            ("restype", "container"),
            ("comp", "list"),
            ("x-ms-version", BLOB_API_VERSION),
        ];
        self.blob_get_json(&url, &query).await
    }

    pub async fn blob_get(
        &self,
        storage_account: &str,
        container: &str,
        blob_name: &str,
        blob_base_url: Option<&str>,
    ) -> AzureResult<BlobGetResponse> {
        validate_hostname_component(storage_account, "storage_account")?;
        let base = blob_base_url
            .unwrap_or("https://{account}.blob.core.windows.net")
            .replace("{account}", storage_account);
        let safe_container = encode_path_segment(container);
        let safe_blob = encode_path_segment(blob_name);
        let url = format!("{base}/{safe_container}/{safe_blob}");

        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            async move {
                debug!(attempt, %url, "Azure Blob GET");
                let builder = self
                    .apply_auth(self.http.get(&url))
                    .header("x-ms-version", BLOB_API_VERSION);

                match builder.send().await {
                    Ok(response) => {
                        let status = response.status();
                        if status.is_success() {
                            let content_type = response
                                .headers()
                                .get("content-type")
                                .and_then(|v| v.to_str().ok())
                                .map(str::to_string);
                            let content_length = response
                                .headers()
                                .get("content-length")
                                .and_then(|v| v.to_str().ok())
                                .and_then(|v| v.parse::<u64>().ok());
                            match response.bytes().await {
                                Ok(bytes) => AttemptOutcome::Success(BlobGetResponse {
                                    content_base64: Some(BASE64.encode(&bytes)),
                                    content_type,
                                    content_length,
                                }),
                                Err(e) => AttemptOutcome::Retryable {
                                    error: AzureError::Http(e),
                                    retry_after: None,
                                },
                            }
                        } else {
                            let body = response.text().await.unwrap_or_default();
                            let err = parse_error_response(status, &body, None);
                            if err.is_retryable() {
                                AttemptOutcome::Retryable {
                                    retry_after: err.retry_after(),
                                    error: err,
                                }
                            } else {
                                AttemptOutcome::Terminal(err)
                            }
                        }
                    }
                    Err(e) if e.is_timeout() || e.is_connect() => AttemptOutcome::Retryable {
                        error: AzureError::Http(e),
                        retry_after: None,
                    },
                    Err(e) => AttemptOutcome::Terminal(AzureError::Http(e)),
                }
            }
        })
        .await
    }

    pub async fn blob_put(
        &self,
        storage_account: &str,
        container: &str,
        blob_name: &str,
        content_base64: &str,
        content_type: Option<&str>,
        blob_base_url: Option<&str>,
    ) -> AzureResult<BlobPutResponse> {
        validate_hostname_component(storage_account, "storage_account")?;
        let base = blob_base_url
            .unwrap_or("https://{account}.blob.core.windows.net")
            .replace("{account}", storage_account);
        let safe_container = encode_path_segment(container);
        let safe_blob = encode_path_segment(blob_name);
        let url = format!("{base}/{safe_container}/{safe_blob}");

        let body_bytes = BASE64
            .decode(content_base64)
            .map_err(|e| AzureError::Validation(format!("Invalid base64 content: {e}")))?;
        let ct = content_type.unwrap_or("application/octet-stream").to_string();

        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let body_bytes = body_bytes.clone();
            let ct = ct.clone();
            async move {
                debug!(attempt, %url, "Azure Blob PUT");
                let builder = self
                    .apply_auth(self.http.put(&url))
                    .header("x-ms-version", BLOB_API_VERSION)
                    .header("x-ms-blob-type", "BlockBlob")
                    .header("Content-Type", &ct)
                    .body(body_bytes);

                match builder.send().await {
                    Ok(response) => {
                        let status = response.status();
                        if status.is_success() {
                            AttemptOutcome::Success(BlobPutResponse {
                                created: true,
                                blob_name: Some(blob_name.to_string()),
                            })
                        } else {
                            let body = response.text().await.unwrap_or_default();
                            let err = parse_error_response(status, &body, None);
                            if err.is_retryable() {
                                AttemptOutcome::Retryable {
                                    retry_after: err.retry_after(),
                                    error: err,
                                }
                            } else {
                                AttemptOutcome::Terminal(err)
                            }
                        }
                    }
                    Err(e) if e.is_timeout() || e.is_connect() => AttemptOutcome::Retryable {
                        error: AzureError::Http(e),
                        retry_after: None,
                    },
                    Err(e) => AttemptOutcome::Terminal(AzureError::Http(e)),
                }
            }
        })
        .await
    }

    // -----------------------------------------------------------------------
    // Key Vault endpoints
    // -----------------------------------------------------------------------

    pub async fn keyvault_list_secrets(
        &self,
        vault_name: &str,
        vault_base_url: Option<&str>,
    ) -> AzureResult<SecretListResponse> {
        validate_hostname_component(vault_name, "vault_name")?;
        let base = vault_base_url
            .unwrap_or("https://{vault}.vault.azure.net")
            .replace("{vault}", vault_name);
        let url = format!("{base}/secrets");
        let query = [("api-version", KEYVAULT_API_VERSION)];
        self.kv_get_json(&url, &query).await
    }

    pub async fn keyvault_get_secret(
        &self,
        vault_name: &str,
        secret_name: &str,
        vault_base_url: Option<&str>,
    ) -> AzureResult<SecretBundle> {
        validate_hostname_component(vault_name, "vault_name")?;
        let base = vault_base_url
            .unwrap_or("https://{vault}.vault.azure.net")
            .replace("{vault}", vault_name);
        let safe_name = encode_path_segment(secret_name);
        let url = format!("{base}/secrets/{safe_name}");
        let query = [("api-version", KEYVAULT_API_VERSION)];
        self.kv_get_json(&url, &query).await
    }

    pub async fn keyvault_set_secret(
        &self,
        vault_name: &str,
        secret_name: &str,
        request: &SetSecretRequest,
        vault_base_url: Option<&str>,
    ) -> AzureResult<SecretBundle> {
        validate_hostname_component(vault_name, "vault_name")?;
        let base = vault_base_url
            .unwrap_or("https://{vault}.vault.azure.net")
            .replace("{vault}", vault_name);
        let safe_name = encode_path_segment(secret_name);
        let url = format!("{base}/secrets/{safe_name}");
        let query = [("api-version", KEYVAULT_API_VERSION)];

        let body = serde_json::to_value(request).map_err(AzureError::Json)?;

        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let body = body.clone();
            async move {
                debug!(attempt, %url, "Azure KeyVault PUT secret");
                let builder = self
                    .apply_auth(self.http.put(&url))
                    .query(&query)
                    .header("Content-Type", "application/json")
                    .json(&body);

                match builder.send().await {
                    Ok(response) => match handle_json_response(response).await {
                        Ok(parsed) => AttemptOutcome::Success(parsed),
                        Err(err) if err.is_retryable() => AttemptOutcome::Retryable {
                            retry_after: err.retry_after(),
                            error: err,
                        },
                        Err(err) => AttemptOutcome::Terminal(err),
                    },
                    Err(e) if e.is_timeout() || e.is_connect() => AttemptOutcome::Retryable {
                        error: AzureError::Http(e),
                        retry_after: None,
                    },
                    Err(e) => AttemptOutcome::Terminal(AzureError::Http(e)),
                }
            }
        })
        .await
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    async fn arm_get<R>(&self, endpoint: &str, query: &[(&str, &str)]) -> AzureResult<R>
    where
        R: DeserializeOwned + Send,
    {
        let url = format!("{}{endpoint}", self.management_url);
        self.get_json(&url, query).await
    }

    async fn get_json<R>(&self, url: &str, query: &[(&str, &str)]) -> AzureResult<R>
    where
        R: DeserializeOwned + Send,
    {
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.to_string();
            async move {
                debug!(attempt, %url, "Azure API GET");
                let builder = self
                    .apply_auth(self.http.get(&url))
                    .query(query)
                    .header("Accept", "application/json");

                match builder.send().await {
                    Ok(response) => match handle_json_response(response).await {
                        Ok(parsed) => AttemptOutcome::Success(parsed),
                        Err(err) if err.is_retryable() => AttemptOutcome::Retryable {
                            retry_after: err.retry_after(),
                            error: err,
                        },
                        Err(err) => AttemptOutcome::Terminal(err),
                    },
                    Err(e) if e.is_timeout() || e.is_connect() => AttemptOutcome::Retryable {
                        error: AzureError::Http(e),
                        retry_after: None,
                    },
                    Err(e) => AttemptOutcome::Terminal(AzureError::Http(e)),
                }
            }
        })
        .await
    }

    async fn blob_get_json<R>(&self, url: &str, query: &[(&str, &str)]) -> AzureResult<R>
    where
        R: DeserializeOwned + Send,
    {
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.to_string();
            async move {
                debug!(attempt, %url, "Azure Blob GET");
                let builder = self
                    .apply_auth(self.http.get(&url))
                    .query(query)
                    .header("Accept", "application/json")
                    .header("x-ms-version", BLOB_API_VERSION);

                match builder.send().await {
                    Ok(response) => match handle_json_response(response).await {
                        Ok(parsed) => AttemptOutcome::Success(parsed),
                        Err(err) if err.is_retryable() => AttemptOutcome::Retryable {
                            retry_after: err.retry_after(),
                            error: err,
                        },
                        Err(err) => AttemptOutcome::Terminal(err),
                    },
                    Err(e) if e.is_timeout() || e.is_connect() => AttemptOutcome::Retryable {
                        error: AzureError::Http(e),
                        retry_after: None,
                    },
                    Err(e) => AttemptOutcome::Terminal(AzureError::Http(e)),
                }
            }
        })
        .await
    }

    async fn kv_get_json<R>(&self, url: &str, query: &[(&str, &str)]) -> AzureResult<R>
    where
        R: DeserializeOwned + Send,
    {
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.to_string();
            async move {
                debug!(attempt, %url, "Azure KeyVault GET");
                let builder = self
                    .apply_auth(self.http.get(&url))
                    .query(query)
                    .header("Accept", "application/json")
                    .header("Content-Type", "application/json");

                match builder.send().await {
                    Ok(response) => match handle_json_response(response).await {
                        Ok(parsed) => AttemptOutcome::Success(parsed),
                        Err(err) if err.is_retryable() => AttemptOutcome::Retryable {
                            retry_after: err.retry_after(),
                            error: err,
                        },
                        Err(err) => AttemptOutcome::Terminal(err),
                    },
                    Err(e) if e.is_timeout() || e.is_connect() => AttemptOutcome::Retryable {
                        error: AzureError::Http(e),
                        retry_after: None,
                    },
                    Err(e) => AttemptOutcome::Terminal(AzureError::Http(e)),
                }
            }
        })
        .await
    }

    fn apply_auth(&self, builder: RequestBuilder) -> RequestBuilder {
        match &self.auth {
            AzureAuth::BearerToken { bearer_token } => {
                builder.header("Authorization", format!("Bearer {bearer_token}"))
            }
            AzureAuth::CredentialId { credential_id } => {
                builder.header("X-FCP-Credential-ID", credential_id.to_string())
            }
        }
    }
}

async fn handle_json_response<R>(response: Response) -> AzureResult<R>
where
    R: DeserializeOwned + Send,
{
    let status = response.status();
    let retry_after_ms = response
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .map(|seconds| seconds * 1_000);
    let body = response.text().await.map_err(AzureError::Http)?;

    if status.is_success() {
        if body.trim().is_empty() {
            serde_json::from_value(serde_json::json!({})).map_err(AzureError::Json)
        } else {
            serde_json::from_str(&body).map_err(AzureError::Json)
        }
    } else {
        Err(parse_error_response(status, &body, retry_after_ms))
    }
}

fn parse_error_response(
    status: StatusCode,
    body: &str,
    retry_after_ms: Option<u64>,
) -> AzureError {
    let parsed = serde_json::from_str::<ApiErrorResponse>(body).ok();
    let code = parsed
        .as_ref()
        .and_then(|p| p.error.as_ref())
        .and_then(|e| e.code.clone());
    let message = parsed
        .as_ref()
        .and_then(|p| p.error.as_ref())
        .map(|e| e.message.clone())
        .or_else(|| parsed.and_then(|p| p.message))
        .unwrap_or_else(|| {
            if body.trim().is_empty() {
                format!("Azure API request failed with status {}", status.as_u16())
            } else {
                body.to_string()
            }
        });

    match status {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => AzureError::Unauthorized(message),
        StatusCode::NOT_FOUND => AzureError::NotFound(message),
        StatusCode::TOO_MANY_REQUESTS => AzureError::RateLimited {
            retry_after_ms: retry_after_ms.unwrap_or(60_000),
        },
        StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY => {
            AzureError::Validation(message)
        }
        _ => AzureError::Api {
            message,
            status_code: Some(status.as_u16()),
            code,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path, query_param},
    };

    fn test_client(base_url: &str) -> AzureClient {
        AzureClient::new(
            AzureAuth::BearerToken {
                bearer_token: "test-token".into(),
            },
            HttpRetryConfig::default(),
            Duration::from_secs(5),
        )
        .unwrap()
        .with_management_url(base_url)
    }

    #[test]
    fn list_subscriptions_returns_typed_payload() {
        fcp_async_core::runtime::block_on_sync(async {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/subscriptions"))
                .and(query_param("api-version", ARM_API_VERSION))
                .and(header("authorization", "Bearer test-token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "value": [
                        {
                            "subscriptionId": "sub-123",
                            "displayName": "Test Sub",
                            "state": "Enabled"
                        }
                    ]
                })))
                .mount(&server)
                .await;

            let client = test_client(&server.uri());
            let resp = client.list_subscriptions().await.unwrap();
            assert_eq!(resp.value.len(), 1);
            assert_eq!(
                resp.value[0].subscription_id.as_deref(),
                Some("sub-123")
            );
        })
        .unwrap();
    }

    #[test]
    fn list_resource_groups_returns_typed_payload() {
        fcp_async_core::runtime::block_on_sync(async {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/subscriptions/sub%2D1/resourcegroups"))
                .and(query_param("api-version", ARM_API_VERSION))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "value": [
                        { "name": "rg-1", "location": "eastus" }
                    ]
                })))
                .mount(&server)
                .await;

            let client = test_client(&server.uri());
            let resp = client.list_resource_groups("sub-1").await.unwrap();
            assert_eq!(resp.value.len(), 1);
            assert_eq!(resp.value[0].name.as_deref(), Some("rg-1"));
        })
        .unwrap();
    }

    #[test]
    fn list_resources_returns_typed_payload() {
        fcp_async_core::runtime::block_on_sync(async {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path(
                    "/subscriptions/sub%2D1/resourceGroups/rg%2D1/resources",
                ))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "value": [
                        { "name": "vm-1", "type": "Microsoft.Compute/virtualMachines", "location": "westus2" }
                    ]
                })))
                .mount(&server)
                .await;

            let client = test_client(&server.uri());
            let resp = client.list_resources("sub-1", "rg-1").await.unwrap();
            assert_eq!(resp.value.len(), 1);
            assert_eq!(resp.value[0].name.as_deref(), Some("vm-1"));
        })
        .unwrap();
    }

    #[test]
    fn health_check_succeeds_when_subscriptions_ok() {
        fcp_async_core::runtime::block_on_sync(async {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/subscriptions"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(serde_json::json!({ "value": [] })),
                )
                .mount(&server)
                .await;

            let client = test_client(&server.uri());
            client.health_check().await.unwrap();
        })
        .unwrap();
    }

    #[test]
    fn unauthorized_returns_error() {
        fcp_async_core::runtime::block_on_sync(async {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/subscriptions"))
                .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                    "error": {
                        "code": "AuthenticationFailed",
                        "message": "The access token is invalid."
                    }
                })))
                .mount(&server)
                .await;

            let client = test_client(&server.uri());
            let err = client.list_subscriptions().await.unwrap_err();
            assert!(matches!(err, AzureError::Unauthorized(_)));
        })
        .unwrap();
    }

    #[test]
    fn not_found_returns_error() {
        fcp_async_core::runtime::block_on_sync(async {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/subscriptions/sub%2Dmissing/resourcegroups"))
                .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                    "error": {
                        "code": "SubscriptionNotFound",
                        "message": "Subscription not found"
                    }
                })))
                .mount(&server)
                .await;

            let client = test_client(&server.uri());
            let err = client
                .list_resource_groups("sub-missing")
                .await
                .unwrap_err();
            assert!(matches!(err, AzureError::NotFound(_)));
        })
        .unwrap();
    }

    #[test]
    fn rate_limited_returns_error() {
        fcp_async_core::runtime::block_on_sync(async {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/subscriptions"))
                .respond_with(
                    ResponseTemplate::new(429)
                        .insert_header("retry-after", "5")
                        .set_body_json(serde_json::json!({ "message": "throttled" })),
                )
                .mount(&server)
                .await;

            let no_retry = HttpRetryConfig {
                max_retries: 0,
                ..HttpRetryConfig::default()
            };
            let client = AzureClient::new(
                AzureAuth::BearerToken {
                    bearer_token: "test-token".into(),
                },
                no_retry,
                Duration::from_secs(5),
            )
            .unwrap()
            .with_management_url(&server.uri());
            let err = client.list_subscriptions().await.unwrap_err();
            match err {
                AzureError::RateLimited { retry_after_ms } => {
                    assert_eq!(retry_after_ms, 5_000);
                }
                other => panic!("expected rate limited, got {other:?}"),
            }
        })
        .unwrap();
    }

    #[test]
    fn client_debug_hides_auth() {
        let client = AzureClient::new(
            AzureAuth::BearerToken {
                bearer_token: "super-secret".into(),
            },
            HttpRetryConfig::default(),
            Duration::from_secs(5),
        )
        .unwrap();
        let debug = format!("{client:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("super-secret"));
    }

    #[test]
    fn parse_error_empty_body() {
        let err = parse_error_response(StatusCode::INTERNAL_SERVER_ERROR, "", None);
        match err {
            AzureError::Api { message, .. } => {
                assert!(message.contains("500"));
            }
            other => panic!("expected api error, got {other:?}"),
        }
    }

    #[test]
    fn parse_error_bad_request() {
        let err = parse_error_response(
            StatusCode::BAD_REQUEST,
            r#"{"error":{"code":"InvalidInput","message":"bad input"}}"#,
            None,
        );
        assert!(matches!(err, AzureError::Validation(_)));
    }

    #[test]
    fn encode_path_segment_encodes_slashes_and_dots() {
        assert_eq!(encode_path_segment("safe123"), "safe123");
        assert_eq!(encode_path_segment("a/b"), "a%2Fb");
        assert_eq!(encode_path_segment("../etc/passwd"), "%2E%2E%2Fetc%2Fpasswd");
        assert_eq!(encode_path_segment("sub-1"), "sub%2D1");
        assert_eq!(encode_path_segment("has space"), "has%20space");
    }

    #[test]
    fn validate_hostname_rejects_slashes() {
        let result = validate_hostname_component("evil.com/attack", "test");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, AzureError::Validation(_)));
    }

    #[test]
    fn validate_hostname_rejects_empty() {
        let result = validate_hostname_component("", "test");
        assert!(result.is_err());
    }

    #[test]
    fn validate_hostname_allows_valid_names() {
        assert!(validate_hostname_component("mystorageaccount", "test").is_ok());
        assert!(validate_hostname_component("my-vault-name", "test").is_ok());
        assert!(validate_hostname_component("abc123", "test").is_ok());
    }

    #[test]
    fn validate_hostname_rejects_special_chars() {
        assert!(validate_hostname_component("a.b", "test").is_err());
        assert!(validate_hostname_component("a:b", "test").is_err());
        assert!(validate_hostname_component("a@b", "test").is_err());
        assert!(validate_hostname_component("a/b", "test").is_err());
    }
}
