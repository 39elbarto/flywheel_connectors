use std::time::Duration;

use reqwest::{Client, RequestBuilder};
use tracing::debug;

use fcp_sdk::migration::{AttemptOutcome, ConnectorRuntime, HttpRetryConfig, RetryLoop};

use crate::error::{AwsError, AwsResult};
use crate::types::*;

/// AWS API client with retry support.
/// Uses simplified REST without SigV4 signing (placeholder for future auth).
pub struct AwsClient {
    client: Client,
    auth: AwsAuth,
    region: String,
    retry_config: HttpRetryConfig,
    s3_base_url: Option<String>,
    ec2_base_url: Option<String>,
    lambda_base_url: Option<String>,
    sts_base_url: Option<String>,
}

impl std::fmt::Debug for AwsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsClient")
            .field("region", &self.region)
            .field("auth", &self.auth)
            .finish()
    }
}

impl AwsClient {
    pub async fn new(
        auth: AwsAuth,
        region: &str,
        retry_config: HttpRetryConfig,
        s3_base_url: Option<String>,
        ec2_base_url: Option<String>,
        lambda_base_url: Option<String>,
        sts_base_url: Option<String>,
    ) -> AwsResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(AwsError::Http)?;

        Ok(Self {
            client,
            auth,
            region: region.to_string(),
            retry_config,
            s3_base_url,
            ec2_base_url,
            lambda_base_url,
            sts_base_url,
        })
    }

    pub fn region(&self) -> &str {
        &self.region
    }

    pub fn is_secretless(&self) -> bool {
        self.auth.access_key_id.is_empty()
    }

    fn s3_url(&self) -> String {
        self.s3_base_url
            .clone()
            .unwrap_or_else(|| format!("https://s3.{}.amazonaws.com", self.region))
    }

    fn ec2_url(&self) -> String {
        self.ec2_base_url
            .clone()
            .unwrap_or_else(|| format!("https://ec2.{}.amazonaws.com", self.region))
    }

    fn lambda_url(&self) -> String {
        self.lambda_base_url
            .clone()
            .unwrap_or_else(|| format!("https://lambda.{}.amazonaws.com", self.region))
    }

    fn sts_url(&self) -> String {
        self.sts_base_url
            .clone()
            .unwrap_or_else(|| "https://sts.amazonaws.com".to_string())
    }

    // ── S3 operations ──

    pub async fn s3_list_buckets(&self, runtime: &ConnectorRuntime) -> AwsResult<Vec<S3Bucket>> {
        let url = self.s3_url();
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            async move {
                debug!(attempt, "S3 list buckets");
                let req = authenticate_request(client.get(&url), &auth);
                handle_json_response::<Vec<S3Bucket>>(req, attempt).await
            }
        })
        .await
    }

    pub async fn s3_list_objects(
        &self,
        runtime: &ConnectorRuntime,
        bucket: &str,
        prefix: Option<&str>,
    ) -> AwsResult<Vec<S3Object>> {
        let mut url = format!("{}/{bucket}", self.s3_url());
        if let Some(p) = prefix {
            url = format!("{url}?prefix={p}&list-type=2");
        } else {
            url = format!("{url}?list-type=2");
        }
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            async move {
                debug!(attempt, bucket, "S3 list objects");
                let req = authenticate_request(client.get(&url), &auth);
                handle_json_response::<Vec<S3Object>>(req, attempt).await
            }
        })
        .await
    }

    pub async fn s3_get_object(
        &self,
        runtime: &ConnectorRuntime,
        bucket: &str,
        key: &str,
    ) -> AwsResult<S3GetObjectResponse> {
        let url = format!("{}/{bucket}/{key}", self.s3_url());
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            let key = key.to_string();
            async move {
                debug!(attempt, bucket, key = %key, "S3 get object");
                let req = authenticate_request(client.get(&url), &auth);
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: AwsError::Http(e),
                            retry_after: None,
                        };
                    }
                };
                let status = resp.status().as_u16();
                if let Some(outcome) = check_error_status::<S3GetObjectResponse>(status) {
                    return outcome;
                }
                let content_type = resp
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .map(String::from);
                let content_length = resp
                    .headers()
                    .get("content-length")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<u64>().ok());
                let etag = resp
                    .headers()
                    .get("etag")
                    .and_then(|v| v.to_str().ok())
                    .map(String::from);
                match resp.text().await {
                    Ok(body) => AttemptOutcome::Success(S3GetObjectResponse {
                        key,
                        content_type,
                        content_length,
                        etag,
                        body,
                    }),
                    Err(e) => AttemptOutcome::Terminal(AwsError::Http(e)),
                }
            }
        })
        .await
    }

    pub async fn s3_put_object(
        &self,
        runtime: &ConnectorRuntime,
        bucket: &str,
        key: &str,
        body: &str,
        content_type: Option<&str>,
    ) -> AwsResult<S3PutObjectResponse> {
        let url = format!("{}/{bucket}/{key}", self.s3_url());
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let body_owned = body.to_string();
        let ct = content_type.unwrap_or("application/octet-stream").to_string();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            let body = body_owned.clone();
            let ct = ct.clone();
            async move {
                debug!(attempt, bucket, key, "S3 put object");
                let req = authenticate_request(client.put(&url), &auth)
                    .header("Content-Type", ct)
                    .body(body);
                handle_json_response::<S3PutObjectResponse>(req, attempt).await
            }
        })
        .await
    }

    pub async fn s3_delete_object(
        &self,
        runtime: &ConnectorRuntime,
        bucket: &str,
        key: &str,
    ) -> AwsResult<S3DeleteObjectResponse> {
        let url = format!("{}/{bucket}/{key}", self.s3_url());
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            async move {
                debug!(attempt, bucket, key, "S3 delete object");
                let req = authenticate_request(client.delete(&url), &auth);
                handle_json_response::<S3DeleteObjectResponse>(req, attempt).await
            }
        })
        .await
    }

    // ── EC2 operations ──

    pub async fn ec2_describe_instances(
        &self,
        runtime: &ConnectorRuntime,
    ) -> AwsResult<Vec<Ec2Instance>> {
        let url = format!(
            "{}?Action=DescribeInstances&Version=2016-11-15",
            self.ec2_url()
        );
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            async move {
                debug!(attempt, "EC2 describe instances");
                let req = authenticate_request(client.get(&url), &auth);
                handle_json_response::<Vec<Ec2Instance>>(req, attempt).await
            }
        })
        .await
    }

    pub async fn ec2_start_instance(
        &self,
        runtime: &ConnectorRuntime,
        instance_id: &str,
    ) -> AwsResult<Ec2StateChange> {
        let url = format!(
            "{}?Action=StartInstances&InstanceId.1={instance_id}&Version=2016-11-15",
            self.ec2_url()
        );
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            async move {
                debug!(attempt, instance_id, "EC2 start instance");
                let req = authenticate_request(client.post(&url), &auth);
                handle_json_response::<Ec2StateChange>(req, attempt).await
            }
        })
        .await
    }

    pub async fn ec2_stop_instance(
        &self,
        runtime: &ConnectorRuntime,
        instance_id: &str,
    ) -> AwsResult<Ec2StateChange> {
        let url = format!(
            "{}?Action=StopInstances&InstanceId.1={instance_id}&Version=2016-11-15",
            self.ec2_url()
        );
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            async move {
                debug!(attempt, instance_id, "EC2 stop instance");
                let req = authenticate_request(client.post(&url), &auth);
                handle_json_response::<Ec2StateChange>(req, attempt).await
            }
        })
        .await
    }

    pub async fn ec2_terminate_instance(
        &self,
        runtime: &ConnectorRuntime,
        instance_id: &str,
    ) -> AwsResult<Ec2StateChange> {
        let url = format!(
            "{}?Action=TerminateInstances&InstanceId.1={instance_id}&Version=2016-11-15",
            self.ec2_url()
        );
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            async move {
                debug!(attempt, instance_id, "EC2 terminate instance");
                let req = authenticate_request(client.post(&url), &auth);
                handle_json_response::<Ec2StateChange>(req, attempt).await
            }
        })
        .await
    }

    // ── Lambda operations ──

    pub async fn lambda_list_functions(
        &self,
        runtime: &ConnectorRuntime,
    ) -> AwsResult<Vec<LambdaFunction>> {
        let url = format!("{}/2015-03-31/functions", self.lambda_url());
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            async move {
                debug!(attempt, "Lambda list functions");
                let req = authenticate_request(client.get(&url), &auth);
                handle_json_response::<Vec<LambdaFunction>>(req, attempt).await
            }
        })
        .await
    }

    pub async fn lambda_invoke(
        &self,
        runtime: &ConnectorRuntime,
        function_name: &str,
        payload: &serde_json::Value,
    ) -> AwsResult<LambdaInvokeResponse> {
        let url = format!(
            "{}/2015-03-31/functions/{function_name}/invocations",
            self.lambda_url()
        );
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let payload = payload.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            let payload = payload.clone();
            async move {
                debug!(attempt, function_name, "Lambda invoke");
                let req = authenticate_request(client.post(&url), &auth).json(&payload);
                handle_json_response::<LambdaInvokeResponse>(req, attempt).await
            }
        })
        .await
    }

    // ── STS operations ──

    pub async fn sts_get_caller_identity(
        &self,
        runtime: &ConnectorRuntime,
    ) -> AwsResult<CallerIdentity> {
        let url = format!(
            "{}?Action=GetCallerIdentity&Version=2011-06-15",
            self.sts_url()
        );
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            async move {
                debug!(attempt, "STS get caller identity");
                let req = authenticate_request(client.post(&url), &auth);
                handle_json_response::<CallerIdentity>(req, attempt).await
            }
        })
        .await
    }

    // ── Health check ──

    pub async fn health_check(&self, runtime: &ConnectorRuntime) -> AwsResult<HealthStatus> {
        match self.sts_get_caller_identity(runtime).await {
            Ok(identity) => Ok(HealthStatus {
                authenticated: true,
                account: Some(identity.account),
                arn: Some(identity.arn),
            }),
            Err(e) => Err(e),
        }
    }
}

// ── Free functions for request handling ──

fn authenticate_request(req: RequestBuilder, auth: &AwsAuth) -> RequestBuilder {
    if auth.access_key_id.is_empty() {
        return req;
    }
    let req = req
        .header("X-Aws-Access-Key-Id", auth.access_key_id.as_str())
        .header(
            "X-Aws-Secret-Access-Key",
            auth.secret_access_key.as_str(),
        );
    if let Some(token) = &auth.session_token {
        req.header("X-Aws-Security-Token", token.as_str())
    } else {
        req
    }
}

fn check_error_status<T>(status: u16) -> Option<AttemptOutcome<T, AwsError>> {
    if status == 429 || status == 503 {
        return Some(AttemptOutcome::Retryable {
            error: AwsError::RateLimited {
                retry_after_ms: 30_000,
            },
            retry_after: Some(Duration::from_secs(30)),
        });
    }
    if status == 401 || status == 403 {
        return Some(AttemptOutcome::Terminal(AwsError::Unauthorized(format!(
            "Authentication failed (HTTP {status})"
        ))));
    }
    if status == 404 {
        return Some(AttemptOutcome::Terminal(AwsError::NotFound(format!(
            "Resource not found (HTTP {status})"
        ))));
    }
    None
}

async fn handle_json_response<T: serde::de::DeserializeOwned>(
    req: RequestBuilder,
    _attempt: u32,
) -> AttemptOutcome<T, AwsError> {
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            return AttemptOutcome::Retryable {
                error: AwsError::Http(e),
                retry_after: None,
            };
        }
    };

    let status = resp.status().as_u16();

    if let Some(outcome) = check_error_status::<T>(status) {
        return outcome;
    }

    if status == 429 || status == 503 {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .map(Duration::from_secs);
        return AttemptOutcome::Retryable {
            error: AwsError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(Duration::from_secs(30)).as_millis() as u64,
            },
            retry_after,
        };
    }

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        let err = AwsError::Api {
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
        Err(e) => return AttemptOutcome::Terminal(AwsError::Http(e)),
    };

    match serde_json::from_str::<T>(&text) {
        Ok(v) => AttemptOutcome::Success(v),
        Err(e) => {
            // For successful responses that can't be parsed, return a default-ish error
            debug!("Failed to parse AWS response: {e}");
            AttemptOutcome::Terminal(AwsError::Json(e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_debug_redacts_auth() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            AwsClient::new(
                AwsAuth {
                    access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
                    secret_access_key: "wJalrXUtnFEMI/K7MDENG".into(),
                    session_token: None,
                },
                "us-east-1",
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
        assert!(!debug.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!debug.contains("wJalrXUtnFEMI"));
    }

    #[test]
    fn secretless_detection() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            AwsClient::new(
                AwsAuth {
                    access_key_id: String::new(),
                    secret_access_key: String::new(),
                    session_token: None,
                },
                "us-east-1",
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
            AwsClient::new(
                AwsAuth {
                    access_key_id: "AKID".into(),
                    secret_access_key: "secret".into(),
                    session_token: None,
                },
                "us-east-1",
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
    fn region_stored() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            AwsClient::new(
                AwsAuth {
                    access_key_id: "k".into(),
                    secret_access_key: "s".into(),
                    session_token: None,
                },
                "eu-west-1",
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
        assert_eq!(rt.region(), "eu-west-1");
    }

    #[test]
    fn custom_base_urls() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            AwsClient::new(
                AwsAuth {
                    access_key_id: "k".into(),
                    secret_access_key: "s".into(),
                    session_token: None,
                },
                "us-east-1",
                HttpRetryConfig::default(),
                Some("http://localhost:4566".into()),
                Some("http://localhost:4567".into()),
                Some("http://localhost:4568".into()),
                Some("http://localhost:4569".into()),
            )
            .await
            .unwrap()
        })
        .unwrap();
        assert_eq!(rt.s3_url(), "http://localhost:4566");
        assert_eq!(rt.ec2_url(), "http://localhost:4567");
        assert_eq!(rt.lambda_url(), "http://localhost:4568");
        assert_eq!(rt.sts_url(), "http://localhost:4569");
    }

    #[test]
    fn default_urls_use_region() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            AwsClient::new(
                AwsAuth {
                    access_key_id: "k".into(),
                    secret_access_key: "s".into(),
                    session_token: None,
                },
                "ap-southeast-1",
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
        assert_eq!(rt.s3_url(), "https://s3.ap-southeast-1.amazonaws.com");
        assert_eq!(rt.ec2_url(), "https://ec2.ap-southeast-1.amazonaws.com");
        assert_eq!(
            rt.lambda_url(),
            "https://lambda.ap-southeast-1.amazonaws.com"
        );
        assert_eq!(rt.sts_url(), "https://sts.amazonaws.com");
    }
}
