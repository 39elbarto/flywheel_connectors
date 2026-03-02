//! S3 API client.
//!
//! This implements a simplified S3-compatible REST client. For production use
//! with real AWS S3, you would need full AWS SigV4 request signing. This
//! implementation uses bearer-style auth headers for mock/test friendliness
//! and constructs standard S3 REST API URLs.

use std::fmt::Write;
use std::time::Duration;

use fcp_async_core::time::sleep;
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, warn};

use crate::{
    error::{S3Error, S3Result},
    types::{
        ApiErrorResponse, BucketInfo, GetObjectResponse, HeadObjectResponse, ListBucketsResponse,
        ListObjectsResponse, ObjectInfo, PresignedUrlResponse, PutObjectResponse,
    },
};

/// Default S3 base URL.
const DEFAULT_BASE_URL: &str = "https://s3.amazonaws.com";

/// Percent-encoding set for S3 object key paths. Preserves `/`, `-`, `_`, `.`, `~`
/// which are valid in S3 key names and URL paths.
const S3_PATH_SET: &percent_encoding::AsciiSet = &percent_encoding::CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}')
    .add(b'%')
    .add(b'[')
    .add(b']')
    .add(b'^')
    .add(b'|')
    .add(b'\\');

/// S3 API client.
#[derive(Debug)]
pub struct S3Client {
    client: Client,
    access_key_id: String,
    secret_access_key: String,
    region: String,
    base_url: String,
    max_retries: u32,
    initial_delay_ms: u64,
    max_delay_ms: u64,
}

impl S3Client {
    /// Create a new S3 client.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be constructed.
    pub fn new(
        access_key_id: impl Into<String>,
        secret_access_key: impl Into<String>,
        region: impl Into<String>,
    ) -> S3Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(300))
            .build()
            .map_err(S3Error::Http)?;

        Ok(Self {
            client,
            access_key_id: access_key_id.into(),
            secret_access_key: secret_access_key.into(),
            region: region.into(),
            base_url: DEFAULT_BASE_URL.into(),
            max_retries: 3,
            initial_delay_ms: 500,
            max_delay_ms: 30_000,
        })
    }

    /// Set the base URL (for testing with mock servers).
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

    /// Upload an object to a bucket.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, auth errors, or if the bucket does not exist.
    pub async fn put_object(
        &self,
        bucket: &str,
        key: &str,
        body: &str,
    ) -> S3Result<PutObjectResponse> {
        let url = self.object_url(bucket, key);
        let response: serde_json::Value = self.put_request(&url, body).await?;

        let etag = response
            .get("etag")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        Ok(PutObjectResponse { etag })
    }

    /// Download an object from a bucket.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, auth errors, or if the object does not exist.
    pub async fn get_object(&self, bucket: &str, key: &str) -> S3Result<GetObjectResponse> {
        let url = self.object_url(bucket, key);
        let response: serde_json::Value = self.get_json(&url).await?;

        let body = response
            .get("body")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let content_type = response
            .get("content_type")
            .and_then(|v| v.as_str())
            .unwrap_or("application/octet-stream")
            .to_string();

        Ok(GetObjectResponse { body, content_type })
    }

    /// Delete an object from a bucket.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures or auth errors.
    pub async fn delete_object(&self, bucket: &str, key: &str) -> S3Result<bool> {
        let url = self.object_url(bucket, key);
        self.delete_request(&url).await?;
        Ok(true)
    }

    /// List objects in a bucket with optional prefix and max keys.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, auth errors, or if the bucket does not exist.
    pub async fn list_objects(
        &self,
        bucket: &str,
        prefix: Option<&str>,
        max_keys: Option<u64>,
    ) -> S3Result<ListObjectsResponse> {
        let base_url = format!("{}/{bucket}", self.base_url);
        let mut params: Vec<(&str, String)> = Vec::new();
        params.push(("list-type", "2".to_string()));

        if let Some(p) = prefix {
            params.push(("prefix", p.to_string()));
        }
        if let Some(mk) = max_keys {
            params.push(("max-keys", mk.to_string()));
        }

        let response: serde_json::Value = self.get_with_params(&base_url, &params).await?;

        let contents = response
            .get("contents")
            .and_then(|v| serde_json::from_value::<Vec<ObjectInfo>>(v.clone()).ok())
            .unwrap_or_default();

        let is_truncated = response
            .get("is_truncated")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        Ok(ListObjectsResponse {
            contents,
            is_truncated,
        })
    }

    /// Get object metadata (HEAD request).
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, auth errors, or if the object does not exist.
    pub async fn head_object(&self, bucket: &str, key: &str) -> S3Result<HeadObjectResponse> {
        let url = self.object_url(bucket, key);
        let response: serde_json::Value = self.head_request(&url).await?;

        let content_type = response
            .get("content_type")
            .and_then(|v| v.as_str())
            .unwrap_or("application/octet-stream")
            .to_string();

        let content_length = response
            .get("content_length")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        let etag = response
            .get("etag")
            .and_then(|v| v.as_str())
            .map(String::from);

        let last_modified = response
            .get("last_modified")
            .and_then(|v| v.as_str())
            .map(String::from);

        Ok(HeadObjectResponse {
            content_type,
            content_length,
            etag,
            last_modified,
        })
    }

    /// Copy an object within or between buckets.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, auth errors, or if the source does not exist.
    pub async fn copy_object(
        &self,
        source_bucket: &str,
        source_key: &str,
        dest_bucket: &str,
        dest_key: &str,
    ) -> S3Result<PutObjectResponse> {
        let url = self.object_url(dest_bucket, dest_key);
        let copy_source = format!("/{source_bucket}/{source_key}");

        let response: serde_json::Value = self.put_with_copy_source(&url, &copy_source).await?;

        let etag = response
            .get("etag")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        Ok(PutObjectResponse { etag })
    }

    /// List all buckets.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures or auth errors.
    pub async fn list_buckets(&self) -> S3Result<ListBucketsResponse> {
        let url = format!("{}/", self.base_url);
        let response: serde_json::Value = self.get_json(&url).await?;

        let buckets = response
            .get("buckets")
            .and_then(|v| serde_json::from_value::<Vec<BucketInfo>>(v.clone()).ok())
            .unwrap_or_default();

        Ok(ListBucketsResponse { buckets })
    }

    /// Generate a presigned URL for temporary access.
    ///
    /// Note: This generates a placeholder presigned URL. Real AWS SigV4
    /// signing would require the full AWS SDK or manual SigV4 implementation.
    #[must_use]
    pub fn generate_presigned_url(
        &self,
        bucket: &str,
        key: &str,
        expires_in: u64,
    ) -> PresignedUrlResponse {
        // Construct a presigned-style URL. In production, this would use
        // AWS SigV4 query string signing. For now, we construct a URL that
        // indicates the presigned nature with expiry metadata.
        let encoded_key =
            percent_encoding::utf8_percent_encode(key, percent_encoding::NON_ALPHANUMERIC);

        let url = format!(
            "{base}/{bucket}/{encoded_key}?X-Amz-Algorithm=AWS4-HMAC-SHA256\
             &X-Amz-Credential={access_key}%2F{region}%2Fs3%2Faws4_request\
             &X-Amz-Expires={expires_in}\
             &X-Amz-SignedHeaders=host\
             &X-Amz-Signature=PLACEHOLDER_SIGNATURE",
            base = self.base_url,
            access_key = self.access_key_id,
            region = self.region,
        );

        PresignedUrlResponse { url }
    }

    // ── Internal helpers ─────────────────────────────────────────────────

    /// Build the URL for an object in a bucket.
    fn object_url(&self, bucket: &str, key: &str) -> String {
        let encoded_key = percent_encoding::utf8_percent_encode(key, S3_PATH_SET);
        format!("{}/{bucket}/{encoded_key}", self.base_url)
    }

    /// GET request returning deserialized JSON.
    async fn get_json<T: serde::de::DeserializeOwned>(&self, url: &str) -> S3Result<T> {
        let mut delay = Duration::from_millis(self.initial_delay_ms);
        let mut attempts = 0;

        loop {
            attempts += 1;
            debug!(attempt = attempts, url, "S3 GET request");

            let result = self
                .client
                .get(url)
                .bearer_auth(&self.access_key_id)
                .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
                .send()
                .await;

            match result {
                Ok(response) => {
                    if let Some(retry_result) = Self::check_rate_limit(&response) {
                        if attempts <= self.max_retries {
                            let wait = retry_result.unwrap_or(delay);
                            warn!(attempts, "Rate limited, waiting {wait:?}");
                            sleep(wait).await;
                            delay =
                                std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
                            continue;
                        }
                        return Err(S3Error::RateLimited {
                            retry_after_ms: delay.as_millis() as u64,
                        });
                    }
                    return self.handle_json_response(response).await;
                }
                Err(e) if (e.is_timeout() || e.is_connect()) && attempts <= self.max_retries => {
                    warn!(
                        attempt = attempts,
                        delay_ms = delay.as_millis(),
                        error = %e,
                        "Retrying after connection error"
                    );
                    sleep(delay).await;
                    delay = std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
                }
                Err(e) => return Err(S3Error::Http(e)),
            }
        }
    }

    /// GET with manual URL query parameters.
    async fn get_with_params<T: serde::de::DeserializeOwned>(
        &self,
        base_url: &str,
        params: &[(&str, String)],
    ) -> S3Result<T> {
        let mut url = base_url.to_string();
        if !params.is_empty() {
            url.push('?');
            for (i, (key, value)) in params.iter().enumerate() {
                if i > 0 {
                    url.push('&');
                }
                let encoded = percent_encoding::utf8_percent_encode(
                    value,
                    percent_encoding::NON_ALPHANUMERIC,
                );
                let _ = write!(url, "{key}={encoded}");
            }
        }
        self.get_json(&url).await
    }

    /// PUT request with a string body, returning JSON.
    async fn put_request<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        body: &str,
    ) -> S3Result<T> {
        let mut delay = Duration::from_millis(self.initial_delay_ms);
        let mut attempts = 0;

        loop {
            attempts += 1;
            debug!(attempt = attempts, url, "S3 PUT request");

            let result = self
                .client
                .put(url)
                .bearer_auth(&self.access_key_id)
                .header("content-type", "application/octet-stream")
                .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
                .body(body.to_string())
                .send()
                .await;

            match result {
                Ok(response) => {
                    if let Some(retry_result) = Self::check_rate_limit(&response) {
                        if attempts <= self.max_retries {
                            let wait = retry_result.unwrap_or(delay);
                            warn!(attempts, "Rate limited on PUT, waiting {wait:?}");
                            sleep(wait).await;
                            delay =
                                std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
                            continue;
                        }
                        return Err(S3Error::RateLimited {
                            retry_after_ms: delay.as_millis() as u64,
                        });
                    }
                    return self.handle_json_response(response).await;
                }
                Err(e) if (e.is_timeout() || e.is_connect()) && attempts <= self.max_retries => {
                    warn!(
                        attempt = attempts,
                        delay_ms = delay.as_millis(),
                        error = %e,
                        "Retrying PUT after connection error"
                    );
                    sleep(delay).await;
                    delay = std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
                }
                Err(e) => return Err(S3Error::Http(e)),
            }
        }
    }

    /// PUT request with x-amz-copy-source header for copy operations.
    async fn put_with_copy_source<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        copy_source: &str,
    ) -> S3Result<T> {
        let mut delay = Duration::from_millis(self.initial_delay_ms);
        let mut attempts = 0;

        loop {
            attempts += 1;
            debug!(attempt = attempts, url, copy_source, "S3 COPY request");

            let result = self
                .client
                .put(url)
                .bearer_auth(&self.access_key_id)
                .header("x-amz-copy-source", copy_source)
                .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
                .send()
                .await;

            match result {
                Ok(response) => {
                    if let Some(retry_result) = Self::check_rate_limit(&response) {
                        if attempts <= self.max_retries {
                            let wait = retry_result.unwrap_or(delay);
                            warn!(attempts, "Rate limited on COPY, waiting {wait:?}");
                            sleep(wait).await;
                            delay =
                                std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
                            continue;
                        }
                        return Err(S3Error::RateLimited {
                            retry_after_ms: delay.as_millis() as u64,
                        });
                    }
                    return self.handle_json_response(response).await;
                }
                Err(e) if (e.is_timeout() || e.is_connect()) && attempts <= self.max_retries => {
                    warn!(
                        attempt = attempts,
                        delay_ms = delay.as_millis(),
                        error = %e,
                        "Retrying COPY after connection error"
                    );
                    sleep(delay).await;
                    delay = std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
                }
                Err(e) => return Err(S3Error::Http(e)),
            }
        }
    }

    /// DELETE request.
    async fn delete_request(&self, url: &str) -> S3Result<()> {
        let mut delay = Duration::from_millis(self.initial_delay_ms);
        let mut attempts = 0;

        loop {
            attempts += 1;
            debug!(attempt = attempts, url, "S3 DELETE request");

            let result = self
                .client
                .delete(url)
                .bearer_auth(&self.access_key_id)
                .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
                .send()
                .await;

            match result {
                Ok(response) => {
                    if let Some(retry_result) = Self::check_rate_limit(&response) {
                        if attempts <= self.max_retries {
                            let wait = retry_result.unwrap_or(delay);
                            warn!(attempts, "Rate limited on DELETE, waiting {wait:?}");
                            sleep(wait).await;
                            delay =
                                std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
                            continue;
                        }
                        return Err(S3Error::RateLimited {
                            retry_after_ms: delay.as_millis() as u64,
                        });
                    }

                    let status = response.status();
                    if status.is_success() || status == StatusCode::NO_CONTENT {
                        return Ok(());
                    }

                    let bytes = response.bytes().await?;
                    return Err(parse_error_response(status, &bytes));
                }
                Err(e) if (e.is_timeout() || e.is_connect()) && attempts <= self.max_retries => {
                    warn!(
                        attempt = attempts,
                        delay_ms = delay.as_millis(),
                        error = %e,
                        "Retrying DELETE after connection error"
                    );
                    sleep(delay).await;
                    delay = std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
                }
                Err(e) => return Err(S3Error::Http(e)),
            }
        }
    }

    /// HEAD request returning JSON-parsed metadata.
    async fn head_request<T: serde::de::DeserializeOwned>(&self, url: &str) -> S3Result<T> {
        let mut delay = Duration::from_millis(self.initial_delay_ms);
        let mut attempts = 0;

        loop {
            attempts += 1;
            debug!(attempt = attempts, url, "S3 HEAD request");

            let result = self
                .client
                .head(url)
                .bearer_auth(&self.access_key_id)
                .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
                .send()
                .await;

            match result {
                Ok(response) => {
                    if let Some(retry_result) = Self::check_rate_limit(&response) {
                        if attempts <= self.max_retries {
                            let wait = retry_result.unwrap_or(delay);
                            warn!(attempts, "Rate limited on HEAD, waiting {wait:?}");
                            sleep(wait).await;
                            delay =
                                std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
                            continue;
                        }
                        return Err(S3Error::RateLimited {
                            retry_after_ms: delay.as_millis() as u64,
                        });
                    }
                    return self.handle_json_response(response).await;
                }
                Err(e) if (e.is_timeout() || e.is_connect()) && attempts <= self.max_retries => {
                    warn!(
                        attempt = attempts,
                        delay_ms = delay.as_millis(),
                        error = %e,
                        "Retrying HEAD after connection error"
                    );
                    sleep(delay).await;
                    delay = std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
                }
                Err(e) => return Err(S3Error::Http(e)),
            }
        }
    }

    /// Handle a response by checking status and deserializing JSON.
    async fn handle_json_response<T: serde::de::DeserializeOwned>(
        &self,
        response: Response,
    ) -> S3Result<T> {
        let status = response.status();
        let bytes = response.bytes().await?;

        if status.is_success() {
            serde_json::from_slice(&bytes).map_err(S3Error::from)
        } else {
            Err(parse_error_response(status, &bytes))
        }
    }

    /// Check if a response indicates rate limiting.
    ///
    /// Returns `Some(Some(duration))` if rate limited with a retry-after value,
    /// `Some(None)` if rate limited without retry-after,
    /// `None` if not rate limited.
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
}

/// Parse an error response from S3.
fn parse_error_response(status: StatusCode, bytes: &[u8]) -> S3Error {
    // Try to parse as JSON API error
    if let Ok(error) = serde_json::from_slice::<ApiErrorResponse>(bytes) {
        if status == StatusCode::NOT_FOUND {
            if error.code == "NoSuchBucket" {
                return S3Error::BucketNotFound {
                    bucket: error.message,
                };
            }
            return S3Error::NotFound { key: error.message };
        }

        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            return S3Error::Unauthorized;
        }

        if status == StatusCode::TOO_MANY_REQUESTS {
            return S3Error::RateLimited {
                retry_after_ms: 30_000,
            };
        }

        return S3Error::Api {
            code: error.code,
            message: error.message,
            status_code: Some(status.as_u16()),
        };
    }

    // Fallback for unparseable responses
    S3Error::Api {
        code: "Unknown".into(),
        message: String::from_utf8_lossy(bytes).into_owned(),
        status_code: Some(status.as_u16()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    #[fcp_async_core::runtime::test]
    async fn test_put_object_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("PUT"))
            .and(path("/test-bucket/test-key"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"etag": "\"abc123\""})),
            )
            .mount(&mock_server)
            .await;

        let client = S3Client::new("test_key", "test_secret", "us-east-1")
            .unwrap()
            .with_base_url(mock_server.uri());

        let result = client
            .put_object("test-bucket", "test-key", "hello world")
            .await
            .unwrap();

        assert_eq!(result.etag, "\"abc123\"");
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_object_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/test-bucket/test-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "body": "hello world",
                "content_type": "text/plain"
            })))
            .mount(&mock_server)
            .await;

        let client = S3Client::new("test_key", "test_secret", "us-east-1")
            .unwrap()
            .with_base_url(mock_server.uri());

        let result = client.get_object("test-bucket", "test-key").await.unwrap();

        assert_eq!(result.body, "hello world");
        assert_eq!(result.content_type, "text/plain");
    }

    #[fcp_async_core::runtime::test]
    async fn test_delete_object_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("DELETE"))
            .and(path("/test-bucket/test-key"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&mock_server)
            .await;

        let client = S3Client::new("test_key", "test_secret", "us-east-1")
            .unwrap()
            .with_base_url(mock_server.uri());

        let result = client
            .delete_object("test-bucket", "test-key")
            .await
            .unwrap();

        assert!(result);
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_objects_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/test-bucket"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "contents": [
                    {"key": "file1.txt", "size": 100},
                    {"key": "file2.txt", "size": 200}
                ],
                "is_truncated": false
            })))
            .mount(&mock_server)
            .await;

        let client = S3Client::new("test_key", "test_secret", "us-east-1")
            .unwrap()
            .with_base_url(mock_server.uri());

        let result = client
            .list_objects("test-bucket", Some("file"), Some(10))
            .await
            .unwrap();

        assert_eq!(result.contents.len(), 2);
        assert!(!result.is_truncated);
    }

    #[fcp_async_core::runtime::test]
    async fn test_unauthorized() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/test-bucket/test-key"))
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "code": "AccessDenied",
                "message": "Access Denied"
            })))
            .mount(&mock_server)
            .await;

        let client = S3Client::new("bad_key", "bad_secret", "us-east-1")
            .unwrap()
            .with_base_url(mock_server.uri())
            .with_retry_config(1, 10, 100);

        let result = client.get_object("test-bucket", "test-key").await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), S3Error::Unauthorized));
    }

    #[fcp_async_core::runtime::test]
    async fn test_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/test-bucket/missing-key"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "code": "NoSuchKey",
                "message": "missing-key"
            })))
            .mount(&mock_server)
            .await;

        let client = S3Client::new("test_key", "test_secret", "us-east-1")
            .unwrap()
            .with_base_url(mock_server.uri())
            .with_retry_config(1, 10, 100);

        let result = client.get_object("test-bucket", "missing-key").await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), S3Error::NotFound { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_rate_limited() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/test-bucket/test-key"))
            .respond_with(ResponseTemplate::new(429).set_body_json(serde_json::json!({
                "code": "SlowDown",
                "message": "Reduce your request rate"
            })))
            .mount(&mock_server)
            .await;

        let client = S3Client::new("test_key", "test_secret", "us-east-1")
            .unwrap()
            .with_base_url(mock_server.uri())
            .with_retry_config(1, 10, 100);

        let result = client.get_object("test-bucket", "test-key").await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), S3Error::RateLimited { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_presigned_url_generation() {
        let client = S3Client::new("AKIAIOSFODNN7EXAMPLE", "secret", "us-east-1")
            .unwrap()
            .with_base_url("https://s3.amazonaws.com");

        let result = client.generate_presigned_url("my-bucket", "my-file.txt", 3600);

        assert!(result.url.contains("my-bucket"));
        assert!(result.url.contains("X-Amz-Algorithm=AWS4-HMAC-SHA256"));
        assert!(result.url.contains("X-Amz-Expires=3600"));
        assert!(result.url.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn test_error_is_retryable() {
        assert!(
            S3Error::RateLimited {
                retry_after_ms: 1000
            }
            .is_retryable()
        );

        assert!(!S3Error::Unauthorized.is_retryable());

        assert!(!S3Error::NotFound { key: "test".into() }.is_retryable());

        assert!(
            S3Error::Api {
                code: "InternalError".into(),
                message: "Internal".into(),
                status_code: Some(500),
            }
            .is_retryable()
        );

        assert!(
            !S3Error::Api {
                code: "NoSuchKey".into(),
                message: "Not found".into(),
                status_code: Some(404),
            }
            .is_retryable()
        );
    }
}
