//! Google Drive API v3 HTTP client.
//!
//! Uses `fcp-google-discovery` shared auth substrate.

use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fcp_google_discovery::auth::GoogleMaterializedAuth;
use fcp_google_discovery::executor::{
    GoogleApiError, GoogleExecuteRequest, GoogleExecuteResponse, GoogleResponseBody,
    GoogleResponseMode, GoogleRestError, GoogleRestExecutor,
};
use fcp_google_discovery::{DiscoveryMethod, DiscoveryParameter};
use fcp_sdk::migration::{
    AttemptOutcome, ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig, RetryLoop,
};
use reqwest::{Client, StatusCode, Url, header};
use tracing::debug;

use crate::{
    error::{DriveError, DriveResult},
    types::{AboutResponse, DriveFile, DrivePermission, FileListResponse},
};

/// Default Google Drive API v3 base URL.
pub const DEFAULT_BASE_URL: &str = "https://www.googleapis.com/drive/v3";

/// Google Drive API v3 client.
pub struct DriveClient {
    executor: GoogleRestExecutor,
    auth: GoogleMaterializedAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
    total_requests: AtomicU64,
}

impl fmt::Debug for DriveClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DriveClient")
            .field("auth", &self.auth_redacted_label())
            .field("base_url", &self.base_url)
            .field("retry_config", &self.retry_config)
            .finish_non_exhaustive()
    }
}

impl DriveClient {
    /// Create a new Drive client with shared Google auth.
    pub fn new_with_auth(auth: GoogleMaterializedAuth) -> DriveResult<Self> {
        let mut headers = header::HeaderMap::new();
        headers.insert(header::ACCEPT, "application/json".parse().unwrap());

        let client = Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-google-drive/0.1.0")
            .build()
            .map_err(DriveError::Http)?;

        Ok(Self {
            executor: GoogleRestExecutor::new().with_client(client),
            auth,
            base_url: DEFAULT_BASE_URL.to_string(),
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(30)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 2,
                initial_delay_ms: 500,
                max_delay_ms: 30_000,
                jitter_enabled: true,
            },
            total_requests: AtomicU64::new(0),
        })
    }

    /// Get current auth.
    #[must_use]
    pub const fn auth(&self) -> &GoogleMaterializedAuth {
        &self.auth
    }

    /// Render a redacted auth label for diagnostics.
    #[must_use]
    pub fn auth_redacted_label(&self) -> String {
        match &self.auth {
            GoogleMaterializedAuth::BearerToken { source, .. } => source.to_string(),
            GoogleMaterializedAuth::CredentialReference { credential_id, .. } => {
                format!("credential_id:{credential_id}")
            }
        }
    }

    /// Get the base URL.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Set a custom base URL (for testing).
    #[must_use]
    pub fn with_base_url(mut self, url: &str) -> Self {
        self.base_url = url.to_string();
        self
    }

    /// Get total requests made.
    #[must_use]
    pub fn total_requests(&self) -> u64 {
        self.total_requests.load(Ordering::Relaxed)
    }

    /// Trigger graceful shutdown of request contexts.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    // ── File operations ─────────────────────────────────────────

    /// List files in Drive, optionally filtered by query.
    pub async fn list_files(
        &self,
        query: Option<&str>,
        max_results: Option<u32>,
        page_token: Option<&str>,
    ) -> DriveResult<FileListResponse> {
        let mut url = format!(
            "{}/files?fields=kind,nextPageToken,files(id,name,mimeType,size,createdTime,modifiedTime,parents,webViewLink,trashed,shared)",
            self.base_url,
        );
        if let Some(q) = query {
            let _ = write!(url, "&q={}", urlencoding::encode(q));
        }
        if let Some(max) = max_results {
            let _ = write!(url, "&pageSize={max}");
        }
        if let Some(token) = page_token {
            let _ = write!(url, "&pageToken={}", urlencoding::encode(token));
        }
        self.get_json(&url).await
    }

    /// Get a file's metadata by ID.
    pub async fn get_file(&self, file_id: &str) -> DriveResult<DriveFile> {
        let url = format!(
            "{}/files/{}?fields=id,name,mimeType,size,description,createdTime,modifiedTime,parents,webViewLink,webContentLink,thumbnailLink,trashed,shared,owners,permissions",
            self.base_url,
            urlencoding::encode(file_id),
        );
        self.get_json(&url).await
    }

    /// Create a folder in Drive.
    pub async fn create_folder(
        &self,
        name: &str,
        parent_id: Option<&str>,
    ) -> DriveResult<DriveFile> {
        let url = format!("{}/files?fields=id,name,mimeType,parents", self.base_url);
        let mut body = serde_json::json!({
            "name": name,
            "mimeType": "application/vnd.google-apps.folder"
        });
        if let Some(parent) = parent_id {
            body["parents"] = serde_json::json!([parent]);
        }
        self.post_json(&url, &body).await
    }

    /// Upload a file (metadata-only, content via media upload is separate).
    pub async fn upload_file(
        &self,
        name: &str,
        mime_type: &str,
        parent_id: Option<&str>,
        content_base64: &str,
    ) -> DriveResult<DriveFile> {
        let url = format!(
            "{}/files?uploadType=multipart&fields=id,name,mimeType,size",
            self.base_url,
        );
        let mut metadata = serde_json::json!({
            "name": name,
            "mimeType": mime_type,
        });
        if let Some(parent) = parent_id {
            metadata["parents"] = serde_json::json!([parent]);
        }
        let body = serde_json::json!({
            "metadata": metadata,
            "media_body_base64": content_base64,
        });
        self.post_json(&url, &body).await
    }

    /// Download a file's content as bytes (returned as base64).
    pub async fn download_file(&self, file_id: &str) -> DriveResult<String> {
        let url = format!(
            "{}/files/{}?alt=media",
            self.base_url,
            urlencoding::encode(file_id),
        );
        let response = self
            .execute_with_retry("GET", &url, None, GoogleResponseMode::Binary)
            .await?;
        match response.body {
            GoogleResponseBody::Binary(bytes) => Ok(base64_encode(&bytes)),
            GoogleResponseBody::Json(value) => Ok(value.to_string()),
            GoogleResponseBody::Empty => Ok(String::new()),
        }
    }

    /// Trash a file (move to trash).
    pub async fn trash_file(&self, file_id: &str) -> DriveResult<DriveFile> {
        let url = format!(
            "{}/files/{}?fields=id,name,trashed",
            self.base_url,
            urlencoding::encode(file_id),
        );
        let body = serde_json::json!({ "trashed": true });
        self.patch_json(&url, &body).await
    }

    /// Share a file with a user.
    pub async fn share_file(
        &self,
        file_id: &str,
        email: &str,
        role: &str,
    ) -> DriveResult<DrivePermission> {
        let url = format!(
            "{}/files/{}/permissions",
            self.base_url,
            urlencoding::encode(file_id),
        );
        let body = serde_json::json!({
            "type": "user",
            "role": role,
            "emailAddress": email,
        });
        self.post_json(&url, &body).await
    }

    /// Get Drive storage quota and user info.
    pub async fn about(&self) -> DriveResult<AboutResponse> {
        let url = format!("{}/about?fields=kind,user,storageQuota", self.base_url);
        self.get_json(&url).await
    }

    /// Health check via about endpoint.
    pub async fn health_check(&self) -> DriveResult<()> {
        let _about = self.about().await?;
        Ok(())
    }

    // ── Internal HTTP helpers ────────────────────────────────────

    async fn get_json<T: serde::de::DeserializeOwned>(&self, url: &str) -> DriveResult<T> {
        let response = self
            .execute_with_retry("GET", url, None, GoogleResponseMode::Json)
            .await?;
        decode_json_response(response)
    }

    async fn post_json<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> DriveResult<T> {
        let response = self
            .execute_with_retry("POST", url, Some(body), GoogleResponseMode::Json)
            .await?;
        decode_json_response(response)
    }

    async fn patch_json<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> DriveResult<T> {
        let response = self
            .execute_with_retry("PATCH", url, Some(body), GoogleResponseMode::Json)
            .await?;
        decode_json_response(response)
    }

    async fn execute_with_retry(
        &self,
        http_method: &'static str,
        url: &str,
        body: Option<&serde_json::Value>,
        response_mode: GoogleResponseMode,
    ) -> DriveResult<GoogleExecuteResponse> {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| async move {
            debug!(attempt, method = http_method, "drive request");

            match self
                .execute_once(http_method, url, body, response_mode)
                .await
            {
                Ok(response) => AttemptOutcome::Success(response),
                Err(error) if error.is_retryable() => AttemptOutcome::Retryable {
                    retry_after: error.retry_after(),
                    error,
                },
                Err(error) => AttemptOutcome::Terminal(error),
            }
        })
        .await
    }

    async fn execute_once(
        &self,
        http_method: &'static str,
        raw_url: &str,
        body: Option<&serde_json::Value>,
        response_mode: GoogleResponseMode,
    ) -> DriveResult<GoogleExecuteResponse> {
        let parsed_url = Url::parse(raw_url).map_err(|error| DriveError::Api {
            status_code: 400,
            message: format!("invalid request url: {error}"),
        })?;

        let mut parameters: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (name, value) in parsed_url.query_pairs() {
            parameters
                .entry(name.into_owned())
                .or_default()
                .push(value.into_owned());
        }

        let method_parameters = parameters
            .keys()
            .map(|name| {
                (
                    name.clone(),
                    DiscoveryParameter {
                        location: Some("query".to_string()),
                        required: false,
                        repeated: true,
                        type_name: Some("string".to_string()),
                        format: None,
                        description: None,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();

        let path = parsed_url.path().trim_start_matches('/').to_string();
        let method = DiscoveryMethod {
            key: format!("drive.transport.{}", http_method.to_ascii_lowercase()),
            id: format!("drive.transport.{}", http_method.to_ascii_lowercase()),
            http_method: http_method.to_string(),
            path: path.clone(),
            flat_path: None,
            canonical_path: path,
            resource_path: Vec::new(),
            description: None,
            scopes: Vec::new(),
            request_ref: None,
            response_ref: None,
            parameters: method_parameters,
            supports_media_download: http_method == "GET",
            supports_media_upload: false,
            media_upload: None,
        };

        let schemas = BTreeMap::new();
        let mut base_url = parsed_url.origin().ascii_serialization();
        if !base_url.ends_with('/') {
            base_url.push('/');
        }

        let mut request = GoogleExecuteRequest::new(&method, &schemas, &base_url);
        request.parameters = parameters;
        request.body = body.cloned();
        request.response_mode = response_mode;
        request.auth = Some(&self.auth);

        self.executor
            .execute(&request)
            .await
            .map_err(map_rest_error)
    }
}

fn decode_json_response<T: serde::de::DeserializeOwned>(
    response: GoogleExecuteResponse,
) -> DriveResult<T> {
    match response.body {
        GoogleResponseBody::Json(value) => serde_json::from_value(value).map_err(DriveError::Json),
        GoogleResponseBody::Binary(bytes) => {
            serde_json::from_slice(&bytes).map_err(DriveError::Json)
        }
        GoogleResponseBody::Empty => Err(DriveError::Api {
            status_code: response.status_code,
            message: "expected JSON response body".to_string(),
        }),
    }
}

fn map_rest_error(error: GoogleRestError) -> DriveError {
    match error {
        GoogleRestError::Http { source } => DriveError::Http(source),
        GoogleRestError::JsonDecode { source } => DriveError::Json(source),
        GoogleRestError::Api { error, .. } => map_google_api_error(error),
        other => DriveError::Api {
            status_code: 500,
            message: other.to_string(),
        },
    }
}

fn map_google_api_error(error: GoogleApiError) -> DriveError {
    match error.status_code {
        code if code == StatusCode::UNAUTHORIZED.as_u16() => DriveError::Unauthorized,
        code if code == StatusCode::TOO_MANY_REQUESTS.as_u16() => DriveError::RateLimited {
            retry_after_secs: 60,
        },
        code if code == StatusCode::NOT_FOUND.as_u16() => DriveError::FileNotFound {
            file_id: error.message,
        },
        code if code == StatusCode::FORBIDDEN.as_u16() => DriveError::Forbidden {
            message: error.message,
        },
        code => DriveError::Api {
            status_code: code,
            message: error.message,
        },
    }
}

fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = if chunk.len() > 1 {
            u32::from(chunk[1])
        } else {
            0
        };
        let b2 = if chunk.len() > 2 {
            u32::from(chunk[2])
        } else {
            0
        };
        let n = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((n >> 18) & 63) as usize] as char);
        result.push(CHARS[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((n >> 6) & 63) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(n & 63) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

/// Simple URL encoding helper.
mod urlencoding {
    use std::fmt::Write;

    pub fn encode(input: &str) -> String {
        let mut encoded = String::with_capacity(input.len());
        for byte in input.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    encoded.push(byte as char);
                }
                _ => {
                    let _ = write!(encoded, "%{byte:02X}");
                }
            }
        }
        encoded
    }
}
