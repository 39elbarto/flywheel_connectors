//! Google Drive API v3 HTTP client.
//!
//! Uses `fcp-google-discovery` shared auth substrate.

use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use fcp_google_discovery::auth::GoogleMaterializedAuth;
use fcp_google_discovery::executor::{
    GoogleApiError, GoogleExecuteRequest, GoogleExecuteResponse, GoogleResponseBody,
    GoogleResponseMode, GoogleRestError, GoogleRestExecutor, GoogleUploadPayload,
};
use fcp_google_discovery::{DiscoveryMediaUpload, DiscoveryMethod, DiscoveryParameter};
use fcp_sdk::migration::{AttemptOutcome, HttpRetryConfig, RetryLoop};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Client, StatusCode, Url, header};
use serde_json::{Value, json};
use tracing::debug;

use crate::{
    error::{DriveError, DriveResult},
    types::{AboutResponse, DriveFile, DrivePermission, FileListResponse},
};

/// Default Google Drive API v3 base URL.
pub const DEFAULT_BASE_URL: &str = "https://www.googleapis.com/drive/v3";

/// Bounded Google Drive upload modes exposed by the connector.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum DriveUploadMode {
    /// One RFC 2387 `multipart/related` request for metadata and small content.
    Multipart,
    /// Session initialization followed by a full-content `PUT` to the validated session URL.
    Resumable,
}

/// Google Drive API v3 client.
pub struct DriveClient {
    executor: GoogleRestExecutor,
    auth: GoogleMaterializedAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
    total_requests: AtomicU64,
    provider_total_us: AtomicU64,
    retry_count: AtomicU64,
    rate_limit_count: AtomicU64,
    provider_request_bytes: AtomicU64,
    provider_response_bytes: AtomicU64,
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
            provider_total_us: AtomicU64::new(0),
            retry_count: AtomicU64::new(0),
            rate_limit_count: AtomicU64::new(0),
            provider_request_bytes: AtomicU64::new(0),
            provider_response_bytes: AtomicU64::new(0),
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

    /// Total measured provider-attempt time in microseconds.
    #[must_use]
    pub fn provider_total_us(&self) -> u64 {
        self.provider_total_us.load(Ordering::Relaxed)
    }

    /// Total retry attempts after the first provider attempt.
    #[must_use]
    pub fn retry_count(&self) -> u64 {
        self.retry_count.load(Ordering::Relaxed)
    }

    /// Total provider rate-limit responses.
    #[must_use]
    pub fn rate_limit_count(&self) -> u64 {
        self.rate_limit_count.load(Ordering::Relaxed)
    }

    /// Total serialized provider request-body bytes, excluding URLs and headers.
    #[must_use]
    pub fn provider_request_bytes(&self) -> u64 {
        self.provider_request_bytes.load(Ordering::Relaxed)
    }

    /// Total provider response-body bytes observed after decoding.
    #[must_use]
    pub fn provider_response_bytes(&self) -> u64 {
        self.provider_response_bytes.load(Ordering::Relaxed)
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
        corpora: Option<&str>,
        drive_id: Option<&str>,
    ) -> DriveResult<FileListResponse> {
        let mut url = format!(
            "{}/files?fields=kind,nextPageToken,incompleteSearch,files(id,name,mimeType,size,createdTime,modifiedTime,parents,webViewLink,trashed,shared,owners,driveId,md5Checksum,capabilities(canMoveItemWithinDrive),shortcutDetails)",
            self.base_url,
        );
        let safe_query = match query {
            Some(q) if q.trim().is_empty() => "trashed = false".to_string(),
            Some(q) => format!("({q}) and trashed = false"),
            None => "trashed = false".to_string(),
        };
        let _ = write!(url, "&q={}", urlencoding::encode(&safe_query));
        if let Some(max) = max_results {
            if !(1..=1000).contains(&max) {
                return Err(DriveError::Api {
                    status_code: 400,
                    message: "page_size must be between 1 and 1000".to_string(),
                });
            }
            let _ = write!(url, "&pageSize={max}");
        }
        if let Some(token) = page_token {
            let _ = write!(url, "&pageToken={}", urlencoding::encode(token));
        }
        if let Some(corpora) = corpora {
            if !matches!(corpora, "user" | "drive" | "allDrives") {
                return Err(DriveError::Api {
                    status_code: 400,
                    message: "corpora must be user, drive, or allDrives".to_string(),
                });
            }
            let _ = write!(url, "&corpora={corpora}");
        }
        if let Some(drive_id) = drive_id {
            let drive_id = sanitize_path_segment(drive_id, "drive_id")?;
            let _ = write!(url, "&driveId={}", urlencoding::encode(drive_id));
        }
        url.push_str("&supportsAllDrives=true&includeItemsFromAllDrives=true");
        self.get_json(&url).await
    }

    /// List items shared with the authenticated account, excluding trash.
    pub async fn list_shared_with_me(
        &self,
        query: Option<&str>,
        page_size: Option<u32>,
        page_token: Option<&str>,
    ) -> DriveResult<FileListResponse> {
        let q = query.map_or_else(
            || "sharedWithMe = true".to_string(),
            |value| format!("sharedWithMe = true and ({value})"),
        );
        self.list_files(Some(&q), page_size, page_token, Some("user"), None)
            .await
    }

    /// List Shared Drives visible to the authenticated account.
    pub async fn list_drives(
        &self,
        page_size: Option<u32>,
        page_token: Option<&str>,
    ) -> DriveResult<Value> {
        let mut url = format!(
            "{}/drives?fields=nextPageToken,drives(id,name,hidden,createdTime,capabilities)",
            self.base_url
        );
        if let Some(size) = page_size {
            if !(1..=100).contains(&size) {
                return Err(DriveError::Api {
                    status_code: 400,
                    message: "page_size must be between 1 and 100".into(),
                });
            }
            let _ = write!(url, "&pageSize={size}");
        }
        if let Some(token) = page_token {
            let _ = write!(url, "&pageToken={}", urlencoding::encode(token));
        }
        self.get_json(&url).await
    }

    /// Get a file's metadata by ID.
    pub async fn get_file(
        &self,
        file_id: &str,
        resource_key: Option<&str>,
    ) -> DriveResult<DriveFile> {
        let file_id = sanitize_path_segment(file_id, "file_id")?;
        let url = format!(
            "{}/files/{}?supportsAllDrives=true&fields=id,name,mimeType,size,description,createdTime,modifiedTime,parents,webViewLink,webContentLink,thumbnailLink,trashed,shared,owners,permissions,driveId,md5Checksum,capabilities(canMoveItemWithinDrive),shortcutDetails",
            self.base_url,
            urlencoding::encode(file_id),
        );
        self.get_json_with_resource_key(&url, file_id, resource_key)
            .await
    }

    /// Create a folder in Drive.
    pub async fn create_folder(
        &self,
        name: &str,
        parent_id: Option<&str>,
    ) -> DriveResult<DriveFile> {
        let url = format!(
            "{}/files?supportsAllDrives=true&fields=id,name,mimeType,parents,driveId,trashed",
            self.base_url
        );
        let mut body = serde_json::json!({
            "name": name,
            "mimeType": "application/vnd.google-apps.folder"
        });
        if let Some(parent) = parent_id {
            sanitize_path_segment(parent, "parent_id")?;
            body["parents"] = serde_json::json!([parent]);
        }
        self.post_json(&url, &body).await
    }

    /// Upload a new file using a real Drive media-upload protocol.
    pub async fn upload_file(
        &self,
        name: &str,
        mime_type: &str,
        parent_id: Option<&str>,
        content_base64: &str,
        mode: DriveUploadMode,
    ) -> DriveResult<DriveFile> {
        let bytes = decode_upload_content(content_base64)?;
        let mut metadata = serde_json::json!({
            "name": name,
            "mimeType": mime_type,
        });
        if let Some(parent) = parent_id {
            sanitize_path_segment(parent, "parent_id")?;
            metadata["parents"] = serde_json::json!([parent]);
        }
        self.execute_media_upload("POST", None, None, mime_type, bytes, metadata, mode)
            .await
    }

    /// Replace a file's content without exposing trash or delete semantics.
    pub async fn update_content(
        &self,
        file_id: &str,
        mime_type: &str,
        content_base64: &str,
        mode: DriveUploadMode,
        resource_key: Option<&str>,
    ) -> DriveResult<DriveFile> {
        let file_id = sanitize_path_segment(file_id, "file_id")?;
        if let Some(resource_key) = resource_key {
            sanitize_path_segment(resource_key, "resource_key")?;
        }
        let bytes = decode_upload_content(content_base64)?;
        self.execute_media_upload(
            "PATCH",
            Some(file_id),
            resource_key,
            mime_type,
            bytes,
            json!({"mimeType": mime_type}),
            mode,
        )
        .await
    }

    /// Download a file's content as bytes (returned as base64).
    pub async fn download_file(
        &self,
        file_id: &str,
        resource_key: Option<&str>,
    ) -> DriveResult<String> {
        let file_id = sanitize_path_segment(file_id, "file_id")?;
        let url = format!(
            "{}/files/{}?alt=media",
            self.base_url,
            urlencoding::encode(file_id),
        );
        let response = self
            .execute_with_retry_with_resource_key(
                "GET",
                &url,
                None,
                GoogleResponseMode::Binary,
                true,
                file_id,
                resource_key,
            )
            .await?;
        match response.body {
            GoogleResponseBody::Binary(bytes) => Ok(base64_encode(&bytes)),
            GoogleResponseBody::Json(value) => Ok(value.to_string()),
            GoogleResponseBody::Empty => Ok(String::new()),
        }
    }

    /// Export a Google Workspace-native file.
    pub async fn export_file(
        &self,
        file_id: &str,
        mime_type: &str,
        resource_key: Option<&str>,
    ) -> DriveResult<String> {
        let file_id = sanitize_path_segment(file_id, "file_id")?;
        let url = format!(
            "{}/files/{}/export?mimeType={}",
            self.base_url,
            urlencoding::encode(file_id),
            urlencoding::encode(mime_type),
        );
        let response = self
            .execute_with_retry_with_resource_key(
                "GET",
                &url,
                None,
                GoogleResponseMode::Binary,
                true,
                file_id,
                resource_key,
            )
            .await?;
        match response.body {
            GoogleResponseBody::Binary(bytes) => Ok(base64_encode(&bytes)),
            GoogleResponseBody::Empty => Ok(String::new()),
            GoogleResponseBody::Json(_) => Err(DriveError::Api {
                status_code: 502,
                message: "export returned JSON instead of file bytes".into(),
            }),
        }
    }

    /// List permissions on a file.
    pub async fn list_permissions(
        &self,
        file_id: &str,
        resource_key: Option<&str>,
    ) -> DriveResult<Value> {
        self.get_file_collection(file_id, "permissions", "permissions(id,type,role,emailAddress,displayName,domain,expirationTime,deleted,pendingOwner)", resource_key).await
    }

    /// List revisions on a file. Revision deletion is intentionally absent.
    pub async fn list_revisions(
        &self,
        file_id: &str,
        resource_key: Option<&str>,
    ) -> DriveResult<Value> {
        self.get_file_collection(
            file_id,
            "revisions",
            "revisions(id,mimeType,modifiedTime,keepForever,originalFilename,size)",
            resource_key,
        )
        .await
    }

    /// List comments on a file.
    pub async fn list_comments(
        &self,
        file_id: &str,
        resource_key: Option<&str>,
    ) -> DriveResult<Value> {
        self.get_file_collection(file_id, "comments", "comments(id,content,quotedFileContent,resolved,createdTime,modifiedTime,author,deleted,replies)", resource_key).await
    }

    async fn get_file_collection(
        &self,
        file_id: &str,
        collection: &str,
        fields: &str,
        resource_key: Option<&str>,
    ) -> DriveResult<Value> {
        let file_id = sanitize_path_segment(file_id, "file_id")?;
        let url = format!(
            "{}/files/{}/{}?fields=nextPageToken,{}&supportsAllDrives=true",
            self.base_url,
            urlencoding::encode(file_id),
            collection,
            fields
        );
        self.get_json_with_resource_key(&url, file_id, resource_key)
            .await
    }

    /// Update an explicit allowlist of safe file metadata fields.
    pub async fn update_metadata(&self, file_id: &str, patch: &Value) -> DriveResult<DriveFile> {
        let file_id = sanitize_path_segment(file_id, "file_id")?;
        let url = format!(
            "{}/files/{}?supportsAllDrives=true&fields=id,name,mimeType,description,starred,modifiedTime,parents,trashed,owners,permissions,driveId,md5Checksum,capabilities(canMoveItemWithinDrive)",
            self.base_url,
            urlencoding::encode(file_id)
        );
        self.patch_json(&url, patch).await
    }

    /// Move a file between folders without trashing it.
    pub async fn move_file(
        &self,
        file_id: &str,
        add_parent: &str,
        remove_parents: &[String],
    ) -> DriveResult<DriveFile> {
        let file_id = sanitize_path_segment(file_id, "file_id")?;
        let add_parent = sanitize_path_segment(add_parent, "add_parent")?;
        let mut url = format!(
            "{}/files/{}?supportsAllDrives=true&addParents={}&fields=id,name,mimeType,parents,trashed,owners,permissions,driveId,md5Checksum,capabilities(canMoveItemWithinDrive)",
            self.base_url,
            urlencoding::encode(file_id),
            urlencoding::encode(add_parent)
        );
        if !remove_parents.is_empty() {
            for parent in remove_parents {
                sanitize_path_segment(parent, "remove_parent")?;
            }
            let _ = write!(
                url,
                "&removeParents={}",
                urlencoding::encode(&remove_parents.join(","))
            );
        }
        self.patch_json(&url, &json!({})).await
    }

    /// Copy a file. Google-native shortcuts are created through `create_shortcut` instead.
    pub async fn copy_file(
        &self,
        file_id: &str,
        name: Option<&str>,
        parent_id: Option<&str>,
    ) -> DriveResult<DriveFile> {
        let file_id = sanitize_path_segment(file_id, "file_id")?;
        let url = format!(
            "{}/files/{}/copy?supportsAllDrives=true&fields=id,name,mimeType,parents,trashed,owners,capabilities",
            self.base_url,
            urlencoding::encode(file_id)
        );
        let mut body = json!({});
        if let Some(name) = name {
            body["name"] = json!(name);
        }
        if let Some(parent) = parent_id {
            sanitize_path_segment(parent, "parent_id")?;
            body["parents"] = json!([parent]);
        }
        self.post_json(&url, &body).await
    }

    /// Create a shortcut without modifying the target file.
    pub async fn create_shortcut(
        &self,
        name: &str,
        target_id: &str,
        parent_id: Option<&str>,
        target_resource_key: Option<&str>,
    ) -> DriveResult<DriveFile> {
        sanitize_path_segment(target_id, "target_id")?;
        let url = format!(
            "{}/files?supportsAllDrives=true&fields=id,name,mimeType,parents,shortcutDetails",
            self.base_url
        );
        let mut shortcut_details = json!({"targetId": target_id});
        if let Some(resource_key) = target_resource_key {
            sanitize_path_segment(resource_key, "target_resource_key")?;
            shortcut_details["targetResourceKey"] = json!(resource_key);
        }
        let mut body = json!({"name": name, "mimeType": "application/vnd.google-apps.shortcut", "shortcutDetails": shortcut_details});
        if let Some(parent) = parent_id {
            sanitize_path_segment(parent, "parent_id")?;
            body["parents"] = json!([parent]);
        }
        self.post_json(&url, &body).await
    }

    /// Add a comment to a file.
    pub async fn create_comment(&self, file_id: &str, content: &str) -> DriveResult<Value> {
        let file_id = sanitize_path_segment(file_id, "file_id")?;
        let url = format!(
            "{}/files/{}/comments?fields=id,content,createdTime,modifiedTime,author,resolved",
            self.base_url,
            urlencoding::encode(file_id)
        );
        self.post_json(&url, &json!({"content": content})).await
    }

    /// Add a reply to an existing comment.
    pub async fn create_reply(
        &self,
        file_id: &str,
        comment_id: &str,
        content: &str,
    ) -> DriveResult<Value> {
        let file_id = sanitize_path_segment(file_id, "file_id")?;
        let comment_id = sanitize_path_segment(comment_id, "comment_id")?;
        let url = format!(
            "{}/files/{}/comments/{}/replies?fields=id,content,createdTime,modifiedTime,author",
            self.base_url,
            urlencoding::encode(file_id),
            urlencoding::encode(comment_id)
        );
        self.post_json(&url, &json!({"content": content})).await
    }

    /// Add a permission.
    pub async fn add_permission(
        &self,
        file_id: &str,
        permission_type: &str,
        role: &str,
        email: Option<&str>,
        domain: Option<&str>,
    ) -> DriveResult<DrivePermission> {
        let file_id = sanitize_path_segment(file_id, "file_id")?;
        let url = format!(
            "{}/files/{}/permissions?supportsAllDrives=true&sendNotificationEmail=false&fields=id,type,role,emailAddress,displayName,domain,expirationTime",
            self.base_url,
            urlencoding::encode(file_id),
        );
        let mut body = json!({"type": permission_type, "role": role});
        if let Some(email) = email {
            body["emailAddress"] = json!(email);
        }
        if let Some(domain) = domain {
            body["domain"] = json!(domain);
        }
        self.post_json(&url, &body).await
    }

    /// Update an existing permission role.
    pub async fn update_permission(
        &self,
        file_id: &str,
        permission_id: &str,
        role: &str,
    ) -> DriveResult<DrivePermission> {
        let file_id = sanitize_path_segment(file_id, "file_id")?;
        let permission_id = sanitize_path_segment(permission_id, "permission_id")?;
        let url = format!(
            "{}/files/{}/permissions/{}?supportsAllDrives=true&fields=id,type,role,emailAddress,displayName,domain,expirationTime",
            self.base_url,
            urlencoding::encode(file_id),
            urlencoding::encode(permission_id)
        );
        self.patch_json(&url, &json!({"role": role})).await
    }

    /// Revoke one ACL entry. This cannot delete or trash a Drive file.
    pub async fn revoke_permission(&self, file_id: &str, permission_id: &str) -> DriveResult<()> {
        let file_id = sanitize_path_segment(file_id, "file_id")?;
        let permission_id = sanitize_path_segment(permission_id, "permission_id")?;
        let url = format!(
            "{}/files/{}/permissions/{}?supportsAllDrives=true",
            self.base_url,
            urlencoding::encode(file_id),
            urlencoding::encode(permission_id)
        );
        let response = self
            .execute_with_retry("DELETE", &url, None, GoogleResponseMode::Json, true)
            .await?;
        match response.body {
            GoogleResponseBody::Empty | GoogleResponseBody::Json(_) => Ok(()),
            GoogleResponseBody::Binary(_) => Err(DriveError::Api {
                status_code: 502,
                message: "unexpected binary permission response".into(),
            }),
        }
    }

    /// Restore a trashed file. No operation exists for setting `trashed=true`.
    pub async fn restore_file(&self, file_id: &str) -> DriveResult<DriveFile> {
        let file_id = sanitize_path_segment(file_id, "file_id")?;
        let url = format!(
            "{}/files/{}?supportsAllDrives=true&fields=id,name,mimeType,parents,trashed,owners,capabilities",
            self.base_url,
            urlencoding::encode(file_id)
        );
        self.patch_json(&url, &json!({"trashed": false})).await
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
            .execute_with_retry("GET", url, None, GoogleResponseMode::Json, true)
            .await?;
        decode_json_response(response)
    }

    async fn get_json_with_resource_key<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        file_id: &str,
        resource_key: Option<&str>,
    ) -> DriveResult<T> {
        let response = self
            .execute_with_retry_with_resource_key(
                "GET",
                url,
                None,
                GoogleResponseMode::Json,
                true,
                file_id,
                resource_key,
            )
            .await?;
        decode_json_response(response)
    }

    async fn execute_with_retry_with_resource_key(
        &self,
        http_method: &'static str,
        url: &str,
        body: Option<&Value>,
        response_mode: GoogleResponseMode,
        replay_safe: bool,
        file_id: &str,
        resource_key: Option<&str>,
    ) -> DriveResult<GoogleExecuteResponse> {
        let Some(resource_key) = resource_key else {
            return self
                .execute_with_retry(http_method, url, body, response_mode, replay_safe)
                .await;
        };
        sanitize_path_segment(file_id, "file_id")?;
        sanitize_path_segment(resource_key, "resource_key")?;
        let separator = if url.contains('?') { '&' } else { '?' };
        let keyed_url = format!(
            "{url}{separator}resourceKey={}",
            urlencoding::encode(resource_key)
        );
        self.execute_with_retry(http_method, &keyed_url, body, response_mode, replay_safe)
            .await
    }

    async fn post_json<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> DriveResult<T> {
        let response = self
            .execute_with_retry("POST", url, Some(body), GoogleResponseMode::Json, false)
            .await?;
        decode_json_response(response)
    }

    async fn patch_json<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> DriveResult<T> {
        let response = self
            .execute_with_retry("PATCH", url, Some(body), GoogleResponseMode::Json, true)
            .await?;
        decode_json_response(response)
    }

    /// Execute with retry.
    ///
    /// `replay_safe` states whether repeating this request can duplicate a
    /// side effect (br-kxd3e). It is a parameter rather than a function of
    /// `http_method` because Google models several state changes — and some
    /// pure reads — as POSTs, so the verb alone decides nothing.
    async fn execute_with_retry(
        &self,
        http_method: &'static str,
        url: &str,
        body: Option<&serde_json::Value>,
        response_mode: GoogleResponseMode,
        replay_safe: bool,
    ) -> DriveResult<GoogleExecuteResponse> {
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let request_bytes = body
            .and_then(|value| serde_json::to_vec(value).ok())
            .map_or(0, |encoded| {
                u64::try_from(encoded.len()).unwrap_or(u64::MAX)
            });

        RetryLoop::execute(&ctx, &policy, |attempt| async move {
            debug!(attempt, method = http_method, "drive request");
            self.total_requests.fetch_add(1, Ordering::Relaxed);
            self.provider_request_bytes
                .fetch_add(request_bytes, Ordering::Relaxed);
            if attempt > 0 {
                self.retry_count.fetch_add(1, Ordering::Relaxed);
            }
            let started_at = Instant::now();
            let result = self
                .execute_once(http_method, url, body, response_mode)
                .await;
            self.provider_total_us.fetch_add(
                u64::try_from(started_at.elapsed().as_micros()).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
            if matches!(&result, Err(DriveError::RateLimited { .. })) {
                self.rate_limit_count.fetch_add(1, Ordering::Relaxed);
            }
            if let Ok(response) = &result {
                self.provider_response_bytes.fetch_add(
                    google_response_body_bytes(&response.body),
                    Ordering::Relaxed,
                );
            }
            match result {
                Ok(response) => AttemptOutcome::Success(response),
                Err(error) if error.is_retryable() => {
                    // A rate limit was refused WITHOUT performing the work, so
                    // it stays retryable; a 5xx means Google received the
                    // request and may already have done it.
                    let replayable = replay_safe || error.replay_is_safe();
                    let retry_after = error.retry_after();
                    AttemptOutcome::retryable_if_replayable(error, retry_after, replayable)
                }
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

    async fn execute_media_upload(
        &self,
        http_method: &'static str,
        file_id: Option<&str>,
        resource_key: Option<&str>,
        mime_type: &str,
        bytes: Vec<u8>,
        metadata: Value,
        mode: DriveUploadMode,
    ) -> DriveResult<DriveFile> {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let provider_started_at = Instant::now();
        let upload_request_bytes = u64::try_from(bytes.len())
            .unwrap_or(u64::MAX)
            .saturating_add(serde_json::to_vec(&metadata).map_or(0, |encoded| {
                u64::try_from(encoded.len()).unwrap_or(u64::MAX)
            }));
        self.provider_request_bytes
            .fetch_add(upload_request_bytes, Ordering::Relaxed);
        let parsed_base = Url::parse(&self.base_url).map_err(|error| DriveError::Api {
            status_code: 400,
            message: format!("invalid Drive base URL: {error}"),
        })?;
        let api_path = parsed_base.path().trim_matches('/');
        let upload_path = file_id.map_or_else(
            || format!("upload/{api_path}/files"),
            |file_id| format!("upload/{api_path}/files/{}", urlencoding::encode(file_id)),
        );
        let mut origin = parsed_base.origin().ascii_serialization();
        if !origin.ends_with('/') {
            origin.push('/');
        }

        let mut parameters = BTreeMap::new();
        parameters.insert("supportsAllDrives".to_string(), vec!["true".to_string()]);
        parameters.insert(
            "fields".to_string(),
            vec!["id,name,mimeType,size,parents,trashed,driveId,md5Checksum".to_string()],
        );
        if let Some(resource_key) = resource_key {
            parameters.insert("resourceKey".to_string(), vec![resource_key.to_string()]);
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
            .collect();
        let method = DiscoveryMethod {
            key: format!("drive.upload.{}", http_method.to_ascii_lowercase()),
            id: format!("drive.upload.{}", http_method.to_ascii_lowercase()),
            http_method: http_method.to_string(),
            path: upload_path.clone(),
            flat_path: None,
            canonical_path: upload_path.clone(),
            resource_path: Vec::new(),
            description: None,
            scopes: Vec::new(),
            request_ref: None,
            response_ref: None,
            parameters: method_parameters,
            supports_media_download: false,
            supports_media_upload: true,
            media_upload: Some(DiscoveryMediaUpload {
                accept: vec!["*/*".to_string()],
                max_size: None,
                simple_path: Some(upload_path.clone()),
                resumable_path: Some(upload_path),
            }),
        };
        let upload = match mode {
            DriveUploadMode::Multipart => {
                GoogleUploadPayload::multipart(mime_type, bytes, metadata)
            }
            DriveUploadMode::Resumable => {
                GoogleUploadPayload::resumable(mime_type, bytes, metadata)
            }
        };
        let schemas = BTreeMap::new();
        let mut request = GoogleExecuteRequest::new(&method, &schemas, &origin);
        request.parameters = parameters;
        request.upload = Some(upload);
        request.response_mode = GoogleResponseMode::Json;
        request.auth = Some(&self.auth);

        let response = self
            .executor
            .execute(&request)
            .await
            .map_err(map_rest_error);
        self.provider_total_us.fetch_add(
            u64::try_from(provider_started_at.elapsed().as_micros()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
        if matches!(&response, Err(DriveError::RateLimited { .. })) {
            self.rate_limit_count.fetch_add(1, Ordering::Relaxed);
        }
        if let Ok(response) = &response {
            self.provider_response_bytes.fetch_add(
                google_response_body_bytes(&response.body),
                Ordering::Relaxed,
            );
        }
        decode_json_response(response?)
    }
}

fn google_response_body_bytes(body: &GoogleResponseBody) -> u64 {
    match body {
        GoogleResponseBody::Empty => 0,
        GoogleResponseBody::Json(value) => serde_json::to_vec(value).map_or(0, |encoded| {
            u64::try_from(encoded.len()).unwrap_or(u64::MAX)
        }),
        GoogleResponseBody::Binary(bytes) => u64::try_from(bytes.len()).unwrap_or(u64::MAX),
    }
}

fn decode_upload_content(content_base64: &str) -> DriveResult<Vec<u8>> {
    BASE64_STANDARD
        .decode(content_base64)
        .map_err(|error| DriveError::Api {
            status_code: 400,
            message: format!("content_base64 is not valid standard base64: {error}"),
        })
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
            retry_after_secs: error.retry_after_ms.map_or(60, |ms| ms / 1000),
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

/// Validate that a user-supplied ID is safe to interpolate into a URL path segment.
///
/// Rejects empty strings, path/query separators, traversal sequences (`..`),
/// and percent-encoded variants that could reappear after double decoding.
fn sanitize_path_segment<'a>(value: &'a str, field: &str) -> DriveResult<&'a str> {
    if value.trim().is_empty() {
        return Err(DriveError::Api {
            status_code: 400,
            message: format!("{field} must not be empty"),
        });
    }

    let lower = value.to_ascii_lowercase();
    if value.contains('/')
        || value.contains('\\')
        || value.contains("..")
        || value.contains('?')
        || value.contains('#')
        || lower.contains("%2f")
        || lower.contains("%5c")
        || lower.contains("%3f")
        || lower.contains("%23")
        || lower.contains("%25")
    {
        return Err(DriveError::Api {
            status_code: 400,
            message: format!("{field} contains path traversal characters"),
        });
    }

    Ok(value)
}

/// Fuzz-only entry points for Drive client parsers.
///
/// Exposed for the Drive path-segment fuzz target so the fuzz crate can
/// exercise the private guard before Drive file IDs enter REST URL paths.
///
/// Bead flywheel_connectors-grb4c.
#[doc(hidden)]
pub mod __fuzz {
    use super::sanitize_path_segment;

    /// Validate an arbitrary Drive URL path segment candidate.
    #[must_use]
    pub fn sanitize_path_segment_candidate(value: &str) -> bool {
        sanitize_path_segment(value, "file_id").is_ok()
    }
}

#[must_use]
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

#[cfg(test)]
mod tests {
    use super::sanitize_path_segment;

    #[test]
    fn sanitize_path_segment_rejects_traversal() {
        assert!(sanitize_path_segment("../admin", "file_id").is_err());
        assert!(sanitize_path_segment("foo/bar", "file_id").is_err());
        assert!(sanitize_path_segment("foo\\bar", "file_id").is_err());
        assert!(sanitize_path_segment("foo%2fbar", "file_id").is_err());
        assert!(sanitize_path_segment("foo%5Cbar", "file_id").is_err());
        assert!(sanitize_path_segment("file?alt=media", "file_id").is_err());
        assert!(sanitize_path_segment("file#frag", "file_id").is_err());
        assert!(sanitize_path_segment("file%3Falt=media", "file_id").is_err());
        assert!(sanitize_path_segment("file%23frag", "file_id").is_err());
        assert!(sanitize_path_segment("", "file_id").is_err());
        assert!(sanitize_path_segment("  ", "file_id").is_err());
    }

    #[test]
    fn sanitize_path_segment_rejects_double_percent_encoding() {
        assert!(sanitize_path_segment("foo%252Fbar", "file_id").is_err());
        assert!(sanitize_path_segment("foo%252fbar", "file_id").is_err());
        assert!(sanitize_path_segment("file%2523frag", "file_id").is_err());
        assert!(sanitize_path_segment("file%2523FRAG", "file_id").is_err());
        assert!(sanitize_path_segment("foo%25", "file_id").is_err());
    }

    #[test]
    fn sanitize_path_segment_accepts_valid() {
        assert!(matches!(
            sanitize_path_segment("1AbC_def-123", "file_id"),
            Ok("1AbC_def-123")
        ));
        assert!(matches!(
            sanitize_path_segment("drive.file.id", "file_id"),
            Ok("drive.file.id")
        ));
    }
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
