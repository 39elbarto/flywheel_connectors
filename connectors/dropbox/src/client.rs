//! Dropbox API client.
//!
//! All Dropbox API v2 endpoints use POST with JSON bodies,
//! even for read operations.

#![allow(clippy::doc_markdown)]

use std::fmt;
use std::time::Duration;

use fcp_core::CredentialId;
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{DropboxError, DropboxResult},
    types::ApiErrorResponse,
};

/// Default Dropbox API base URL (metadata operations).
pub const DEFAULT_BASE_URL: &str = "https://api.dropboxapi.com/2";

/// Default Dropbox content URL (file content operations).
pub const DEFAULT_CONTENT_URL: &str = "https://content.dropboxapi.com/2";

/// Authentication mode for the Dropbox API.
#[derive(Clone)]
pub enum DropboxAuth {
    /// OAuth2 Bearer token.
    BearerToken(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl DropboxAuth {
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::BearerToken(_) => "bearer_token:redacted".to_string(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for DropboxAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BearerToken(_) => f.debug_tuple("BearerToken").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// Dropbox API client.
///
/// All API calls use POST with JSON body, per Dropbox API v2 convention.
pub struct DropboxClient {
    client: Client,
    auth: DropboxAuth,
    base_url: String,
    content_url: String,
}

impl fmt::Debug for DropboxClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DropboxClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .field("content_url", &self.content_url)
            .finish()
    }
}

impl DropboxClient {
    /// Create a new Dropbox client.
    pub fn new(
        auth: DropboxAuth,
        base_url: Option<&str>,
        content_url: Option<&str>,
    ) -> DropboxResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-dropbox/0.1.0 (FCP connector)")
            .build()?;

        Ok(Self {
            client,
            auth,
            base_url: base_url
                .unwrap_or(DEFAULT_BASE_URL)
                .trim_end_matches('/')
                .to_string(),
            content_url: content_url
                .unwrap_or(DEFAULT_CONTENT_URL)
                .trim_end_matches('/')
                .to_string(),
        })
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            DropboxAuth::BearerToken(token) => req.bearer_auth(token),
            DropboxAuth::CredentialId(id) => req.header("X-FCP-Credential-Id", id.to_string()),
        }
    }

    async fn handle_response(&self, resp: Response) -> DropboxResult<serde_json::Value> {
        let status = resp.status();
        if status.is_success() {
            let body = resp.text().await?;
            if body.is_empty() {
                return Ok(serde_json::json!({}));
            }
            Ok(serde_json::from_str(&body)?)
        } else {
            self.handle_error(status, resp).await
        }
    }

    async fn handle_error(
        &self,
        status: StatusCode,
        resp: Response,
    ) -> DropboxResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = resp.text().await.unwrap_or_default();

        // Dropbox error format: {"error_summary": "path/not_found/...", "error": {".tag": "path", ...}}
        let parsed = serde_json::from_str::<ApiErrorResponse>(&body).ok();
        let detail = parsed
            .as_ref()
            .and_then(|e| e.error_summary.clone())
            .unwrap_or_else(|| body.clone());

        match status.as_u16() {
            401 => Err(DropboxError::Unauthorized),
            403 => Err(DropboxError::Forbidden),
            404 | 409 => {
                // Dropbox uses 409 for path/not_found in some cases
                if detail.contains("not_found") {
                    Err(DropboxError::NotFound { resource: detail })
                } else {
                    Err(DropboxError::Api {
                        status_code: status.as_u16(),
                        message: detail,
                    })
                }
            }
            429 => Err(DropboxError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(DropboxError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    /// Send a POST request to the metadata API.
    #[instrument(skip(self, body), fields(url))]
    async fn post(
        &self,
        endpoint: &str,
        body: &serde_json::Value,
    ) -> DropboxResult<serde_json::Value> {
        let url = format!("{}{endpoint}", self.base_url);
        debug!(url = %url, "POST request");
        let req = self
            .add_auth(self.client.post(&url))
            .header("Content-Type", "application/json")
            .json(body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- Files --

    /// List files and folders at a path.
    /// Dropbox API: `POST /files/list_folder`
    pub async fn list_folder(&self, path: &str) -> DropboxResult<serde_json::Value> {
        self.post("/files/list_folder", &serde_json::json!({ "path": path }))
            .await
    }

    /// Get metadata for a file or folder.
    /// Dropbox API: `POST /files/get_metadata`
    pub async fn get_metadata(&self, path: &str) -> DropboxResult<serde_json::Value> {
        self.post("/files/get_metadata", &serde_json::json!({ "path": path }))
            .await
    }

    /// Continue listing files using a cursor.
    /// Dropbox API: `POST /files/list_folder/continue`
    pub async fn list_folder_continue(&self, cursor: &str) -> DropboxResult<serde_json::Value> {
        self.post(
            "/files/list_folder/continue",
            &serde_json::json!({ "cursor": cursor }),
        )
        .await
    }

    /// Create a folder.
    /// Dropbox API: `POST /files/create_folder_v2`
    pub async fn create_folder(&self, path: &str) -> DropboxResult<serde_json::Value> {
        self.post(
            "/files/create_folder_v2",
            &serde_json::json!({ "path": path, "autorename": false }),
        )
        .await
    }

    /// Delete a file or folder.
    /// Dropbox API: `POST /files/delete_v2`
    pub async fn delete(&self, path: &str) -> DropboxResult<serde_json::Value> {
        self.post("/files/delete_v2", &serde_json::json!({ "path": path }))
            .await
    }

    /// Move a file or folder.
    /// Dropbox API: `POST /files/move_v2`
    pub async fn move_path(
        &self,
        from_path: &str,
        to_path: &str,
    ) -> DropboxResult<serde_json::Value> {
        self.post(
            "/files/move_v2",
            &serde_json::json!({ "from_path": from_path, "to_path": to_path }),
        )
        .await
    }

    /// Copy a file or folder.
    /// Dropbox API: `POST /files/copy_v2`
    pub async fn copy_path(
        &self,
        from_path: &str,
        to_path: &str,
    ) -> DropboxResult<serde_json::Value> {
        self.post(
            "/files/copy_v2",
            &serde_json::json!({ "from_path": from_path, "to_path": to_path }),
        )
        .await
    }

    /// Search for files.
    /// Dropbox API: `POST /files/search_v2`
    pub async fn search(&self, query: &str) -> DropboxResult<serde_json::Value> {
        self.post("/files/search_v2", &serde_json::json!({ "query": query }))
            .await
    }

    // -- Users --

    /// Get space usage for the current user.
    /// Dropbox API: `POST /users/get_space_usage` (empty body)
    pub async fn get_space_usage(&self) -> DropboxResult<serde_json::Value> {
        self.post("/users/get_space_usage", &serde_json::json!(null))
            .await
    }

    /// Get current account info.
    /// Dropbox API: `POST /users/get_current_account` (empty body)
    pub async fn get_current_account(&self) -> DropboxResult<serde_json::Value> {
        self.post("/users/get_current_account", &serde_json::json!(null))
            .await
    }

    // -- Sharing --

    /// List shared links.
    /// Dropbox API: `POST /sharing/list_shared_links`
    pub async fn list_shared_links(&self, path: Option<&str>) -> DropboxResult<serde_json::Value> {
        let mut body = serde_json::json!({});
        if let Some(p) = path {
            body["path"] = serde_json::json!(p);
        }
        self.post("/sharing/list_shared_links", &body).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_token() {
        let auth = DropboxAuth::BearerToken("secret-token".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("secret-token"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let token = DropboxAuth::BearerToken("tok".into());
        assert!(!token.is_secretless());
        let cred = DropboxAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label_bearer() {
        let token = DropboxAuth::BearerToken("tok".into());
        assert_eq!(token.redacted_label(), "bearer_token:redacted");
    }

    #[test]
    fn auth_redacted_label_credential() {
        let cred = DropboxAuth::CredentialId(CredentialId::new());
        let label = cred.redacted_label();
        assert!(label.starts_with("credential_id:"));
    }

    #[test]
    fn auth_debug_credential_id() {
        let cred = DropboxAuth::CredentialId(CredentialId::new());
        let dbg = format!("{cred:?}");
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn default_base_url_value() {
        assert_eq!(DEFAULT_BASE_URL, "https://api.dropboxapi.com/2");
    }

    #[test]
    fn default_content_url_value() {
        assert_eq!(DEFAULT_CONTENT_URL, "https://content.dropboxapi.com/2");
    }

    #[test]
    fn client_debug_format() {
        let client =
            DropboxClient::new(DropboxAuth::BearerToken("tok".into()), None, None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("DropboxClient"));
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains("tok"));
    }

    #[test]
    fn client_custom_base_url() {
        let client = DropboxClient::new(
            DropboxAuth::BearerToken("tok".into()),
            Some("https://custom.dropboxapi.com/2/"),
            None,
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("custom.dropboxapi.com"));
    }

    #[test]
    fn client_custom_content_url() {
        let client = DropboxClient::new(
            DropboxAuth::BearerToken("tok".into()),
            None,
            Some("https://custom.content.dropboxapi.com/2/"),
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("custom.content.dropboxapi.com"));
    }

    #[test]
    fn client_strips_trailing_slash() {
        let client = DropboxClient::new(
            DropboxAuth::BearerToken("tok".into()),
            Some("https://api.dropboxapi.com/2/"),
            Some("https://content.dropboxapi.com/2/"),
        )
        .unwrap();
        let dbg = format!("{client:?}");
        // Trailing slash should be stripped
        assert!(!dbg.contains("2/\""));
    }

    #[test]
    fn client_default_urls() {
        let client =
            DropboxClient::new(DropboxAuth::BearerToken("tok".into()), None, None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("api.dropboxapi.com"));
        assert!(dbg.contains("content.dropboxapi.com"));
    }

    #[test]
    fn auth_bearer_clone() {
        let auth = DropboxAuth::BearerToken("test".into());
        #[allow(clippy::redundant_clone)]
        let cloned = auth.clone();
        assert!(!cloned.is_secretless());
    }

    #[test]
    fn auth_credential_clone() {
        let auth = DropboxAuth::CredentialId(CredentialId::new());
        #[allow(clippy::redundant_clone)]
        let cloned = auth.clone();
        assert!(cloned.is_secretless());
    }

    #[test]
    fn client_with_credential_id() {
        let client =
            DropboxClient::new(DropboxAuth::CredentialId(CredentialId::new()), None, None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn auth_bearer_is_not_secretless() {
        let auth = DropboxAuth::BearerToken("anything".into());
        assert!(!auth.is_secretless());
    }

    #[test]
    fn auth_credential_is_secretless() {
        let auth = DropboxAuth::CredentialId(CredentialId::new());
        assert!(auth.is_secretless());
    }

    #[test]
    fn default_base_url_starts_with_https() {
        assert!(DEFAULT_BASE_URL.starts_with("https"));
    }

    #[test]
    fn default_content_url_starts_with_https() {
        assert!(DEFAULT_CONTENT_URL.starts_with("https"));
    }

    #[test]
    fn default_base_url_does_not_end_with_slash() {
        assert!(!DEFAULT_BASE_URL.ends_with('/'));
    }

    #[test]
    fn default_content_url_does_not_end_with_slash() {
        assert!(!DEFAULT_CONTENT_URL.ends_with('/'));
    }

    #[test]
    fn client_debug_contains_dropbox_client() {
        let client =
            DropboxClient::new(DropboxAuth::BearerToken("tok".into()), None, None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("DropboxClient"));
    }

    #[test]
    fn auth_credential_redacted_label_format() {
        let id = CredentialId::new();
        let expected = format!("credential_id:{id}");
        let auth = DropboxAuth::CredentialId(id);
        assert_eq!(auth.redacted_label(), expected);
    }

    #[test]
    fn client_debug_does_not_leak_token() {
        let client = DropboxClient::new(
            DropboxAuth::BearerToken("super-secret-token-xyz".into()),
            None,
            None,
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("super-secret-token-xyz"));
    }
}
