//! `Box` API client.

use std::fmt;
use std::time::Duration;

use fcp_core::CredentialId;
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{BoxError, BoxResult},
    types::ApiErrorResponse,
};

/// Default `Box` API base URL.
pub const DEFAULT_BASE_URL: &str = "https://api.box.com/2.0";

/// Default `Box` upload base URL.
pub const DEFAULT_UPLOAD_URL: &str = "https://upload.box.com/api/2.0";

/// Authentication mode for the `Box` API.
#[derive(Clone)]
pub enum BoxAuth {
    /// `OAuth2` Bearer token.
    BearerToken(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl BoxAuth {
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

impl fmt::Debug for BoxAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BearerToken(_) => f.debug_tuple("BearerToken").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// `Box` API client.
pub struct BoxClient {
    client: Client,
    auth: BoxAuth,
    base_url: String,
    upload_url: String,
}

impl fmt::Debug for BoxClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoxClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .field("upload_url", &self.upload_url)
            .finish()
    }
}

impl BoxClient {
    /// Create a new `Box` client.
    pub fn new(auth: BoxAuth, base_url: Option<&str>, upload_url: Option<&str>) -> BoxResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-box/0.1.0 (FCP connector)")
            .build()?;

        Ok(Self {
            client,
            auth,
            base_url: base_url
                .unwrap_or(DEFAULT_BASE_URL)
                .trim_end_matches('/')
                .to_string(),
            upload_url: upload_url
                .unwrap_or(DEFAULT_UPLOAD_URL)
                .trim_end_matches('/')
                .to_string(),
        })
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            BoxAuth::BearerToken(token) => req.bearer_auth(token),
            BoxAuth::CredentialId(id) => req.header("X-FCP-Credential-Id", id.to_string()),
        }
    }

    async fn handle_response(&self, resp: Response) -> BoxResult<serde_json::Value> {
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
    ) -> BoxResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = resp.text().await.unwrap_or_default();
        let parsed = serde_json::from_str::<ApiErrorResponse>(&body).ok();
        let detail = parsed
            .as_ref()
            .and_then(|e| e.message.clone())
            .unwrap_or_else(|| body.clone());

        match status.as_u16() {
            401 => Err(BoxError::Unauthorized),
            403 => Err(BoxError::Forbidden),
            404 => Err(BoxError::NotFound { resource: detail }),
            409 => Err(BoxError::Conflict { message: detail }),
            429 => Err(BoxError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(BoxError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    #[instrument(skip(self, query), fields(url))]
    async fn get(
        &self,
        path: &str,
        query: Option<&[(&str, String)]>,
    ) -> BoxResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "GET request");
        let mut req = self
            .add_auth(self.client.get(&url))
            .header("Accept", "application/json");

        if let Some(q) = query {
            req = req.query(q);
        }

        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn post(&self, path: &str, body: &serde_json::Value) -> BoxResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "POST request");
        let req = self
            .add_auth(self.client.post(&url))
            .header("Accept", "application/json")
            .json(body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self), fields(url))]
    async fn post_upload(
        &self,
        path: &str,
        form: reqwest::multipart::Form,
    ) -> BoxResult<serde_json::Value> {
        let url = format!("{}{path}", self.upload_url);
        debug!(url = %url, "POST upload request");
        let req = self.add_auth(self.client.post(&url)).multipart(form);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self), fields(url))]
    async fn delete(&self, path: &str) -> BoxResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "DELETE request");
        let req = self
            .add_auth(self.client.delete(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- Files --

    /// Get file metadata.
    pub async fn get_file(&self, file_id: &str) -> BoxResult<serde_json::Value> {
        self.get(&format!("/files/{file_id}"), None).await
    }

    /// Upload a file (simplified — sends JSON attributes, not real multipart binary).
    /// In production, the actual binary content would be sent via multipart form.
    /// For the connector protocol, we pass metadata and let the host handle content.
    pub async fn upload_file(
        &self,
        folder_id: &str,
        name: &str,
        content: Option<&str>,
    ) -> BoxResult<serde_json::Value> {
        let attributes = serde_json::json!({
            "name": name,
            "parent": {"id": folder_id}
        });

        let attrs_part = reqwest::multipart::Part::text(attributes.to_string())
            .mime_str("application/json")
            .unwrap();

        let file_content = content.unwrap_or("").to_string();
        let file_part = reqwest::multipart::Part::text(file_content)
            .file_name(name.to_string())
            .mime_str("application/octet-stream")
            .unwrap();

        let form = reqwest::multipart::Form::new()
            .part("attributes", attrs_part)
            .part("file", file_part);

        self.post_upload("/files/content", form).await
    }

    /// Delete a file.
    pub async fn delete_file(&self, file_id: &str) -> BoxResult<serde_json::Value> {
        self.delete(&format!("/files/{file_id}")).await
    }

    // -- Folders --

    /// List folder items.
    pub async fn list_folder_items(
        &self,
        folder_id: &str,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> BoxResult<serde_json::Value> {
        let mut query = Vec::new();
        if let Some(l) = limit {
            query.push(("limit", l.to_string()));
        }
        if let Some(o) = offset {
            query.push(("offset", o.to_string()));
        }
        self.get(
            &format!("/folders/{folder_id}/items"),
            if query.is_empty() { None } else { Some(&query) },
        )
        .await
    }

    // -- Sharing --

    /// List collaborations for a file.
    pub async fn list_file_collaborations(&self, file_id: &str) -> BoxResult<serde_json::Value> {
        self.get(&format!("/files/{file_id}/collaborations"), None)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_token() {
        let auth = BoxAuth::BearerToken("secret-token".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("secret-token"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let token = BoxAuth::BearerToken("tok".into());
        assert!(!token.is_secretless());
        let cred = BoxAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label_bearer() {
        let token = BoxAuth::BearerToken("tok".into());
        assert_eq!(token.redacted_label(), "bearer_token:redacted");
    }

    #[test]
    fn auth_redacted_label_credential() {
        let cred = BoxAuth::CredentialId(CredentialId::new());
        let label = cred.redacted_label();
        assert!(label.starts_with("credential_id:"));
    }

    #[test]
    fn auth_debug_credential_id() {
        let cred = BoxAuth::CredentialId(CredentialId::new());
        let dbg = format!("{cred:?}");
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn default_base_url_value() {
        assert_eq!(DEFAULT_BASE_URL, "https://api.box.com/2.0");
    }

    #[test]
    fn default_upload_url_value() {
        assert_eq!(DEFAULT_UPLOAD_URL, "https://upload.box.com/api/2.0");
    }

    #[test]
    fn client_debug_format() {
        let client = BoxClient::new(BoxAuth::BearerToken("tok".into()), None, None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("BoxClient"));
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains("tok"));
    }

    #[test]
    fn client_custom_base_url() {
        let client = BoxClient::new(
            BoxAuth::BearerToken("tok".into()),
            Some("https://custom.box.com/2.0/"),
            None,
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("custom.box.com"));
    }

    #[test]
    fn client_custom_upload_url() {
        let client = BoxClient::new(
            BoxAuth::BearerToken("tok".into()),
            None,
            Some("https://upload.custom.box.com/api/2.0/"),
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("upload.custom.box.com"));
    }

    #[test]
    fn client_strips_trailing_slash() {
        let client = BoxClient::new(
            BoxAuth::BearerToken("tok".into()),
            Some("https://api.box.com/2.0/"),
            Some("https://upload.box.com/api/2.0/"),
        )
        .unwrap();
        let dbg = format!("{client:?}");
        // Trailing slash should be stripped
        assert!(!dbg.contains("2.0/\""));
    }

    #[test]
    fn client_with_credential_id() {
        let client =
            BoxClient::new(BoxAuth::CredentialId(CredentialId::new()), None, None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn auth_bearer_is_not_secretless() {
        let auth = BoxAuth::BearerToken("anything".into());
        assert!(!auth.is_secretless());
    }

    #[test]
    fn auth_credential_is_secretless() {
        let auth = BoxAuth::CredentialId(CredentialId::new());
        assert!(auth.is_secretless());
    }

    #[test]
    fn default_base_url_starts_with_https() {
        assert!(DEFAULT_BASE_URL.starts_with("https"));
    }

    #[test]
    fn default_upload_url_starts_with_https() {
        assert!(DEFAULT_UPLOAD_URL.starts_with("https"));
    }

    #[test]
    fn default_base_url_does_not_end_with_slash() {
        assert!(!DEFAULT_BASE_URL.ends_with('/'));
    }

    #[test]
    fn default_upload_url_does_not_end_with_slash() {
        assert!(!DEFAULT_UPLOAD_URL.ends_with('/'));
    }

    #[test]
    fn client_default_urls() {
        let client = BoxClient::new(BoxAuth::BearerToken("tok".into()), None, None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("api.box.com"));
        assert!(dbg.contains("upload.box.com"));
    }

    #[test]
    fn auth_credential_redacted_label_format() {
        let id = CredentialId::new();
        let expected = format!("credential_id:{id}");
        let auth = BoxAuth::CredentialId(id);
        assert_eq!(auth.redacted_label(), expected);
    }

    #[test]
    fn client_debug_does_not_leak_token() {
        let client =
            BoxClient::new(BoxAuth::BearerToken("secret-box-token".into()), None, None).unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("secret-box-token"));
    }

    #[test]
    fn auth_bearer_clone() {
        let auth = BoxAuth::BearerToken("tok".into());
        #[allow(clippy::redundant_clone)]
        let cloned = auth.clone();
        assert!(!cloned.is_secretless());
    }

    #[test]
    fn auth_credential_clone() {
        let auth = BoxAuth::CredentialId(CredentialId::new());
        #[allow(clippy::redundant_clone)]
        let cloned = auth.clone();
        assert!(cloned.is_secretless());
    }
}
