//! `PandaDoc` API client.

use std::fmt;
use std::time::Duration;

use fcp_core::CredentialId;
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{PandaDocError, PandaDocResult},
    types::ApiErrorResponse,
};

/// Default `PandaDoc` API base URL.
pub const DEFAULT_BASE_URL: &str = "https://api.pandadoc.com/public/v1";

/// Authentication mode for the `PandaDoc` API.
#[derive(Clone)]
pub enum PandaDocAuth {
    /// Bearer token (API key).
    BearerToken(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl PandaDocAuth {
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

impl fmt::Debug for PandaDocAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BearerToken(_) => f.debug_tuple("BearerToken").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// `PandaDoc` API client.
pub struct PandaDocClient {
    client: Client,
    auth: PandaDocAuth,
    base_url: String,
}

impl fmt::Debug for PandaDocClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PandaDocClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl PandaDocClient {
    /// Create a new `PandaDoc` client.
    pub fn new(auth: PandaDocAuth, base_url: Option<&str>) -> PandaDocResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-pandadoc/0.1.0 (FCP connector)")
            .build()?;

        Ok(Self {
            client,
            auth,
            base_url: base_url
                .unwrap_or(DEFAULT_BASE_URL)
                .trim_end_matches('/')
                .to_string(),
        })
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            PandaDocAuth::BearerToken(token) => req.bearer_auth(token),
            PandaDocAuth::CredentialId(id) => req.header("X-FCP-Credential-Id", id.to_string()),
        }
    }

    async fn handle_response(&self, resp: Response) -> PandaDocResult<serde_json::Value> {
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
    ) -> PandaDocResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = resp.text().await.unwrap_or_default();
        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.detail)
            .unwrap_or_else(|| body.clone());

        match status.as_u16() {
            401 => Err(PandaDocError::Unauthorized),
            403 => Err(PandaDocError::Forbidden),
            404 => Err(PandaDocError::NotFound { resource: detail }),
            429 => Err(PandaDocError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(PandaDocError::Api {
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
    ) -> PandaDocResult<serde_json::Value> {
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
    async fn post(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> PandaDocResult<serde_json::Value> {
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
    async fn delete(&self, path: &str) -> PandaDocResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "DELETE request");
        let req = self
            .add_auth(self.client.delete(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- Documents --

    /// List documents, optionally filtered by status.
    pub async fn list_documents(
        &self,
        status: Option<&str>,
        count: Option<i64>,
    ) -> PandaDocResult<serde_json::Value> {
        let mut query = Vec::new();
        if let Some(s) = status {
            query.push(("status", s.to_string()));
        }
        if let Some(c) = count {
            query.push(("count", c.to_string()));
        }
        self.get(
            "/documents",
            if query.is_empty() { None } else { Some(&query) },
        )
        .await
    }

    /// Get a document by ID.
    pub async fn get_document(&self, document_id: &str) -> PandaDocResult<serde_json::Value> {
        self.get(&format!("/documents/{document_id}"), None).await
    }

    /// Create a document from a template.
    pub async fn create_document(
        &self,
        body: &serde_json::Value,
    ) -> PandaDocResult<serde_json::Value> {
        self.post("/documents", body).await
    }

    /// Send a document for signing.
    pub async fn send_document(
        &self,
        document_id: &str,
        body: &serde_json::Value,
    ) -> PandaDocResult<serde_json::Value> {
        self.post(&format!("/documents/{document_id}/send"), body)
            .await
    }

    /// Delete a document.
    pub async fn delete_document(&self, document_id: &str) -> PandaDocResult<serde_json::Value> {
        self.delete(&format!("/documents/{document_id}")).await
    }

    // -- Templates --

    /// List all templates.
    pub async fn list_templates(&self) -> PandaDocResult<serde_json::Value> {
        self.get("/templates", None).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_token() {
        let auth = PandaDocAuth::BearerToken("secret-api-key".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("secret-api-key"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let token = PandaDocAuth::BearerToken("tok".into());
        assert!(!token.is_secretless());
        let cred = PandaDocAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label() {
        let token = PandaDocAuth::BearerToken("tok".into());
        assert_eq!(token.redacted_label(), "bearer_token:redacted");
    }

    #[test]
    fn auth_credential_id_redacted_label() {
        let cred = PandaDocAuth::CredentialId(CredentialId::new());
        let label = cred.redacted_label();
        assert!(label.starts_with("credential_id:"));
    }

    #[test]
    fn auth_clone_bearer() {
        let bearer = PandaDocAuth::BearerToken("test-key".into());
        let cloned = bearer.clone();
        assert_eq!(cloned.redacted_label(), "bearer_token:redacted");
        assert_eq!(bearer.redacted_label(), "bearer_token:redacted");
        assert!(!cloned.is_secretless());
    }

    #[test]
    fn auth_clone_credential() {
        let cred = PandaDocAuth::CredentialId(CredentialId::new());
        let cloned = cred.clone();
        assert!(cloned.is_secretless());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_debug_credential_id_shows_id() {
        let id = CredentialId::new();
        let id_str = id.to_string();
        let auth = PandaDocAuth::CredentialId(id);
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("CredentialId"));
        assert!(dbg.contains(&id_str));
    }

    #[test]
    fn client_new_default_url() {
        let client = PandaDocClient::new(PandaDocAuth::BearerToken("tok".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains(DEFAULT_BASE_URL));
    }

    #[test]
    fn client_new_custom_url() {
        let client = PandaDocClient::new(
            PandaDocAuth::BearerToken("tok".into()),
            Some("https://custom.pandadoc.com/v1"),
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("https://custom.pandadoc.com/v1"));
    }

    #[test]
    fn client_new_trims_trailing_slash() {
        let client = PandaDocClient::new(
            PandaDocAuth::BearerToken("tok".into()),
            Some("https://api.pandadoc.com/public/v1/"),
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("v1/\""));
    }

    #[test]
    fn client_debug_redacts_token() {
        let client =
            PandaDocClient::new(PandaDocAuth::BearerToken("my-secret-api-key".into()), None)
                .unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("my-secret-api-key"));
        assert!(dbg.contains("PandaDocClient"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn client_debug_shows_base_url() {
        let client = PandaDocClient::new(
            PandaDocAuth::BearerToken("tok".into()),
            Some("https://my-pandadoc.example.com/v1"),
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("https://my-pandadoc.example.com/v1"));
    }

    #[test]
    fn default_base_url_value() {
        assert_eq!(DEFAULT_BASE_URL, "https://api.pandadoc.com/public/v1");
    }

    #[test]
    fn auth_bearer_not_secretless() {
        let auth = PandaDocAuth::BearerToken(String::new());
        assert!(!auth.is_secretless());
    }

    #[test]
    fn auth_credential_is_secretless() {
        let auth = PandaDocAuth::CredentialId(CredentialId::new());
        assert!(auth.is_secretless());
    }

    #[test]
    fn client_new_trims_multiple_trailing_slashes() {
        let client = PandaDocClient::new(
            PandaDocAuth::BearerToken("tok".into()),
            Some("https://api.pandadoc.com/v1///"),
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("v1/"));
    }
}
