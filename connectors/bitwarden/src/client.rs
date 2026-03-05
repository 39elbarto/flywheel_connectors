//! `Bitwarden` API client.

use std::fmt;
use std::time::Duration;

use fcp_core::CredentialId;
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{BitwardenError, BitwardenResult},
    types::ApiErrorResponse,
};

/// Default `Bitwarden` API base URL.
pub const DEFAULT_BASE_URL: &str = "https://api.bitwarden.com";

/// Authentication mode for the `Bitwarden` API.
#[derive(Clone)]
pub enum BitwardenAuth {
    /// Bearer token (from client credentials).
    BearerToken(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl BitwardenAuth {
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

impl fmt::Debug for BitwardenAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BearerToken(_) => f.debug_tuple("BearerToken").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// `Bitwarden` API client.
pub struct BitwardenClient {
    client: Client,
    auth: BitwardenAuth,
    base_url: String,
}

impl fmt::Debug for BitwardenClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BitwardenClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl BitwardenClient {
    /// Create a new `Bitwarden` client.
    pub fn new(auth: BitwardenAuth, base_url: Option<&str>) -> BitwardenResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-bitwarden/0.1.0 (FCP connector)")
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
            BitwardenAuth::BearerToken(token) => req.bearer_auth(token),
            BitwardenAuth::CredentialId(id) => req.header("X-FCP-Credential-Id", id.to_string()),
        }
    }

    async fn handle_response(&self, resp: Response) -> BitwardenResult<serde_json::Value> {
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
    ) -> BitwardenResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = resp.text().await.unwrap_or_default();
        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| {
                e.message
                    .or(e.error_description)
                    .or(e.error)
            })
            .unwrap_or_else(|| body.clone());

        match status.as_u16() {
            401 => Err(BitwardenError::Unauthorized),
            403 => Err(BitwardenError::Forbidden),
            404 => Err(BitwardenError::NotFound { resource: detail }),
            429 => Err(BitwardenError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(BitwardenError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    #[instrument(skip(self), fields(url))]
    async fn get(&self, path: &str) -> BitwardenResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "GET request");
        let req = self
            .add_auth(self.client.get(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn post(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> BitwardenResult<serde_json::Value> {
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
    async fn delete(&self, path: &str) -> BitwardenResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "DELETE request");
        let req = self
            .add_auth(self.client.delete(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- Collections --

    /// List all collections.
    pub async fn list_collections(&self) -> BitwardenResult<serde_json::Value> {
        self.get("/collections").await
    }

    // -- Items --

    /// List vault items with optional filters.
    pub async fn list_items(
        &self,
        collection_id: Option<&str>,
        folder_id: Option<&str>,
    ) -> BitwardenResult<serde_json::Value> {
        let qs = build_query(&[
            collection_id.map(|c| ("collectionId", c.to_string())),
            folder_id.map(|f| ("folderId", f.to_string())),
        ]);
        self.get(&format!("/list/object/items{qs}")).await
    }

    /// Get a single vault item by ID.
    pub async fn get_item(&self, item_id: &str) -> BitwardenResult<serde_json::Value> {
        self.get(&format!("/object/item/{item_id}")).await
    }

    /// Create a new vault item.
    pub async fn create_item(
        &self,
        body: &serde_json::Value,
    ) -> BitwardenResult<serde_json::Value> {
        self.post("/object/item", body).await
    }

    /// Delete a vault item.
    pub async fn delete_item(&self, item_id: &str) -> BitwardenResult<serde_json::Value> {
        self.delete(&format!("/object/item/{item_id}")).await
    }
}

fn build_query(params: &[Option<(&str, String)>]) -> String {
    let mut qs = String::new();
    let mut sep = '?';
    for param in params.iter().flatten() {
        qs.push(sep);
        qs.push_str(param.0);
        qs.push('=');
        qs.push_str(&param.1);
        sep = '&';
    }
    qs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_token() {
        let auth = BitwardenAuth::BearerToken("secret-token".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("secret-token"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let token = BitwardenAuth::BearerToken("tok".into());
        assert!(!token.is_secretless());
        let cred = BitwardenAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label() {
        let token = BitwardenAuth::BearerToken("tok".into());
        assert_eq!(token.redacted_label(), "bearer_token:redacted");
    }

    #[test]
    fn auth_redacted_label_credential() {
        let cred = BitwardenAuth::CredentialId(CredentialId::new());
        let label = cred.redacted_label();
        assert!(label.starts_with("credential_id:"));
    }

    #[test]
    fn build_query_empty() {
        assert_eq!(build_query(&[None, None]), "");
    }

    #[test]
    fn build_query_one() {
        assert_eq!(
            build_query(&[Some(("collectionId", "c1".into()))]),
            "?collectionId=c1"
        );
    }

    #[test]
    fn build_query_two() {
        assert_eq!(
            build_query(&[
                Some(("collectionId", "c1".into())),
                Some(("folderId", "f1".into()))
            ]),
            "?collectionId=c1&folderId=f1"
        );
    }

    #[test]
    fn build_query_first_none() {
        assert_eq!(
            build_query(&[None, Some(("folderId", "f1".into()))]),
            "?folderId=f1"
        );
    }

    #[test]
    fn default_base_url_value() {
        assert_eq!(DEFAULT_BASE_URL, "https://api.bitwarden.com");
    }

    #[test]
    fn client_new_default_url() {
        let client =
            BitwardenClient::new(BitwardenAuth::BearerToken("tok".into()), None).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn client_new_custom_url() {
        let client = BitwardenClient::new(
            BitwardenAuth::BearerToken("tok".into()),
            Some("https://bitwarden.example.com/"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://bitwarden.example.com");
    }

    #[test]
    fn client_debug_format() {
        let client =
            BitwardenClient::new(BitwardenAuth::BearerToken("secret".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("secret"));
        assert!(dbg.contains("redacted"));
        assert!(dbg.contains("BitwardenClient"));
    }
}
