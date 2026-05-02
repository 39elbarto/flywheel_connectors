//! `Bitwarden` API client.

use fcp_prelude::log_redaction::redact_url;
use std::fmt;
use std::time::Duration;

use fcp_prelude::CredentialId;
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig};
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
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
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
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(30)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 2,
                ..HttpRetryConfig::default()
            },
        })
    }

    /// Shut down the connector runtime.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
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
            .and_then(|e| e.message.or(e.error_description).or(e.error))
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
    async fn get(
        &self,
        path: &str,
        query: Option<&[(&str, String)]>,
    ) -> BitwardenResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "GET request");
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
    ) -> BitwardenResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "POST request");
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
        debug!(url = %redact_url(&url), "DELETE request");
        let req = self
            .add_auth(self.client.delete(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- Collections --

    /// List all collections.
    pub async fn list_collections(&self) -> BitwardenResult<serde_json::Value> {
        self.get("/collections", None).await
    }

    // -- Items --

    /// List vault items with optional filters.
    pub async fn list_items(
        &self,
        collection_id: Option<&str>,
        folder_id: Option<&str>,
    ) -> BitwardenResult<serde_json::Value> {
        let mut q = Vec::new();
        if let Some(c) = collection_id {
            q.push(("collectionId", c.to_string()));
        }
        if let Some(f) = folder_id {
            q.push(("folderId", f.to_string()));
        }
        self.get(
            "/list/object/items",
            if q.is_empty() { None } else { Some(&q) },
        )
        .await
    }

    /// Get a single vault item by ID.
    pub async fn get_item(&self, item_id: &str) -> BitwardenResult<serde_json::Value> {
        self.get(&format!("/object/item/{item_id}"), None).await
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
    fn default_base_url_value() {
        assert_eq!(DEFAULT_BASE_URL, "https://api.bitwarden.com");
    }

    #[test]
    fn client_new_default_url() {
        let client = BitwardenClient::new(BitwardenAuth::BearerToken("tok".into()), None).unwrap();
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

    #[test]
    fn auth_bearer_clone() {
        let auth = BitwardenAuth::BearerToken("tok".into());
        let cloned = auth.clone();
        assert_eq!(auth.redacted_label(), cloned.redacted_label());
    }

    #[test]
    fn auth_credential_clone() {
        let auth = BitwardenAuth::CredentialId(CredentialId::new());
        let cloned = auth.clone();
        assert!(auth.is_secretless());
        assert!(cloned.is_secretless());
    }

    #[test]
    fn client_strips_multiple_trailing_slashes() {
        let client = BitwardenClient::new(
            BitwardenAuth::BearerToken("tok".into()),
            Some("https://bitwarden.example.com///"),
        )
        .unwrap();
        assert!(!client.base_url.ends_with('/'));
    }

    #[test]
    fn client_debug_shows_base_url() {
        let client = BitwardenClient::new(
            BitwardenAuth::BearerToken("tok".into()),
            Some("https://my-vault.example.com"),
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("my-vault.example.com"));
    }

    #[test]
    fn auth_debug_credential_shows_id() {
        let cred = BitwardenAuth::CredentialId(CredentialId::new());
        let dbg = format!("{cred:?}");
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn auth_debug_bearer_shows_tuple_name() {
        let auth = BitwardenAuth::BearerToken("x".into());
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("BearerToken"));
    }

    #[test]
    fn default_base_url_is_https() {
        assert!(DEFAULT_BASE_URL.starts_with("https://"));
    }

    #[test]
    fn client_new_with_empty_url_fallback() {
        // empty string should be kept as-is (not fallback)
        let client =
            BitwardenClient::new(BitwardenAuth::BearerToken("tok".into()), Some("")).unwrap();
        assert_eq!(client.base_url, "");
    }

    #[test]
    fn auth_redacted_label_never_contains_token() {
        let auth = BitwardenAuth::BearerToken("super-secret-password-12345".into());
        let label = auth.redacted_label();
        assert!(!label.contains("super-secret-password-12345"));
    }

    #[test]
    fn auth_is_secretless_false_for_bearer() {
        assert!(!BitwardenAuth::BearerToken("tok".into()).is_secretless());
    }

    #[test]
    fn auth_is_secretless_true_for_credential() {
        assert!(BitwardenAuth::CredentialId(CredentialId::new()).is_secretless());
    }

    #[test]
    fn client_new_preserves_path_in_base_url() {
        let client = BitwardenClient::new(
            BitwardenAuth::BearerToken("tok".into()),
            Some("https://proxy.example.com/bitwarden"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://proxy.example.com/bitwarden");
    }
}
