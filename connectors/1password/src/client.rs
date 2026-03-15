//! `1Password` Connect Server API client.

use std::fmt;
use std::time::Duration;

use fcp_core::CredentialId;
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig};
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{OnePasswordError, OnePasswordResult},
    types::ApiErrorResponse,
};

/// Default `1Password` Connect Server base URL.
pub const DEFAULT_BASE_URL: &str = "https://localhost:8080";

/// Authentication mode for the `1Password` API.
#[derive(Clone)]
pub enum OnePasswordAuth {
    /// Service account Bearer token.
    BearerToken(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl OnePasswordAuth {
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

impl fmt::Debug for OnePasswordAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BearerToken(_) => f.debug_tuple("BearerToken").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// `1Password` Connect Server API client.
pub struct OnePasswordClient {
    client: Client,
    auth: OnePasswordAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl fmt::Debug for OnePasswordClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OnePasswordClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl OnePasswordClient {
    /// Create a new `1Password` Connect client.
    pub fn new(auth: OnePasswordAuth, base_url: Option<&str>) -> OnePasswordResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-onepassword/0.1.0 (FCP connector)")
            .build()?;

        Ok(Self {
            client,
            auth,
            base_url: base_url
                .unwrap_or(DEFAULT_BASE_URL)
                .trim_end_matches('/')
                .to_string(),
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default()
                    .with_request_timeout(Duration::from_secs(30)),
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
            OnePasswordAuth::BearerToken(token) => req.bearer_auth(token),
            OnePasswordAuth::CredentialId(id) => req.header("X-FCP-Credential-Id", id.to_string()),
        }
    }

    async fn handle_response(&self, resp: Response) -> OnePasswordResult<serde_json::Value> {
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
    ) -> OnePasswordResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = resp.text().await.unwrap_or_default();
        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.message)
            .unwrap_or_else(|| body.clone());

        match status.as_u16() {
            401 => Err(OnePasswordError::Unauthorized),
            403 => Err(OnePasswordError::Forbidden),
            404 => Err(OnePasswordError::NotFound { resource: detail }),
            429 => Err(OnePasswordError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(OnePasswordError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    #[instrument(skip(self), fields(url))]
    async fn get(&self, path: &str) -> OnePasswordResult<serde_json::Value> {
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
    ) -> OnePasswordResult<serde_json::Value> {
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
    async fn delete(&self, path: &str) -> OnePasswordResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "DELETE request");
        let req = self
            .add_auth(self.client.delete(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- Vaults --

    /// List all vaults accessible to the service account.
    pub async fn list_vaults(&self) -> OnePasswordResult<serde_json::Value> {
        self.get("/v1/vaults").await
    }

    // -- Items --

    /// List items in a vault.
    pub async fn list_items(&self, vault_id: &str) -> OnePasswordResult<serde_json::Value> {
        self.get(&format!("/v1/vaults/{vault_id}/items")).await
    }

    /// Get a single item with full field values.
    pub async fn get_item(
        &self,
        vault_id: &str,
        item_id: &str,
    ) -> OnePasswordResult<serde_json::Value> {
        self.get(&format!("/v1/vaults/{vault_id}/items/{item_id}"))
            .await
    }

    /// Create a new item in a vault.
    pub async fn create_item(
        &self,
        vault_id: &str,
        body: &serde_json::Value,
    ) -> OnePasswordResult<serde_json::Value> {
        self.post(&format!("/v1/vaults/{vault_id}/items"), body)
            .await
    }

    /// Delete an item from a vault.
    pub async fn delete_item(
        &self,
        vault_id: &str,
        item_id: &str,
    ) -> OnePasswordResult<serde_json::Value> {
        self.delete(&format!("/v1/vaults/{vault_id}/items/{item_id}"))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_token() {
        let auth = OnePasswordAuth::BearerToken("secret-token".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("secret-token"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let token = OnePasswordAuth::BearerToken("tok".into());
        assert!(!token.is_secretless());
        let cred = OnePasswordAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label() {
        let token = OnePasswordAuth::BearerToken("tok".into());
        assert_eq!(token.redacted_label(), "bearer_token:redacted");
    }

    #[test]
    fn auth_credential_id_label() {
        let cred = OnePasswordAuth::CredentialId(CredentialId::new());
        let label = cred.redacted_label();
        assert!(label.starts_with("credential_id:"));
    }

    #[test]
    fn client_new_default_base_url() {
        let client =
            OnePasswordClient::new(OnePasswordAuth::BearerToken("tok".into()), None).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn client_new_custom_base_url() {
        let client = OnePasswordClient::new(
            OnePasswordAuth::BearerToken("tok".into()),
            Some("https://connect.example.com/"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://connect.example.com");
    }

    #[test]
    fn client_new_strips_trailing_slash() {
        let client = OnePasswordClient::new(
            OnePasswordAuth::BearerToken("tok".into()),
            Some("https://connect.example.com///"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://connect.example.com");
    }

    #[test]
    fn client_debug_does_not_leak_token() {
        let client =
            OnePasswordClient::new(OnePasswordAuth::BearerToken("my-secret".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("my-secret"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_bearer_clone() {
        let auth = OnePasswordAuth::BearerToken("tok".into());
        let cloned = auth.clone();
        assert_eq!(auth.redacted_label(), cloned.redacted_label());
    }

    #[test]
    fn auth_credential_clone() {
        let auth = OnePasswordAuth::CredentialId(CredentialId::new());
        let cloned = auth.clone();
        assert!(auth.is_secretless());
        assert!(cloned.is_secretless());
    }

    #[test]
    fn auth_debug_bearer_shows_tuple_name() {
        let auth = OnePasswordAuth::BearerToken("x".into());
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("BearerToken"));
    }

    #[test]
    fn auth_debug_credential_shows_id() {
        let cred = OnePasswordAuth::CredentialId(CredentialId::new());
        let dbg = format!("{cred:?}");
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn default_base_url_value() {
        assert_eq!(DEFAULT_BASE_URL, "https://localhost:8080");
    }

    #[test]
    fn default_base_url_is_https() {
        assert!(DEFAULT_BASE_URL.starts_with("https://"));
    }

    #[test]
    fn auth_redacted_label_never_contains_token() {
        let auth = OnePasswordAuth::BearerToken("my-super-secret-1password-token".into());
        let label = auth.redacted_label();
        assert!(!label.contains("my-super-secret-1password-token"));
    }

    #[test]
    fn auth_is_secretless_false_for_bearer() {
        assert!(!OnePasswordAuth::BearerToken("tok".into()).is_secretless());
    }

    #[test]
    fn auth_is_secretless_true_for_credential() {
        assert!(OnePasswordAuth::CredentialId(CredentialId::new()).is_secretless());
    }

    #[test]
    fn client_new_with_empty_url() {
        let client =
            OnePasswordClient::new(OnePasswordAuth::BearerToken("tok".into()), Some("")).unwrap();
        assert_eq!(client.base_url, "");
    }

    #[test]
    fn client_new_preserves_path_in_base_url() {
        let client = OnePasswordClient::new(
            OnePasswordAuth::BearerToken("tok".into()),
            Some("https://proxy.example.com/1password"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://proxy.example.com/1password");
    }

    #[test]
    fn client_debug_shows_base_url() {
        let client = OnePasswordClient::new(
            OnePasswordAuth::BearerToken("tok".into()),
            Some("https://connect.mysite.com"),
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("connect.mysite.com"));
    }

    #[test]
    fn client_debug_contains_struct_name() {
        let client =
            OnePasswordClient::new(OnePasswordAuth::BearerToken("tok".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("OnePasswordClient"));
    }
}
