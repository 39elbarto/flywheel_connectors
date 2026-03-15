//! `Intercom` API client.

use std::fmt;
use std::time::Duration;

use fcp_core::CredentialId;
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig};
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{IntercomError, IntercomResult},
    types::ApiErrorResponse,
};

/// Default `Intercom` API base URL.
pub const DEFAULT_BASE_URL: &str = "https://api.intercom.io";

/// Authentication mode for the `Intercom` API.
#[derive(Clone)]
pub enum IntercomAuth {
    /// `OAuth2` Bearer token.
    BearerToken(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl IntercomAuth {
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

impl fmt::Debug for IntercomAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BearerToken(_) => f.debug_tuple("BearerToken").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// `Intercom` API client.
pub struct IntercomClient {
    client: Client,
    auth: IntercomAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl fmt::Debug for IntercomClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IntercomClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl IntercomClient {
    /// Create a new `Intercom` client.
    pub fn new(auth: IntercomAuth, base_url: Option<&str>) -> IntercomResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-intercom/0.1.0 (FCP connector)")
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
                max_retries: 3,
                ..HttpRetryConfig::default()
            },
        })
    }

    /// Trigger graceful shutdown of request contexts.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            IntercomAuth::BearerToken(token) => req.bearer_auth(token),
            IntercomAuth::CredentialId(id) => req.header("X-FCP-Credential-Id", id.to_string()),
        }
    }

    async fn handle_response(&self, resp: Response) -> IntercomResult<serde_json::Value> {
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
    ) -> IntercomResult<serde_json::Value> {
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
            401 => Err(IntercomError::Unauthorized),
            403 => Err(IntercomError::Forbidden),
            404 => Err(IntercomError::NotFound { resource: detail }),
            429 => Err(IntercomError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(IntercomError::Api {
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
    ) -> IntercomResult<serde_json::Value> {
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
    ) -> IntercomResult<serde_json::Value> {
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
    async fn delete(&self, path: &str) -> IntercomResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "DELETE request");
        let req = self
            .add_auth(self.client.delete(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- Contacts --

    /// List contacts.
    pub async fn list_contacts(
        &self,
        per_page: Option<i64>,
        starting_after: Option<&str>,
    ) -> IntercomResult<serde_json::Value> {
        let mut q = Vec::new();
        if let Some(p) = per_page {
            q.push(("per_page", p.to_string()));
        }
        if let Some(s) = starting_after {
            q.push(("starting_after", s.to_string()));
        }
        self.get("/contacts", if q.is_empty() { None } else { Some(&q) })
            .await
    }

    /// Create a contact.
    pub async fn create_contact(
        &self,
        body: &serde_json::Value,
    ) -> IntercomResult<serde_json::Value> {
        self.post("/contacts", body).await
    }

    /// Delete a contact.
    pub async fn delete_contact(&self, contact_id: &str) -> IntercomResult<serde_json::Value> {
        self.delete(&format!("/contacts/{contact_id}")).await
    }

    // -- Conversations --

    /// List conversations.
    pub async fn list_conversations(
        &self,
        per_page: Option<i64>,
        starting_after: Option<&str>,
    ) -> IntercomResult<serde_json::Value> {
        let mut q = Vec::new();
        if let Some(p) = per_page {
            q.push(("per_page", p.to_string()));
        }
        if let Some(s) = starting_after {
            q.push(("starting_after", s.to_string()));
        }
        self.get("/conversations", if q.is_empty() { None } else { Some(&q) })
            .await
    }

    /// Reply to a conversation.
    pub async fn reply_to_conversation(
        &self,
        conversation_id: &str,
        body: &serde_json::Value,
    ) -> IntercomResult<serde_json::Value> {
        self.post(&format!("/conversations/{conversation_id}/reply"), body)
            .await
    }

    // -- Tags --

    /// List all tags.
    pub async fn list_tags(&self) -> IntercomResult<serde_json::Value> {
        self.get("/tags", None).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_token() {
        let auth = IntercomAuth::BearerToken("secret-token".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("secret-token"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let token = IntercomAuth::BearerToken("tok".into());
        assert!(!token.is_secretless());
        let cred = IntercomAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label() {
        let token = IntercomAuth::BearerToken("tok".into());
        assert_eq!(token.redacted_label(), "bearer_token:redacted");
    }

    #[test]
    fn auth_redacted_label_credential_id() {
        let cred = IntercomAuth::CredentialId(CredentialId::new());
        let label = cred.redacted_label();
        assert!(label.starts_with("credential_id:"));
        assert!(!label.contains("redacted"));
    }

    #[test]
    fn auth_debug_credential_id_shows_id() {
        let id = CredentialId::new();
        let auth = IntercomAuth::CredentialId(id);
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("CredentialId"));
        assert!(dbg.contains(&id.to_string()));
    }

    #[test]
    fn auth_debug_bearer_does_not_leak() {
        let auth = IntercomAuth::BearerToken("super-secret-token-12345".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("super-secret-token-12345"));
        assert!(dbg.contains("BearerToken"));
        assert!(dbg.contains("<redacted>"));
    }

    #[test]
    fn auth_clone() {
        let auth = IntercomAuth::BearerToken("tok".into());
        let cloned = auth.clone();
        assert_eq!(auth.redacted_label(), "bearer_token:redacted");
        assert!(!cloned.is_secretless());
    }

    #[test]
    fn client_new_default_url() {
        let client = IntercomClient::new(IntercomAuth::BearerToken("tok".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains(DEFAULT_BASE_URL));
    }

    #[test]
    fn client_new_custom_url() {
        let client = IntercomClient::new(
            IntercomAuth::BearerToken("tok".into()),
            Some("https://custom.example.com"),
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("https://custom.example.com"));
    }

    #[test]
    fn client_new_trims_trailing_slash() {
        let client = IntercomClient::new(
            IntercomAuth::BearerToken("tok".into()),
            Some("https://example.com/"),
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("https://example.com"));
        assert!(!dbg.contains("https://example.com/\""));
    }

    #[test]
    fn client_new_trims_multiple_trailing_slashes() {
        let client = IntercomClient::new(
            IntercomAuth::BearerToken("tok".into()),
            Some("https://example.com///"),
        )
        .unwrap();
        let dbg = format!("{client:?}");
        // trim_end_matches removes all trailing slashes
        assert!(!dbg.contains("///"));
    }

    #[test]
    fn client_debug_shows_struct() {
        let client = IntercomClient::new(IntercomAuth::BearerToken("tok".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("IntercomClient"));
        assert!(dbg.contains("auth"));
        assert!(dbg.contains("base_url"));
    }

    #[test]
    fn client_debug_redacts_auth() {
        let client =
            IntercomClient::new(IntercomAuth::BearerToken("my-secret".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("my-secret"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn default_base_url_value() {
        assert_eq!(DEFAULT_BASE_URL, "https://api.intercom.io");
    }

    #[test]
    fn client_with_credential_id_auth() {
        let client =
            IntercomClient::new(IntercomAuth::CredentialId(CredentialId::new()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("CredentialId"));
    }

    // ── Additional client coverage tests ──────────────────────────

    #[test]
    fn auth_clone_credential() {
        let cred = IntercomAuth::CredentialId(CredentialId::new());
        let cloned = cred.clone();
        assert!(cred.is_secretless());
        assert!(cloned.is_secretless());
    }

    #[test]
    fn auth_redacted_label_does_not_contain_token() {
        let auth = IntercomAuth::BearerToken("my-secret-token-xyz".into());
        let label = auth.redacted_label();
        assert!(!label.contains("my-secret-token-xyz"));
        assert!(label.contains("redacted"));
    }

    #[test]
    fn client_new_empty_string_url() {
        let client =
            IntercomClient::new(IntercomAuth::BearerToken("tok".into()), Some("")).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("IntercomClient"));
    }
}
