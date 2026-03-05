//! `Intercom` API client.

use std::fmt;
use std::time::Duration;

use fcp_core::CredentialId;
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
        })
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

    async fn handle_error(&self, status: StatusCode, resp: Response) -> IntercomResult<serde_json::Value> {
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
            code => Err(IntercomError::Api { status_code: code, message: detail }),
        }
    }

    #[instrument(skip(self), fields(url))]
    async fn get(&self, path: &str) -> IntercomResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "GET request");
        let req = self.add_auth(self.client.get(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn post(&self, path: &str, body: &serde_json::Value) -> IntercomResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "POST request");
        let req = self.add_auth(self.client.post(&url))
            .header("Accept", "application/json")
            .json(body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self), fields(url))]
    async fn delete(&self, path: &str) -> IntercomResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "DELETE request");
        let req = self.add_auth(self.client.delete(&url))
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
        let qs = build_query(&[
            per_page.map(|p| ("per_page", p.to_string())),
            starting_after.map(|s| ("starting_after", s.to_string())),
        ]);
        self.get(&format!("/contacts{qs}")).await
    }

    /// Create a contact.
    pub async fn create_contact(
        &self,
        body: &serde_json::Value,
    ) -> IntercomResult<serde_json::Value> {
        self.post("/contacts", body).await
    }

    /// Delete a contact.
    pub async fn delete_contact(
        &self,
        contact_id: &str,
    ) -> IntercomResult<serde_json::Value> {
        self.delete(&format!("/contacts/{contact_id}")).await
    }

    // -- Conversations --

    /// List conversations.
    pub async fn list_conversations(
        &self,
        per_page: Option<i64>,
        starting_after: Option<&str>,
    ) -> IntercomResult<serde_json::Value> {
        let qs = build_query(&[
            per_page.map(|p| ("per_page", p.to_string())),
            starting_after.map(|s| ("starting_after", s.to_string())),
        ]);
        self.get(&format!("/conversations{qs}")).await
    }

    /// Reply to a conversation.
    pub async fn reply_to_conversation(
        &self,
        conversation_id: &str,
        body: &serde_json::Value,
    ) -> IntercomResult<serde_json::Value> {
        self.post(&format!("/conversations/{conversation_id}/reply"), body).await
    }

    // -- Tags --

    /// List all tags.
    pub async fn list_tags(&self) -> IntercomResult<serde_json::Value> {
        self.get("/tags").await
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
    fn build_query_empty() {
        assert_eq!(build_query(&[None, None]), "");
    }

    #[test]
    fn build_query_one() {
        assert_eq!(build_query(&[Some(("per_page", "50".into()))]), "?per_page=50");
    }

    #[test]
    fn build_query_two() {
        assert_eq!(
            build_query(&[Some(("per_page", "50".into())), Some(("starting_after", "abc".into()))]),
            "?per_page=50&starting_after=abc"
        );
    }
}
