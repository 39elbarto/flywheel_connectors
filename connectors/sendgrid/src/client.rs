//! `SendGrid` API client.

use std::fmt;
use std::time::Duration;

use fcp_core::CredentialId;
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig};
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{SendGridError, SendGridResult},
    types::ApiErrorResponse,
};

/// Default `SendGrid` REST API base URL.
pub const DEFAULT_BASE_URL: &str = "https://api.sendgrid.com/v3";

/// Authentication mode for the `SendGrid` API.
#[derive(Clone)]
pub enum SendGridAuth {
    /// API key (passed as `Authorization: Bearer <api_key>`).
    ApiKey(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl SendGridAuth {
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::ApiKey(_) => "api_key:redacted".to_string(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for SendGridAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApiKey(_) => f.debug_tuple("ApiKey").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// `SendGrid` API client.
pub struct SendGridClient {
    client: Client,
    auth: SendGridAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl fmt::Debug for SendGridClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SendGridClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .field("retry_config", &self.retry_config)
            .finish_non_exhaustive()
    }
}

impl SendGridClient {
    /// Create a new `SendGrid` client.
    pub fn new(auth: SendGridAuth, base_url: Option<&str>) -> SendGridResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-sendgrid/0.1.0 (FCP connector)")
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

    /// Trigger graceful shutdown.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            SendGridAuth::ApiKey(key) => req.header("Authorization", format!("Bearer {key}")),
            SendGridAuth::CredentialId(id) => req.header("X-FCP-Credential-Id", id.to_string()),
        }
    }

    async fn handle_response(&self, resp: Response) -> SendGridResult<serde_json::Value> {
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
    ) -> SendGridResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let mut body = resp.text().await.unwrap_or_default();
        body.truncate(2048);

        // SendGrid returns {"errors": [{"message": "...", "field": "...", "help": "..."}]}
        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.errors)
            .and_then(|errs| {
                errs.into_iter()
                    .filter_map(|e| e.message)
                    .collect::<Vec<_>>()
                    .first()
                    .cloned()
            })
            .unwrap_or_else(|| {
                if body.is_empty() {
                    format!("HTTP {}", status.as_u16())
                } else {
                    body.clone()
                }
            });

        match status.as_u16() {
            401 => Err(SendGridError::Unauthorized),
            403 => Err(SendGridError::Forbidden),
            404 => Err(SendGridError::NotFound { resource: detail }),
            429 => Err(SendGridError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(SendGridError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    #[instrument(skip(self), fields(url))]
    async fn get(&self, path: &str) -> SendGridResult<serde_json::Value> {
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
    ) -> SendGridResult<serde_json::Value> {
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
    async fn delete(&self, path: &str) -> SendGridResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "DELETE request");
        let req = self
            .add_auth(self.client.delete(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- Mail --

    /// Send a transactional email.
    ///
    /// `SendGrid` returns 202 Accepted with an empty body on success.
    pub async fn send_mail(&self, body: &serde_json::Value) -> SendGridResult<serde_json::Value> {
        self.post("/mail/send", body).await
    }

    // -- Contacts --

    /// List all marketing contacts.
    pub async fn list_contacts(&self) -> SendGridResult<serde_json::Value> {
        self.get("/marketing/contacts").await
    }

    /// Search marketing contacts.
    pub async fn search_contacts(
        &self,
        body: &serde_json::Value,
    ) -> SendGridResult<serde_json::Value> {
        self.post("/marketing/contacts/search", body).await
    }

    /// Get a single contact by ID.
    pub async fn get_contact(&self, id: &str) -> SendGridResult<serde_json::Value> {
        self.get(&format!("/marketing/contacts/{id}")).await
    }

    // -- Lists --

    /// List all marketing lists.
    pub async fn list_lists(&self) -> SendGridResult<serde_json::Value> {
        self.get("/marketing/lists").await
    }

    /// Create a marketing list.
    pub async fn create_list(&self, body: &serde_json::Value) -> SendGridResult<serde_json::Value> {
        self.post("/marketing/lists", body).await
    }

    /// Delete a marketing list.
    pub async fn delete_list(&self, list_id: &str) -> SendGridResult<serde_json::Value> {
        self.delete(&format!("/marketing/lists/{list_id}")).await
    }

    // -- Templates --

    /// List dynamic email templates.
    pub async fn list_templates(&self) -> SendGridResult<serde_json::Value> {
        self.get("/templates?generations=dynamic").await
    }

    /// Get a single template by ID.
    pub async fn get_template(&self, template_id: &str) -> SendGridResult<serde_json::Value> {
        self.get(&format!("/templates/{template_id}")).await
    }

    // -- Stats --

    /// Get email delivery statistics.
    pub async fn get_stats(&self, query: &str) -> SendGridResult<serde_json::Value> {
        self.get(&format!("/stats?{query}")).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_key() {
        let auth = SendGridAuth::ApiKey("SG.secret-api-key-12345".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("SG.secret-api-key-12345"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let key = SendGridAuth::ApiKey("SG.key".into());
        assert!(!key.is_secretless());
        let cred = SendGridAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label() {
        let key = SendGridAuth::ApiKey("SG.key".into());
        assert_eq!(key.redacted_label(), "api_key:redacted");
    }

    #[test]
    fn auth_credential_label() {
        let cred = SendGridAuth::CredentialId(CredentialId::new());
        let label = cred.redacted_label();
        assert!(label.starts_with("credential_id:"));
    }

    #[test]
    fn client_new_default_url() {
        let client = SendGridClient::new(SendGridAuth::ApiKey("SG.key".into()), None).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn client_new_custom_url() {
        let client = SendGridClient::new(
            SendGridAuth::ApiKey("SG.key".into()),
            Some("https://test.example.com/v3/"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://test.example.com/v3");
    }

    #[test]
    fn client_debug_redacts() {
        let client = SendGridClient::new(SendGridAuth::ApiKey("SG.secret".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("SG.secret"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn auth_api_key_clone() {
        let auth = SendGridAuth::ApiKey("SG.key".into());
        let cloned = auth.clone();
        assert_eq!(cloned.redacted_label(), "api_key:redacted");
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn auth_credential_id_clone() {
        let auth = SendGridAuth::CredentialId(CredentialId::new());
        let cloned = auth.clone();
        assert!(cloned.is_secretless());
    }

    #[test]
    fn client_debug_contains_struct_name() {
        let client = SendGridClient::new(SendGridAuth::ApiKey("SG.key".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("SendGridClient"));
    }

    #[test]
    fn client_debug_contains_base_url() {
        let client = SendGridClient::new(
            SendGridAuth::ApiKey("SG.key".into()),
            Some("https://custom.sendgrid.com/v3"),
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("custom.sendgrid.com"));
    }

    #[test]
    fn auth_debug_contains_api_key_type() {
        let auth = SendGridAuth::ApiKey("SG.secret".into());
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("ApiKey"));
    }

    #[test]
    fn auth_debug_credential_id_contains_type() {
        let cred = SendGridAuth::CredentialId(CredentialId::new());
        let dbg = format!("{cred:?}");
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn default_base_url_starts_with_https() {
        assert!(DEFAULT_BASE_URL.starts_with("https://"));
    }

    #[test]
    fn default_base_url_is_sendgrid_v3() {
        assert_eq!(DEFAULT_BASE_URL, "https://api.sendgrid.com/v3");
    }

    #[test]
    fn client_strips_multiple_trailing_slashes() {
        let client = SendGridClient::new(
            SendGridAuth::ApiKey("SG.key".into()),
            Some("https://api.sendgrid.com/v3///"),
        )
        .unwrap();
        assert!(!client.base_url.ends_with('/'));
    }

    #[test]
    fn client_with_empty_custom_url() {
        let client = SendGridClient::new(SendGridAuth::ApiKey("SG.key".into()), Some("")).unwrap();
        assert!(client.base_url.is_empty());
    }

    #[test]
    fn auth_credential_debug_does_not_contain_redacted_tag() {
        let cred = SendGridAuth::CredentialId(CredentialId::new());
        let dbg = format!("{cred:?}");
        assert!(!dbg.contains("<redacted>"));
    }
}
