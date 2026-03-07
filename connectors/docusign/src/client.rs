//! `DocuSign` API client.

use std::fmt;
use std::time::Duration;

use fcp_core::CredentialId;
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{DocuSignError, DocuSignResult},
    types::ApiErrorResponse,
};

/// Default `DocuSign` API base URL (demo environment).
pub const DEFAULT_BASE_URL: &str = "https://demo.docusign.net/restapi/v2.1/accounts";

/// Parameters for listing envelopes.
#[derive(Debug, Default)]
pub struct ListEnvelopesParams<'a> {
    pub account_id: &'a str,
    pub from_date: Option<&'a str>,
    pub to_date: Option<&'a str>,
    pub status: Option<&'a str>,
    pub search_text: Option<&'a str>,
    pub count: Option<i64>,
    pub start_position: Option<&'a str>,
}

/// Authentication mode for the `DocuSign` API.
#[derive(Clone)]
pub enum DocuSignAuth {
    /// `OAuth2` Bearer token.
    BearerToken(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl DocuSignAuth {
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

impl fmt::Debug for DocuSignAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BearerToken(_) => f.debug_tuple("BearerToken").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// `DocuSign` API client.
pub struct DocuSignClient {
    client: Client,
    auth: DocuSignAuth,
    base_url: String,
}

impl fmt::Debug for DocuSignClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DocuSignClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl DocuSignClient {
    /// Create a new `DocuSign` client.
    pub fn new(auth: DocuSignAuth, base_url: Option<&str>) -> DocuSignResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-docusign/0.1.0 (FCP connector)")
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
            DocuSignAuth::BearerToken(token) => req.bearer_auth(token),
            DocuSignAuth::CredentialId(id) => req.header("X-FCP-Credential-Id", id.to_string()),
        }
    }

    async fn handle_response(&self, resp: Response) -> DocuSignResult<serde_json::Value> {
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

    async fn handle_response_raw(&self, resp: Response) -> DocuSignResult<Vec<u8>> {
        let status = resp.status();
        if status.is_success() {
            let bytes = resp.bytes().await?;
            Ok(bytes.to_vec())
        } else {
            self.handle_error(status, resp).await.map(|_| vec![])
        }
    }

    async fn handle_error(
        &self,
        status: StatusCode,
        resp: Response,
    ) -> DocuSignResult<serde_json::Value> {
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
            401 => Err(DocuSignError::Unauthorized),
            403 => Err(DocuSignError::Forbidden),
            404 => Err(DocuSignError::NotFound { resource: detail }),
            429 => Err(DocuSignError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(DocuSignError::Api {
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
    ) -> DocuSignResult<serde_json::Value> {
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

    #[instrument(skip(self), fields(url))]
    async fn get_raw(
        &self,
        path: &str,
        query: Option<&[(&str, String)]>,
    ) -> DocuSignResult<Vec<u8>> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "GET raw request");
        let mut req = self.add_auth(self.client.get(&url));
        if let Some(q) = query {
            req = req.query(q);
        }
        let resp = req.send().await?;
        self.handle_response_raw(resp).await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn post(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> DocuSignResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "POST request");
        let req = self
            .add_auth(self.client.post(&url))
            .header("Accept", "application/json")
            .json(body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn put(&self, path: &str, body: &serde_json::Value) -> DocuSignResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "PUT request");
        let req = self
            .add_auth(self.client.put(&url))
            .header("Accept", "application/json")
            .json(body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- Envelopes --

    /// List envelopes with optional filters.
    pub async fn list_envelopes(
        &self,
        params: &ListEnvelopesParams<'_>,
    ) -> DocuSignResult<serde_json::Value> {
        let mut q = Vec::new();
        if let Some(v) = params.from_date {
            q.push(("from_date", v.to_string()));
        }
        if let Some(v) = params.to_date {
            q.push(("to_date", v.to_string()));
        }
        if let Some(v) = params.status {
            q.push(("status", v.to_string()));
        }
        if let Some(v) = params.search_text {
            q.push(("search_text", v.to_string()));
        }
        if let Some(v) = params.count {
            q.push(("count", v.to_string()));
        }
        if let Some(v) = params.start_position {
            q.push(("start_position", v.to_string()));
        }
        self.get(
            &format!("/{}/envelopes", params.account_id),
            if q.is_empty() { None } else { Some(&q) },
        )
        .await
    }

    /// Get envelope details.
    pub async fn get_envelope(
        &self,
        account_id: &str,
        envelope_id: &str,
        include: Option<&str>,
    ) -> DocuSignResult<serde_json::Value> {
        let q = include.map(|v| vec![("include", v.to_string())]);
        self.get(
            &format!("/{account_id}/envelopes/{envelope_id}"),
            q.as_deref(),
        )
        .await
    }

    /// Create envelope.
    pub async fn create_envelope(
        &self,
        account_id: &str,
        body: &serde_json::Value,
    ) -> DocuSignResult<serde_json::Value> {
        self.post(&format!("/{account_id}/envelopes"), body).await
    }

    /// Send a draft envelope (update status to sent).
    pub async fn send_envelope(
        &self,
        account_id: &str,
        envelope_id: &str,
    ) -> DocuSignResult<serde_json::Value> {
        let body = serde_json::json!({"status": "sent"});
        self.put(&format!("/{account_id}/envelopes/{envelope_id}"), &body)
            .await
    }

    /// Void an envelope.
    pub async fn void_envelope(
        &self,
        account_id: &str,
        envelope_id: &str,
        voided_reason: &str,
    ) -> DocuSignResult<serde_json::Value> {
        let body = serde_json::json!({
            "status": "voided",
            "voidedReason": voided_reason,
        });
        self.put(&format!("/{account_id}/envelopes/{envelope_id}"), &body)
            .await
    }

    /// Add recipients to an envelope.
    pub async fn add_recipients(
        &self,
        account_id: &str,
        envelope_id: &str,
        recipients: &serde_json::Value,
    ) -> DocuSignResult<serde_json::Value> {
        self.post(
            &format!("/{account_id}/envelopes/{envelope_id}/recipients"),
            recipients,
        )
        .await
    }

    // -- Templates --

    /// List templates.
    pub async fn list_templates(
        &self,
        account_id: &str,
        search_text: Option<&str>,
    ) -> DocuSignResult<serde_json::Value> {
        let q = search_text.map(|v| vec![("search_text", v.to_string())]);
        self.get(&format!("/{account_id}/templates"), q.as_deref())
            .await
    }

    /// Get template details.
    pub async fn get_template(
        &self,
        account_id: &str,
        template_id: &str,
    ) -> DocuSignResult<serde_json::Value> {
        self.get(&format!("/{account_id}/templates/{template_id}"), None)
            .await
    }

    // -- Documents --

    /// Download documents (combined PDF by default).
    pub async fn download_documents(
        &self,
        account_id: &str,
        envelope_id: &str,
        document_id: Option<&str>,
    ) -> DocuSignResult<Vec<u8>> {
        let doc_path = document_id.unwrap_or("combined");
        self.get_raw(
            &format!("/{account_id}/envelopes/{envelope_id}/documents/{doc_path}"),
            None,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_token() {
        let auth = DocuSignAuth::BearerToken("secret-token".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("secret-token"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let token = DocuSignAuth::BearerToken("tok".into());
        assert!(!token.is_secretless());
        let cred = DocuSignAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label() {
        let token = DocuSignAuth::BearerToken("tok".into());
        assert_eq!(token.redacted_label(), "bearer_token:redacted");
    }

    #[test]
    fn auth_redacted_label_credential_id() {
        let cred = DocuSignAuth::CredentialId(CredentialId::new());
        let label = cred.redacted_label();
        assert!(label.starts_with("credential_id:"));
    }

    #[test]
    fn client_default_base_url() {
        let c = DocuSignClient::new(DocuSignAuth::BearerToken("tok".into()), None).unwrap();
        assert_eq!(c.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn client_custom_base_url() {
        let c = DocuSignClient::new(
            DocuSignAuth::BearerToken("tok".into()),
            Some("https://custom.docusign.net/restapi/v2.1/accounts"),
        )
        .unwrap();
        assert_eq!(
            c.base_url,
            "https://custom.docusign.net/restapi/v2.1/accounts"
        );
    }

    #[test]
    fn client_trims_trailing_slash() {
        let c = DocuSignClient::new(
            DocuSignAuth::BearerToken("tok".into()),
            Some("https://example.com/api/"),
        )
        .unwrap();
        assert_eq!(c.base_url, "https://example.com/api");
    }

    #[test]
    fn client_debug_format() {
        let c = DocuSignClient::new(DocuSignAuth::BearerToken("secret".into()), None).unwrap();
        let dbg = format!("{c:?}");
        assert!(!dbg.contains("secret"));
        assert!(dbg.contains("DocuSignClient"));
    }

    #[test]
    fn auth_clone_bearer() {
        let auth = DocuSignAuth::BearerToken("tok123".into());
        let cloned = auth.clone();
        drop(auth);
        assert_eq!(cloned.redacted_label(), "bearer_token:redacted");
    }

    #[test]
    fn auth_clone_credential() {
        let auth = DocuSignAuth::CredentialId(CredentialId::new());
        let cloned = auth.clone();
        drop(auth);
        assert!(cloned.is_secretless());
    }

    #[test]
    fn client_debug_contains_base_url() {
        let c = DocuSignClient::new(DocuSignAuth::BearerToken("tok".into()), None).unwrap();
        let dbg = format!("{c:?}");
        assert!(dbg.contains("base_url"));
    }

    #[test]
    fn client_new_with_credential_id() {
        let cred = CredentialId::new();
        let c = DocuSignClient::new(DocuSignAuth::CredentialId(cred), None).unwrap();
        assert_eq!(c.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn default_base_url_contains_docusign() {
        assert!(DEFAULT_BASE_URL.contains("docusign"));
    }

    #[test]
    fn default_base_url_is_https() {
        assert!(DEFAULT_BASE_URL.starts_with("https://"));
    }

    #[test]
    fn default_base_url_contains_restapi() {
        assert!(DEFAULT_BASE_URL.contains("restapi"));
    }

    #[test]
    fn auth_bearer_is_not_secretless() {
        let auth = DocuSignAuth::BearerToken("any".into());
        assert!(!auth.is_secretless());
    }

    #[test]
    fn auth_credential_is_secretless() {
        let auth = DocuSignAuth::CredentialId(CredentialId::new());
        assert!(auth.is_secretless());
    }

    #[test]
    fn auth_debug_bearer_shows_tuple_name() {
        let auth = DocuSignAuth::BearerToken("secret".into());
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("BearerToken"));
    }

    #[test]
    fn auth_debug_credential_shows_id() {
        let cred = DocuSignAuth::CredentialId(CredentialId::new());
        let dbg = format!("{cred:?}");
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn client_strips_multiple_trailing_slashes() {
        let c = DocuSignClient::new(
            DocuSignAuth::BearerToken("k".into()),
            Some("https://example.com/api////"),
        )
        .unwrap();
        assert!(!c.base_url.ends_with('/'));
    }

    #[test]
    fn list_envelopes_params_default() {
        let p = ListEnvelopesParams::default();
        assert_eq!(p.account_id, "");
        assert!(p.from_date.is_none());
        assert!(p.to_date.is_none());
        assert!(p.status.is_none());
        assert!(p.search_text.is_none());
        assert!(p.count.is_none());
        assert!(p.start_position.is_none());
    }

    #[test]
    fn list_envelopes_params_debug() {
        let p = ListEnvelopesParams {
            account_id: "acc-123",
            from_date: Some("2026-01-01"),
            ..Default::default()
        };
        let dbg = format!("{p:?}");
        assert!(dbg.contains("ListEnvelopesParams"));
        assert!(dbg.contains("acc-123"));
    }
}
