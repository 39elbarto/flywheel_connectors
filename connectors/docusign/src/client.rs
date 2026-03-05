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
    async fn get(&self, path: &str) -> DocuSignResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "GET request");
        let req = self
            .add_auth(self.client.get(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self), fields(url))]
    async fn get_raw(&self, path: &str) -> DocuSignResult<Vec<u8>> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "GET raw request");
        let req = self.add_auth(self.client.get(&url));
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
    async fn put(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> DocuSignResult<serde_json::Value> {
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
        let qs = build_query(&[
            params.from_date.map(|v| ("from_date", v.to_string())),
            params.to_date.map(|v| ("to_date", v.to_string())),
            params.status.map(|v| ("status", v.to_string())),
            params.search_text.map(|v| ("search_text", v.to_string())),
            params.count.map(|v| ("count", v.to_string())),
            params.start_position.map(|v| ("start_position", v.to_string())),
        ]);
        self.get(&format!("/{}/envelopes{qs}", params.account_id))
            .await
    }

    /// Get envelope details.
    pub async fn get_envelope(
        &self,
        account_id: &str,
        envelope_id: &str,
        include: Option<&str>,
    ) -> DocuSignResult<serde_json::Value> {
        let qs = build_query(&[include.map(|v| ("include", v.to_string()))]);
        self.get(&format!("/{account_id}/envelopes/{envelope_id}{qs}"))
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
        let qs = build_query(&[search_text.map(|v| ("search_text", v.to_string()))]);
        self.get(&format!("/{account_id}/templates{qs}")).await
    }

    /// Get template details.
    pub async fn get_template(
        &self,
        account_id: &str,
        template_id: &str,
    ) -> DocuSignResult<serde_json::Value> {
        self.get(&format!("/{account_id}/templates/{template_id}"))
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
        self.get_raw(&format!(
            "/{account_id}/envelopes/{envelope_id}/documents/{doc_path}"
        ))
        .await
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
    fn build_query_empty() {
        assert_eq!(build_query(&[None, None]), "");
    }

    #[test]
    fn build_query_one() {
        assert_eq!(
            build_query(&[Some(("from_date", "2026-01-01".into()))]),
            "?from_date=2026-01-01"
        );
    }

    #[test]
    fn build_query_two() {
        assert_eq!(
            build_query(&[
                Some(("from_date", "2026-01-01".into())),
                Some(("status", "completed".into()))
            ]),
            "?from_date=2026-01-01&status=completed"
        );
    }

    #[test]
    fn build_query_with_nones() {
        assert_eq!(
            build_query(&[
                None,
                Some(("status", "sent".into())),
                None,
                Some(("count", "25".into())),
            ]),
            "?status=sent&count=25"
        );
    }

    #[test]
    fn build_query_all_none() {
        assert_eq!(build_query(&[None, None, None, None, None, None]), "");
    }

    #[test]
    fn client_default_base_url() {
        let c = DocuSignClient::new(
            DocuSignAuth::BearerToken("tok".into()),
            None,
        )
        .unwrap();
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
        let c = DocuSignClient::new(
            DocuSignAuth::BearerToken("secret".into()),
            None,
        )
        .unwrap();
        let dbg = format!("{c:?}");
        assert!(!dbg.contains("secret"));
        assert!(dbg.contains("DocuSignClient"));
    }
}
