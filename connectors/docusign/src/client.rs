//! `DocuSign` API client.

use std::fmt;
use std::time::Duration;

use fcp_prelude::CredentialId;
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig};
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{DocuSignError, DocuSignResult},
    types::ApiErrorResponse,
};

/// Validate a user-supplied path segment to prevent URL path injection.
fn sanitize_path_segment<'a>(value: &'a str, field: &str) -> DocuSignResult<&'a str> {
    if value.trim().is_empty() {
        return Err(DocuSignError::InvalidInput(format!(
            "{field} must not be empty"
        )));
    }
    let lower = value.to_ascii_lowercase();
    if value.contains('/')
        || value.contains('\\')
        || value.contains("..")
        || lower.contains("%2f")
        || lower.contains("%5c")
    {
        return Err(DocuSignError::InvalidInput(format!(
            "{field} contains path traversal characters"
        )));
    }
    Ok(value)
}

/// Well-known `DocuSign` demo environment URL.
///
/// **WARNING**: This is the demo/sandbox environment, NOT production.
/// Production URLs vary by region (na1, na2, eu, au).
/// Connectors must always receive an explicit `base_url` from configuration.
pub const DEMO_BASE_URL: &str = "https://demo.docusign.net/restapi/v2.1/accounts";

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
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
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
    ///
    /// `base_url` is **required** — there is no safe default because `DocuSign`
    /// demo and production environments are completely separate. Callers must
    /// explicitly choose (e.g. `"https://na1.docusign.net/restapi/v2.1/accounts"`
    /// for production or `DEMO_BASE_URL` for testing).
    pub fn new(auth: DocuSignAuth, base_url: &str) -> DocuSignResult<Self> {
        if base_url.trim().is_empty() {
            return Err(DocuSignError::InvalidInput(
                "base_url is required — DocuSign has no safe default (demo vs production is a deployment choice)".into(),
            ));
        }
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-docusign/0.1.0 (FCP connector)")
            .build()?;

        Ok(Self {
            client,
            auth,
            base_url: base_url.trim_end_matches('/').to_string(),
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

        let mut body = resp.text().await.unwrap_or_default();
        body.truncate(2048);
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
        let account_id = sanitize_path_segment(params.account_id, "account_id")?;
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
            &format!("/{account_id}/envelopes"),
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
        let account_id = sanitize_path_segment(account_id, "account_id")?;
        let envelope_id = sanitize_path_segment(envelope_id, "envelope_id")?;
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
        let account_id = sanitize_path_segment(account_id, "account_id")?;
        self.post(&format!("/{account_id}/envelopes"), body).await
    }

    /// Send a draft envelope (update status to sent).
    pub async fn send_envelope(
        &self,
        account_id: &str,
        envelope_id: &str,
    ) -> DocuSignResult<serde_json::Value> {
        let account_id = sanitize_path_segment(account_id, "account_id")?;
        let envelope_id = sanitize_path_segment(envelope_id, "envelope_id")?;
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
        let account_id = sanitize_path_segment(account_id, "account_id")?;
        let envelope_id = sanitize_path_segment(envelope_id, "envelope_id")?;
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
        let account_id = sanitize_path_segment(account_id, "account_id")?;
        let envelope_id = sanitize_path_segment(envelope_id, "envelope_id")?;
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
        let account_id = sanitize_path_segment(account_id, "account_id")?;
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
        let account_id = sanitize_path_segment(account_id, "account_id")?;
        let template_id = sanitize_path_segment(template_id, "template_id")?;
        self.get(&format!("/{account_id}/templates/{template_id}"), None)
            .await
    }

    // -- Documents --

    /// Update existing recipients on an envelope.
    pub async fn update_recipients(
        &self,
        account_id: &str,
        envelope_id: &str,
        recipients: &serde_json::Value,
    ) -> DocuSignResult<serde_json::Value> {
        let account_id = sanitize_path_segment(account_id, "account_id")?;
        let envelope_id = sanitize_path_segment(envelope_id, "envelope_id")?;
        self.put(
            &format!("/{account_id}/envelopes/{envelope_id}/recipients"),
            recipients,
        )
        .await
    }

    /// Add tabs/fields to an envelope recipient.
    pub async fn add_tabs(
        &self,
        account_id: &str,
        envelope_id: &str,
        recipient_id: &str,
        tabs: &serde_json::Value,
    ) -> DocuSignResult<serde_json::Value> {
        let account_id = sanitize_path_segment(account_id, "account_id")?;
        let envelope_id = sanitize_path_segment(envelope_id, "envelope_id")?;
        let recipient_id = sanitize_path_segment(recipient_id, "recipient_id")?;
        self.post(
            &format!("/{account_id}/envelopes/{envelope_id}/recipients/{recipient_id}/tabs"),
            tabs,
        )
        .await
    }

    /// Resend notifications for an envelope.
    pub async fn resend_envelope(
        &self,
        account_id: &str,
        envelope_id: &str,
    ) -> DocuSignResult<serde_json::Value> {
        let account_id = sanitize_path_segment(account_id, "account_id")?;
        let envelope_id = sanitize_path_segment(envelope_id, "envelope_id")?;
        let url = format!(
            "{}/{account_id}/envelopes/{envelope_id}?resend_envelope=true",
            self.base_url
        );
        let body = serde_json::json!({"status": "sent"});
        let req = self
            .add_auth(self.client.put(&url))
            .header("Accept", "application/json")
            .json(&body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    /// List documents in an envelope.
    pub async fn list_documents(
        &self,
        account_id: &str,
        envelope_id: &str,
    ) -> DocuSignResult<serde_json::Value> {
        let account_id = sanitize_path_segment(account_id, "account_id")?;
        let envelope_id = sanitize_path_segment(envelope_id, "envelope_id")?;
        self.get(
            &format!("/{account_id}/envelopes/{envelope_id}/documents"),
            None,
        )
        .await
    }

    /// Create an envelope from a template.
    pub async fn create_from_template(
        &self,
        account_id: &str,
        template_id: &str,
        roles: &serde_json::Value,
        status: Option<&str>,
    ) -> DocuSignResult<serde_json::Value> {
        let account_id = sanitize_path_segment(account_id, "account_id")?;
        let body = serde_json::json!({
            "templateId": template_id,
            "templateRoles": roles,
            "status": status.unwrap_or("created"),
        });
        self.post(&format!("/{account_id}/envelopes"), &body).await
    }

    /// Download documents (combined PDF by default).
    pub async fn download_documents(
        &self,
        account_id: &str,
        envelope_id: &str,
        document_id: Option<&str>,
    ) -> DocuSignResult<Vec<u8>> {
        let account_id = sanitize_path_segment(account_id, "account_id")?;
        let envelope_id = sanitize_path_segment(envelope_id, "envelope_id")?;
        let doc_path = document_id.unwrap_or("combined");
        let doc_path = sanitize_path_segment(doc_path, "document_id")?;
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
    fn client_with_demo_base_url() {
        let c =
            DocuSignClient::new(DocuSignAuth::BearerToken("tok".into()), DEMO_BASE_URL).unwrap();
        assert_eq!(c.base_url, DEMO_BASE_URL);
    }

    #[test]
    fn client_rejects_empty_base_url() {
        let result = DocuSignClient::new(DocuSignAuth::BearerToken("tok".into()), "");
        assert!(result.is_err());
    }

    #[test]
    fn client_custom_base_url() {
        let c = DocuSignClient::new(
            DocuSignAuth::BearerToken("tok".into()),
            "https://custom.docusign.net/restapi/v2.1/accounts",
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
            "https://example.com/api/",
        )
        .unwrap();
        assert_eq!(c.base_url, "https://example.com/api");
    }

    #[test]
    fn client_debug_format() {
        let c =
            DocuSignClient::new(DocuSignAuth::BearerToken("secret".into()), DEMO_BASE_URL).unwrap();
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
        let c =
            DocuSignClient::new(DocuSignAuth::BearerToken("tok".into()), DEMO_BASE_URL).unwrap();
        let dbg = format!("{c:?}");
        assert!(dbg.contains("base_url"));
    }

    #[test]
    fn client_new_with_credential_id() {
        let cred = CredentialId::new();
        let c = DocuSignClient::new(DocuSignAuth::CredentialId(cred), DEMO_BASE_URL).unwrap();
        assert_eq!(c.base_url, DEMO_BASE_URL);
    }

    #[test]
    fn demo_base_url_contains_docusign() {
        assert!(DEMO_BASE_URL.contains("docusign"));
    }

    #[test]
    fn default_base_url_is_https() {
        assert!(DEMO_BASE_URL.starts_with("https://"));
    }

    #[test]
    fn default_base_url_contains_restapi() {
        assert!(DEMO_BASE_URL.contains("restapi"));
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
            "https://example.com/api////",
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

    // -- sanitize_path_segment tests --

    #[test]
    fn sanitize_path_segment_valid() {
        assert_eq!(
            sanitize_path_segment("abc-123-def", "id").unwrap(),
            "abc-123-def"
        );
    }

    #[test]
    fn sanitize_path_segment_rejects_empty() {
        let err = sanitize_path_segment("", "account_id").unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn sanitize_path_segment_rejects_whitespace_only() {
        let err = sanitize_path_segment("   ", "account_id").unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn sanitize_path_segment_rejects_slash() {
        let err = sanitize_path_segment("acc/evil", "account_id").unwrap_err();
        assert!(err.to_string().contains("path traversal"));
    }

    #[test]
    fn sanitize_path_segment_rejects_backslash() {
        let err = sanitize_path_segment("acc\\evil", "account_id").unwrap_err();
        assert!(err.to_string().contains("path traversal"));
    }

    #[test]
    fn sanitize_path_segment_rejects_dot_dot() {
        let err = sanitize_path_segment("acc..evil", "account_id").unwrap_err();
        assert!(err.to_string().contains("path traversal"));
    }

    #[test]
    fn sanitize_path_segment_rejects_encoded_slash() {
        let err = sanitize_path_segment("acc%2Fevil", "account_id").unwrap_err();
        assert!(err.to_string().contains("path traversal"));
    }

    #[test]
    fn sanitize_path_segment_rejects_encoded_backslash_lower() {
        let err = sanitize_path_segment("acc%5cevil", "envelope_id").unwrap_err();
        assert!(err.to_string().contains("path traversal"));
    }

    #[test]
    fn sanitize_path_segment_allows_guid_format() {
        assert_eq!(
            sanitize_path_segment("d8e7f6a5-b4c3-2d1e-0f9a-8b7c6d5e4f3a", "envelope_id").unwrap(),
            "d8e7f6a5-b4c3-2d1e-0f9a-8b7c6d5e4f3a"
        );
    }
}
