//! `Logseq` API client.

use std::fmt;
use std::time::Duration;

use fcp_prelude::CredentialId;
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig};
use reqwest::{Client, Response, StatusCode};
use serde_json::json;
use tracing::{debug, instrument};

use crate::{
    error::{LogseqError, LogseqResult},
    types::ApiErrorResponse,
};

/// Default `Logseq` API base URL (local HTTP server).
pub const DEFAULT_BASE_URL: &str = "http://localhost:12315/api";

/// Authentication mode for the `Logseq` API.
#[derive(Clone)]
pub enum LogseqAuth {
    /// Bearer token (API token from Logseq Settings > Features > Developer).
    BearerToken(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl LogseqAuth {
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

impl fmt::Debug for LogseqAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BearerToken(_) => f.debug_tuple("BearerToken").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// `Logseq` API client.
pub struct LogseqClient {
    client: Client,
    auth: LogseqAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl fmt::Debug for LogseqClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LogseqClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl LogseqClient {
    /// Create a new `Logseq` client.
    pub fn new(auth: LogseqAuth, base_url: Option<&str>) -> LogseqResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent("fcp-logseq/0.1.0 (FCP connector)")
            .build()?;

        Ok(Self {
            client,
            auth,
            base_url: base_url
                .unwrap_or(DEFAULT_BASE_URL)
                .trim_end_matches('/')
                .to_string(),
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(15)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 3,
                ..HttpRetryConfig::default()
            },
        })
    }

    /// Return the base URL.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Trigger graceful shutdown of request contexts.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            LogseqAuth::BearerToken(token) => req.bearer_auth(token),
            LogseqAuth::CredentialId(id) => req.header("X-FCP-Credential-Id", id.to_string()),
        }
    }

    async fn handle_response(&self, resp: Response) -> LogseqResult<serde_json::Value> {
        let status = resp.status();
        if status.is_success() {
            let body = resp.text().await?;
            if body.is_empty() {
                return Ok(json!({}));
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
    ) -> LogseqResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let mut body = resp.text().await.unwrap_or_default();
        body.truncate(2048);
        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.error)
            .unwrap_or_else(|| body.clone());

        match status.as_u16() {
            401 => Err(LogseqError::Unauthorized),
            403 => Err(LogseqError::Forbidden),
            404 => Err(LogseqError::NotFound { resource: detail }),
            429 => Err(LogseqError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(LogseqError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    #[instrument(skip(self, body), fields(url))]
    async fn post(
        &self,
        endpoint: &str,
        body: &serde_json::Value,
    ) -> LogseqResult<serde_json::Value> {
        let url = format!("{}{endpoint}", self.base_url);
        debug!(url = %url, "POST request");
        let req = self
            .add_auth(self.client.post(&url))
            .header("Accept", "application/json")
            .json(body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- Pages --

    /// List all pages in the graph.
    pub async fn list_pages(&self) -> LogseqResult<serde_json::Value> {
        let result = self.post("/pages", &json!({})).await?;
        // Logseq returns an array of pages; wrap in object
        let pages = if result.is_array() { result } else { json!([]) };
        Ok(json!({ "pages": pages }))
    }

    /// Get a page by name.
    pub async fn get_page(&self, name: &str) -> LogseqResult<serde_json::Value> {
        let body = json!({ "name": name });
        let result = self.post("/page", &body).await?;
        if result.is_null()
            || (result.is_object() && result.as_object().is_some_and(|o| o.is_empty()))
        {
            return Err(LogseqError::NotFound {
                resource: format!("Page with name: {name}"),
            });
        }
        Ok(result)
    }

    // -- Blocks --

    /// List blocks on a page.
    pub async fn list_blocks(&self, page: &str) -> LogseqResult<serde_json::Value> {
        let body = json!({ "page": page });
        let result = self.post("/page-blocks", &body).await?;
        let blocks = if result.is_array() { result } else { json!([]) };
        Ok(json!({ "blocks": blocks }))
    }

    /// Create a block on a page.
    pub async fn create_block(&self, page: &str, content: &str) -> LogseqResult<serde_json::Value> {
        let body = json!({
            "page": page,
            "content": content,
        });
        self.post("/insert-block", &body).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_token() {
        let auth = LogseqAuth::BearerToken("secret-token".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("secret-token"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let token = LogseqAuth::BearerToken("tok".into());
        assert!(!token.is_secretless());
        let cred = LogseqAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label() {
        let token = LogseqAuth::BearerToken("tok".into());
        assert_eq!(token.redacted_label(), "bearer_token:redacted");
    }

    #[test]
    fn auth_credential_id_label() {
        let cred = LogseqAuth::CredentialId(CredentialId::new());
        let label = cred.redacted_label();
        assert!(label.starts_with("credential_id:"));
    }

    #[test]
    fn auth_debug_credential_id() {
        let cred = LogseqAuth::CredentialId(CredentialId::new());
        let dbg = format!("{cred:?}");
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn default_base_url_value() {
        assert_eq!(DEFAULT_BASE_URL, "http://localhost:12315/api");
    }

    #[test]
    fn client_new_default_base_url() {
        let client = LogseqClient::new(LogseqAuth::BearerToken("tok".into()), None).unwrap();
        assert_eq!(client.base_url(), DEFAULT_BASE_URL);
    }

    #[test]
    fn client_new_custom_base_url() {
        let client = LogseqClient::new(
            LogseqAuth::BearerToken("tok".into()),
            Some("http://localhost:9999/api"),
        )
        .unwrap();
        assert_eq!(client.base_url(), "http://localhost:9999/api");
    }

    #[test]
    fn client_trims_trailing_slash() {
        let client = LogseqClient::new(
            LogseqAuth::BearerToken("tok".into()),
            Some("http://localhost:12315/api/"),
        )
        .unwrap();
        assert_eq!(client.base_url(), "http://localhost:12315/api");
    }

    #[test]
    fn client_debug_shows_fields() {
        let client = LogseqClient::new(LogseqAuth::BearerToken("secret".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("LogseqClient"));
        assert!(dbg.contains("base_url"));
        assert!(!dbg.contains("secret"));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn auth_bearer_clone() {
        let auth = LogseqAuth::BearerToken("tok".into());
        let cloned = auth.clone();
        assert!(!cloned.is_secretless());
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn auth_credential_clone() {
        let auth = LogseqAuth::CredentialId(CredentialId::new());
        let cloned = auth.clone();
        assert!(cloned.is_secretless());
    }

    #[test]
    fn client_new_with_credential_id() {
        let client =
            LogseqClient::new(LogseqAuth::CredentialId(CredentialId::new()), None).unwrap();
        assert_eq!(client.base_url(), DEFAULT_BASE_URL);
    }

    #[test]
    fn client_debug_contains_base_url() {
        let client = LogseqClient::new(LogseqAuth::BearerToken("tok".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("localhost:12315"));
    }

    #[test]
    fn client_trims_multiple_trailing_slashes() {
        let client = LogseqClient::new(
            LogseqAuth::BearerToken("tok".into()),
            Some("http://localhost:12315/api///"),
        )
        .unwrap();
        // Only the last slash should be trimmed by trim_end_matches
        assert!(!client.base_url().ends_with('/'));
    }

    #[test]
    fn auth_bearer_debug_contains_bearer_token_label() {
        let auth = LogseqAuth::BearerToken("super-secret".into());
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("BearerToken"));
        assert!(!dbg.contains("super-secret"));
    }

    #[test]
    fn auth_credential_redacted_label_contains_uuid() {
        let id = CredentialId::new();
        let label_expected = format!("credential_id:{id}");
        let auth = LogseqAuth::CredentialId(id);
        assert_eq!(auth.redacted_label(), label_expected);
    }

    #[test]
    fn client_custom_base_url_no_trailing_slash() {
        let client = LogseqClient::new(
            LogseqAuth::BearerToken("tok".into()),
            Some("http://myhost:8080/logseq"),
        )
        .unwrap();
        assert_eq!(client.base_url(), "http://myhost:8080/logseq");
    }

    #[test]
    fn default_base_url_starts_with_http() {
        assert!(DEFAULT_BASE_URL.starts_with("http"));
    }

    #[test]
    fn default_base_url_contains_api() {
        assert!(DEFAULT_BASE_URL.contains("/api"));
    }

    #[test]
    fn auth_bearer_is_not_secretless() {
        let auth = LogseqAuth::BearerToken("anything".into());
        assert!(!auth.is_secretless());
    }

    #[test]
    fn auth_credential_is_secretless() {
        let auth = LogseqAuth::CredentialId(CredentialId::new());
        assert!(auth.is_secretless());
    }

    #[test]
    fn client_debug_does_not_leak_bearer_token() {
        let client =
            LogseqClient::new(LogseqAuth::BearerToken("my-token-xyz".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("my-token-xyz"));
    }
}
