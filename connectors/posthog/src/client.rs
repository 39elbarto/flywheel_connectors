//! `PostHog` API client.

#![allow(clippy::doc_markdown)]

use std::fmt;
use std::time::Duration;

use fcp_core::CredentialId;
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{PostHogError, PostHogResult},
    types::ApiErrorResponse,
};

/// Default `PostHog` REST API base URL.
pub const DEFAULT_BASE_URL: &str = "https://app.posthog.com/api";

/// Authentication mode for the `PostHog` API.
#[derive(Clone)]
pub enum PostHogAuth {
    /// Personal API key (passed as `Authorization: Bearer <key>`).
    ApiKey(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl PostHogAuth {
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

impl fmt::Debug for PostHogAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApiKey(_) => f.debug_tuple("ApiKey").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// `PostHog` API client.
pub struct PostHogClient {
    client: Client,
    auth: PostHogAuth,
    base_url: String,
    project_id: String,
}

impl fmt::Debug for PostHogClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PostHogClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .field("project_id", &self.project_id)
            .finish()
    }
}

impl PostHogClient {
    /// Create a new `PostHog` client.
    pub fn new(
        auth: PostHogAuth,
        project_id: &str,
        base_url: Option<&str>,
    ) -> PostHogResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-posthog/0.1.0 (FCP connector)")
            .build()?;

        Ok(Self {
            client,
            auth,
            base_url: base_url
                .unwrap_or(DEFAULT_BASE_URL)
                .trim_end_matches('/')
                .to_string(),
            project_id: project_id.to_string(),
        })
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            PostHogAuth::ApiKey(key) => req.header("Authorization", format!("Bearer {key}")),
            PostHogAuth::CredentialId(id) => {
                req.header("X-FCP-Credential-Id", id.to_string())
            }
        }
    }

    async fn handle_response(&self, resp: Response) -> PostHogResult<serde_json::Value> {
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
    ) -> PostHogResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = resp.text().await.unwrap_or_default();

        // PostHog returns {"type": "...", "code": "...", "detail": "message", "attr": ...} on errors.
        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.detail)
            .unwrap_or_else(|| {
                if body.is_empty() {
                    format!("HTTP {}", status.as_u16())
                } else {
                    body.clone()
                }
            });

        match status.as_u16() {
            401 => Err(PostHogError::Unauthorized),
            403 => Err(PostHogError::Forbidden),
            404 => Err(PostHogError::NotFound { resource: detail }),
            429 => Err(PostHogError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(PostHogError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    #[instrument(skip(self), fields(url))]
    async fn get(&self, path: &str) -> PostHogResult<serde_json::Value> {
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
    ) -> PostHogResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "POST request");
        let req = self
            .add_auth(self.client.post(&url))
            .header("Accept", "application/json")
            .json(body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- Events Query --

    /// Query events using HogQL.
    pub async fn query_events(&self, hogql_query: &str) -> PostHogResult<serde_json::Value> {
        let body = serde_json::json!({
            "query": {
                "kind": "HogQLQuery",
                "query": hogql_query
            }
        });
        self.post(
            &format!("/projects/{}/query", self.project_id),
            &body,
        )
        .await
    }

    // -- Insights --

    /// List saved insights.
    pub async fn list_insights(&self) -> PostHogResult<serde_json::Value> {
        self.get(&format!("/projects/{}/insights", self.project_id))
            .await
    }

    // -- Feature Flags --

    /// List feature flags.
    pub async fn list_feature_flags(&self) -> PostHogResult<serde_json::Value> {
        self.get(&format!(
            "/projects/{}/feature_flags",
            self.project_id
        ))
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_key() {
        let auth = PostHogAuth::ApiKey("phx_secret_api_key_12345".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("phx_secret_api_key_12345"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let key = PostHogAuth::ApiKey("phx_key".into());
        assert!(!key.is_secretless());
        let cred = PostHogAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label() {
        let key = PostHogAuth::ApiKey("phx_key".into());
        assert_eq!(key.redacted_label(), "api_key:redacted");
    }

    #[test]
    fn auth_credential_label() {
        let cred = PostHogAuth::CredentialId(CredentialId::new());
        let label = cred.redacted_label();
        assert!(label.starts_with("credential_id:"));
    }

    #[test]
    fn client_new_default_url() {
        let client =
            PostHogClient::new(PostHogAuth::ApiKey("phx_key".into()), "12345", None).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
        assert_eq!(client.project_id, "12345");
    }

    #[test]
    fn client_new_custom_url() {
        let client = PostHogClient::new(
            PostHogAuth::ApiKey("phx_key".into()),
            "99",
            Some("https://posthog.example.com/api/"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://posthog.example.com/api");
    }

    #[test]
    fn client_debug_redacts() {
        let client =
            PostHogClient::new(PostHogAuth::ApiKey("secret".into()), "123", None).unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("secret"));
        assert!(dbg.contains("redacted"));
    }

    // -- Additional client tests --

    #[test]
    fn client_new_trims_trailing_slash() {
        let client = PostHogClient::new(
            PostHogAuth::ApiKey("phx_key".into()),
            "42",
            Some("https://posthog.example.com/api/"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://posthog.example.com/api");
    }

    #[test]
    fn client_debug_shows_project_id() {
        let client = PostHogClient::new(
            PostHogAuth::ApiKey("phx_key".into()),
            "proj_999",
            None,
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("proj_999"));
        assert!(dbg.contains("PostHogClient"));
    }

    #[test]
    fn client_debug_shows_credential_id() {
        let cred = CredentialId::new();
        let cred_str = cred.to_string();
        let client = PostHogClient::new(
            PostHogAuth::CredentialId(cred),
            "1",
            None,
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains(&cred_str));
    }

    #[test]
    fn auth_clone() {
        let auth = PostHogAuth::ApiKey("phx_key".into());
        let cloned = auth.clone();
        assert!(!auth.is_secretless());
        assert_eq!(cloned.redacted_label(), "api_key:redacted");
    }

    #[test]
    fn auth_credential_clone() {
        let auth = PostHogAuth::CredentialId(CredentialId::new());
        let cloned = auth.clone();
        assert!(auth.is_secretless());
        assert!(cloned.redacted_label().starts_with("credential_id:"));
    }

    #[test]
    fn auth_credential_debug_shows_id() {
        let cred = CredentialId::new();
        let cred_str = cred.to_string();
        let auth = PostHogAuth::CredentialId(cred);
        let dbg = format!("{auth:?}");
        assert!(dbg.contains(&cred_str));
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn default_base_url_value() {
        assert_eq!(DEFAULT_BASE_URL, "https://app.posthog.com/api");
    }

    #[test]
    fn client_stores_project_id() {
        let client = PostHogClient::new(
            PostHogAuth::ApiKey("phx_key".into()),
            "my_project",
            None,
        )
        .unwrap();
        assert_eq!(client.project_id, "my_project");
    }

    #[test]
    fn client_credential_default_url() {
        let client = PostHogClient::new(
            PostHogAuth::CredentialId(CredentialId::new()),
            "1",
            None,
        )
        .unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn client_empty_project_id() {
        let client = PostHogClient::new(
            PostHogAuth::ApiKey("phx_key".into()),
            "",
            None,
        )
        .unwrap();
        assert_eq!(client.project_id, "");
    }
}
