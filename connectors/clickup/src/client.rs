//! `ClickUp` API client.

use std::fmt;
use std::time::Duration;

use fcp_core::CredentialId;
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{ClickUpError, ClickUpResult},
    types::ApiErrorResponse,
};

/// Default `ClickUp` REST API base URL.
pub const DEFAULT_BASE_URL: &str = "https://api.clickup.com/api/v2";

/// Authentication mode for the `ClickUp` API.
#[derive(Clone)]
pub enum ClickUpAuth {
    /// API token (passed as `Authorization: <token>` without Bearer prefix).
    ApiToken(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl ClickUpAuth {
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::ApiToken(_) => "api_token:redacted".to_string(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for ClickUpAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApiToken(_) => f.debug_tuple("ApiToken").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// `ClickUp` API client.
pub struct ClickUpClient {
    client: Client,
    auth: ClickUpAuth,
    base_url: String,
}

impl fmt::Debug for ClickUpClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClickUpClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl ClickUpClient {
    /// Create a new `ClickUp` client.
    pub fn new(auth: ClickUpAuth, base_url: Option<&str>) -> ClickUpResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-clickup/0.1.0 (FCP connector)")
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
            ClickUpAuth::ApiToken(token) => req.header("Authorization", token),
            ClickUpAuth::CredentialId(id) => req.header("X-FCP-Credential-Id", id.to_string()),
        }
    }

    async fn handle_response(&self, resp: Response) -> ClickUpResult<serde_json::Value> {
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
    ) -> ClickUpResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = resp.text().await.unwrap_or_default();

        // ClickUp returns {"err": "message", "ECODE": "CODE"} on errors.
        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.err)
            .unwrap_or_else(|| {
                if body.is_empty() {
                    format!("HTTP {}", status.as_u16())
                } else {
                    body.clone()
                }
            });

        match status.as_u16() {
            401 => Err(ClickUpError::Unauthorized),
            403 => Err(ClickUpError::Forbidden),
            404 => Err(ClickUpError::NotFound { resource: detail }),
            429 => Err(ClickUpError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(ClickUpError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    #[instrument(skip(self), fields(url))]
    async fn get(&self, path: &str) -> ClickUpResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "GET request");
        let req = self
            .add_auth(self.client.get(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn post(&self, path: &str, body: &serde_json::Value) -> ClickUpResult<serde_json::Value> {
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
    async fn delete(&self, path: &str) -> ClickUpResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "DELETE request");
        let req = self
            .add_auth(self.client.delete(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- Spaces --

    /// List all spaces in a team/workspace.
    pub async fn list_spaces(&self, team_id: &str) -> ClickUpResult<serde_json::Value> {
        self.get(&format!("/team/{team_id}/space")).await
    }

    // -- Lists --

    /// List all lists in a space.
    pub async fn list_lists(&self, space_id: &str) -> ClickUpResult<serde_json::Value> {
        self.get(&format!("/space/{space_id}/list")).await
    }

    // -- Tasks --

    /// List tasks in a list.
    pub async fn list_tasks(&self, list_id: &str) -> ClickUpResult<serde_json::Value> {
        self.get(&format!("/list/{list_id}/task")).await
    }

    /// Create a new task in a list.
    pub async fn create_task(
        &self,
        list_id: &str,
        body: &serde_json::Value,
    ) -> ClickUpResult<serde_json::Value> {
        self.post(&format!("/list/{list_id}/task"), body).await
    }

    /// Delete a task.
    pub async fn delete_task(&self, task_id: &str) -> ClickUpResult<serde_json::Value> {
        self.delete(&format!("/task/{task_id}")).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_token() {
        let auth = ClickUpAuth::ApiToken("secret-api-token".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("secret-api-token"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let token = ClickUpAuth::ApiToken("tok".into());
        assert!(!token.is_secretless());
        let cred = ClickUpAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label() {
        let token = ClickUpAuth::ApiToken("tok".into());
        assert_eq!(token.redacted_label(), "api_token:redacted");
    }

    #[test]
    fn auth_credential_label() {
        let cred = ClickUpAuth::CredentialId(CredentialId::new());
        let label = cred.redacted_label();
        assert!(label.starts_with("credential_id:"));
    }

    #[test]
    fn client_new_default_url() {
        let client = ClickUpClient::new(ClickUpAuth::ApiToken("tok".into()), None).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn client_new_custom_url() {
        let client = ClickUpClient::new(
            ClickUpAuth::ApiToken("tok".into()),
            Some("https://test.example.com/api/"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://test.example.com/api");
    }

    #[test]
    fn client_debug_redacts() {
        let client = ClickUpClient::new(ClickUpAuth::ApiToken("secret".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("secret"));
        assert!(dbg.contains("redacted"));
    }

    // ── Client construction edge cases ────────────────────────────

    #[test]
    fn client_new_trims_trailing_slash() {
        let client = ClickUpClient::new(
            ClickUpAuth::ApiToken("tok".into()),
            Some("https://test.example.com/api/v2/"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://test.example.com/api/v2");
    }

    #[test]
    fn client_debug_contains_base_url() {
        let client = ClickUpClient::new(ClickUpAuth::ApiToken("tok".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("ClickUpClient"));
        assert!(dbg.contains("base_url"));
        assert!(dbg.contains("clickup.com"));
    }

    // ── Auth clone ────────────────────────────────────────────────

    #[test]
    fn auth_api_token_clone() {
        let auth = ClickUpAuth::ApiToken("mytoken".into());
        let cloned = auth.clone();
        assert_eq!(auth.redacted_label(), "api_token:redacted");
        assert_eq!(cloned.redacted_label(), "api_token:redacted");
        assert!(!cloned.is_secretless());
    }

    #[test]
    fn auth_credential_id_clone() {
        let cred = ClickUpAuth::CredentialId(CredentialId::new());
        let cloned = cred.clone();
        assert!(cred.is_secretless());
        assert!(cloned.is_secretless());
        assert!(cloned.redacted_label().starts_with("credential_id:"));
    }

    #[test]
    fn auth_debug_credential_id_contains_id() {
        let id = CredentialId::new();
        let id_str = id.to_string();
        let auth = ClickUpAuth::CredentialId(id);
        let dbg = format!("{auth:?}");
        assert!(dbg.contains(&id_str));
        assert!(dbg.contains("CredentialId"));
    }

    // ── DEFAULT_BASE_URL ──────────────────────────────────────────

    #[test]
    fn default_base_url_constant() {
        assert!(DEFAULT_BASE_URL.starts_with("https://"));
        assert!(DEFAULT_BASE_URL.contains("clickup"));
        assert!(!DEFAULT_BASE_URL.ends_with('/'));
    }

    #[test]
    fn client_new_with_credential_id() {
        let client =
            ClickUpClient::new(ClickUpAuth::CredentialId(CredentialId::new()), None).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn auth_debug_api_token_no_leak() {
        let auth = ClickUpAuth::ApiToken("pk_12345678_ABCDEFGHIJKLMNOP".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("pk_12345678"));
        assert!(!dbg.contains("ABCDEFGHIJKLMNOP"));
        assert!(dbg.contains("ApiToken"));
    }

    #[test]
    fn client_new_empty_url() {
        let client = ClickUpClient::new(ClickUpAuth::ApiToken("tok".into()), Some("")).unwrap();
        assert_eq!(client.base_url, "");
    }

    #[test]
    fn client_new_multiple_trailing_slashes() {
        let client = ClickUpClient::new(
            ClickUpAuth::ApiToken("tok".into()),
            Some("https://x.com///"),
        )
        .unwrap();
        assert!(client.base_url.ends_with("//"));
    }

    #[test]
    fn default_base_url_contains_v2() {
        assert!(DEFAULT_BASE_URL.contains("v2"));
    }

    #[test]
    fn auth_debug_format_starts_with_variant() {
        let tok = ClickUpAuth::ApiToken("t".into());
        assert!(format!("{tok:?}").starts_with("ApiToken"));
        let cred = ClickUpAuth::CredentialId(CredentialId::new());
        assert!(format!("{cred:?}").starts_with("CredentialId"));
    }

    #[test]
    fn client_debug_shows_auth_field() {
        let client = ClickUpClient::new(ClickUpAuth::ApiToken("tok".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("auth"));
    }

    #[test]
    fn auth_redacted_label_credential_contains_uuid() {
        let id = CredentialId::new();
        let id_str = id.to_string();
        let auth = ClickUpAuth::CredentialId(id);
        let label = auth.redacted_label();
        assert!(label.contains(&id_str));
    }

    #[test]
    fn client_new_no_trailing_slash_unchanged() {
        let client = ClickUpClient::new(
            ClickUpAuth::ApiToken("tok".into()),
            Some("https://example.com"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://example.com");
    }
}
