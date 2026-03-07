//! n8n API client.

use std::fmt;
use std::time::Duration;

use fcp_core::CredentialId;
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{N8nError, N8nResult},
    types::ApiErrorResponse,
};

/// Authentication mode for the n8n API.
#[derive(Clone)]
pub enum N8nAuth {
    /// API key (passed as `X-N8N-API-KEY: <key>` header).
    ApiKey(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl N8nAuth {
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

impl fmt::Debug for N8nAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApiKey(_) => f.debug_tuple("ApiKey").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// n8n API client.
pub struct N8nClient {
    client: Client,
    auth: N8nAuth,
    base_url: String,
}

impl fmt::Debug for N8nClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("N8nClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl N8nClient {
    /// Create a new n8n client.
    ///
    /// `base_url` is required for n8n (self-hosted).
    pub fn new(auth: N8nAuth, base_url: &str) -> N8nResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-n8n/0.1.0 (FCP connector)")
            .build()?;

        Ok(Self {
            client,
            auth,
            base_url: base_url.trim_end_matches('/').to_string(),
        })
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            N8nAuth::ApiKey(key) => req.header("X-N8N-API-KEY", key),
            N8nAuth::CredentialId(id) => req.header("X-FCP-Credential-Id", id.to_string()),
        }
    }

    async fn handle_response(&self, resp: Response) -> N8nResult<serde_json::Value> {
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
    ) -> N8nResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = resp.text().await.unwrap_or_default();

        // n8n returns {"message": "error description"} on errors.
        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.message)
            .unwrap_or_else(|| {
                if body.is_empty() {
                    format!("HTTP {}", status.as_u16())
                } else {
                    body.clone()
                }
            });

        match status.as_u16() {
            401 => Err(N8nError::Unauthorized),
            403 => Err(N8nError::Forbidden),
            404 => Err(N8nError::NotFound { resource: detail }),
            429 => Err(N8nError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(N8nError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    #[instrument(skip(self), fields(url))]
    async fn get(&self, path: &str) -> N8nResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "GET request");
        let req = self
            .add_auth(self.client.get(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn patch(&self, path: &str, body: &serde_json::Value) -> N8nResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "PATCH request");
        let req = self
            .add_auth(self.client.patch(&url))
            .header("Accept", "application/json")
            .json(body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- Workflows --

    /// List all workflows.
    pub async fn list_workflows(&self) -> N8nResult<serde_json::Value> {
        self.get("/workflows").await
    }

    /// Get a specific workflow by ID.
    pub async fn get_workflow(&self, id: &str) -> N8nResult<serde_json::Value> {
        self.get(&format!("/workflows/{id}")).await
    }

    /// Activate or deactivate a workflow.
    pub async fn activate_workflow(&self, id: &str, active: bool) -> N8nResult<serde_json::Value> {
        let body = serde_json::json!({ "active": active });
        self.patch(&format!("/workflows/{id}"), &body).await
    }

    // -- Executions --

    /// List recent executions.
    pub async fn list_executions(&self) -> N8nResult<serde_json::Value> {
        self.get("/executions").await
    }

    /// Get a specific execution by ID.
    pub async fn get_execution(&self, id: &str) -> N8nResult<serde_json::Value> {
        self.get(&format!("/executions/{id}")).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_key() {
        let auth = N8nAuth::ApiKey("secret-api-key-12345".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("secret-api-key-12345"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let key = N8nAuth::ApiKey("key".into());
        assert!(!key.is_secretless());
        let cred = N8nAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label_api_key() {
        let key = N8nAuth::ApiKey("key".into());
        assert_eq!(key.redacted_label(), "api_key:redacted");
    }

    #[test]
    fn auth_redacted_label_credential() {
        let cred = N8nAuth::CredentialId(CredentialId::new());
        let label = cred.redacted_label();
        assert!(label.starts_with("credential_id:"));
    }

    #[test]
    fn client_new_strips_trailing_slash() {
        let client = N8nClient::new(
            N8nAuth::ApiKey("key".into()),
            "https://n8n.example.com/api/v1/",
        )
        .unwrap();
        assert_eq!(client.base_url, "https://n8n.example.com/api/v1");
    }

    #[test]
    fn client_new_no_trailing_slash() {
        let client = N8nClient::new(
            N8nAuth::ApiKey("key".into()),
            "https://n8n.example.com/api/v1",
        )
        .unwrap();
        assert_eq!(client.base_url, "https://n8n.example.com/api/v1");
    }

    #[test]
    fn client_debug_redacts() {
        let client = N8nClient::new(
            N8nAuth::ApiKey("super-secret".into()),
            "https://n8n.example.com/api/v1",
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("super-secret"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_debug_credential_id() {
        let cred = N8nAuth::CredentialId(CredentialId::new());
        let dbg = format!("{cred:?}");
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn auth_clone() {
        let auth = N8nAuth::ApiKey("key".into());
        #[allow(clippy::redundant_clone)]
        let cloned = auth.clone();
        assert_eq!(cloned.redacted_label(), "api_key:redacted");
    }

    #[test]
    fn client_base_url_preserved() {
        let client = N8nClient::new(
            N8nAuth::ApiKey("key".into()),
            "http://localhost:5678/api/v1",
        )
        .unwrap();
        assert_eq!(client.base_url, "http://localhost:5678/api/v1");
    }

    #[test]
    fn client_new_multiple_trailing_slashes() {
        let client = N8nClient::new(
            N8nAuth::ApiKey("key".into()),
            "https://n8n.example.com/api/v1///",
        )
        .unwrap();
        // trim_end_matches removes all trailing slashes
        assert!(!client.base_url.ends_with('/'));
    }

    #[test]
    fn auth_api_key_is_not_secretless() {
        assert!(!N8nAuth::ApiKey("key".into()).is_secretless());
    }

    #[test]
    fn auth_credential_id_is_secretless() {
        assert!(N8nAuth::CredentialId(CredentialId::new()).is_secretless());
    }

    #[test]
    fn auth_debug_bearer_shows_redacted_tuple() {
        let auth = N8nAuth::ApiKey("my-secret-key".into());
        let dbg = format!("{auth:?}");
        assert!(dbg.starts_with("ApiKey("));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn client_debug_contains_struct_name() {
        let client = N8nClient::new(
            N8nAuth::ApiKey("key".into()),
            "https://n8n.example.com/api/v1",
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("N8nClient"));
    }

    #[test]
    fn client_debug_contains_base_url() {
        let client = N8nClient::new(
            N8nAuth::ApiKey("key".into()),
            "https://custom.n8n.io/api/v1",
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("custom.n8n.io"));
    }

    #[test]
    fn auth_clone_credential_id() {
        let cred = N8nAuth::CredentialId(CredentialId::new());
        #[allow(clippy::redundant_clone)]
        let cloned = cred.clone();
        assert!(cloned.is_secretless());
    }

    #[test]
    fn auth_redacted_label_does_not_contain_key() {
        let auth = N8nAuth::ApiKey("very-secret-key-value".into());
        let label = auth.redacted_label();
        assert!(!label.contains("very-secret-key-value"));
    }

    #[test]
    fn client_new_with_localhost() {
        let client = N8nClient::new(
            N8nAuth::ApiKey("key".into()),
            "http://127.0.0.1:5678/api/v1",
        )
        .unwrap();
        assert_eq!(client.base_url, "http://127.0.0.1:5678/api/v1");
    }

    #[test]
    fn client_new_with_port() {
        let client = N8nClient::new(
            N8nAuth::ApiKey("key".into()),
            "https://n8n.example.com:8443/api/v1",
        )
        .unwrap();
        assert!(client.base_url.contains("8443"));
    }

    #[test]
    fn auth_debug_credential_does_not_say_redacted() {
        let cred = N8nAuth::CredentialId(CredentialId::new());
        let dbg = format!("{cred:?}");
        assert!(!dbg.contains("redacted"));
    }
}
