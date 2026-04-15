//! `Todoist` API client.

use std::fmt;
use std::time::Duration;

use fcp_core::CredentialId;
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig};
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{TodoistError, TodoistResult},
    types::ApiErrorResponse,
};

/// Default `Todoist` REST API base URL.
pub const DEFAULT_BASE_URL: &str = "https://api.todoist.com/rest/v2";

/// Validate a path segment to prevent path traversal.
fn sanitize_path_segment(segment: &str) -> TodoistResult<&str> {
    let lower = segment.to_ascii_lowercase();
    if segment.trim().is_empty()
        || segment.contains('/')
        || segment.contains('\\')
        || segment.contains("..")
        || segment.contains('\0')
        || lower.contains("%2f")
        || lower.contains("%5c")
    {
        return Err(TodoistError::InvalidInput(
            "Invalid path segment: contains illegal characters".into(),
        ));
    }
    Ok(segment)
}

/// Authentication mode for the `Todoist` API.
#[derive(Clone)]
pub enum TodoistAuth {
    /// Bearer token (API token).
    BearerToken(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl TodoistAuth {
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

impl fmt::Debug for TodoistAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BearerToken(_) => f.debug_tuple("BearerToken").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// `Todoist` API client.
pub struct TodoistClient {
    client: Client,
    auth: TodoistAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl fmt::Debug for TodoistClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TodoistClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl TodoistClient {
    /// Create a new `Todoist` client.
    pub fn new(auth: TodoistAuth, base_url: Option<&str>) -> TodoistResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-todoist/0.1.0 (FCP connector)")
            .build()?;

        let request_timeout = Duration::from_secs(30);
        Ok(Self {
            client,
            auth,
            base_url: base_url
                .unwrap_or(DEFAULT_BASE_URL)
                .trim_end_matches('/')
                .to_string(),
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(request_timeout),
            ),
            retry_config: HttpRetryConfig::default(),
        })
    }

    /// Shut down the connector runtime.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            TodoistAuth::BearerToken(token) => req.bearer_auth(token),
            TodoistAuth::CredentialId(id) => req.header("X-FCP-Credential-Id", id.to_string()),
        }
    }

    async fn handle_response(&self, resp: Response) -> TodoistResult<serde_json::Value> {
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
    ) -> TodoistResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = resp.text().await.unwrap_or_default();

        // Todoist returns plain text or JSON errors; try JSON first, fall back to body text.
        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.error_message)
            .unwrap_or_else(|| {
                if body.is_empty() {
                    format!("HTTP {}", status.as_u16())
                } else {
                    body.clone()
                }
            });

        match status.as_u16() {
            401 => Err(TodoistError::Unauthorized),
            403 => Err(TodoistError::Forbidden),
            404 => Err(TodoistError::NotFound { resource: detail }),
            429 => Err(TodoistError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(TodoistError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    #[instrument(skip(self, query), fields(url))]
    async fn get(
        &self,
        path: &str,
        query: Option<&[(&str, &str)]>,
    ) -> TodoistResult<serde_json::Value> {
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
    async fn post(&self, path: &str, body: &serde_json::Value) -> TodoistResult<serde_json::Value> {
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
    async fn post_no_body(&self, path: &str) -> TodoistResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "POST (no body) request");
        let req = self
            .add_auth(self.client.post(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self), fields(url))]
    async fn delete(&self, path: &str) -> TodoistResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "DELETE request");
        let req = self
            .add_auth(self.client.delete(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- Projects --

    /// List all projects for the authenticated user.
    pub async fn list_projects(&self) -> TodoistResult<serde_json::Value> {
        self.get("/projects", None).await
    }

    // -- Tasks --

    /// List tasks, optionally filtered by project.
    pub async fn list_tasks(&self, project_id: Option<&str>) -> TodoistResult<serde_json::Value> {
        if let Some(pid) = project_id {
            self.get("/tasks", Some(&[("project_id", pid)])).await
        } else {
            self.get("/tasks", None).await
        }
    }

    /// Create a new task.
    pub async fn create_task(&self, body: &serde_json::Value) -> TodoistResult<serde_json::Value> {
        self.post("/tasks", body).await
    }

    /// Mark a task as complete (POST `/tasks/{task_id}/close`).
    pub async fn complete_task(&self, task_id: &str) -> TodoistResult<serde_json::Value> {
        let safe_id = sanitize_path_segment(task_id)?;
        self.post_no_body(&format!("/tasks/{safe_id}/close")).await
    }

    /// Delete a task.
    pub async fn delete_task(&self, task_id: &str) -> TodoistResult<serde_json::Value> {
        let safe_id = sanitize_path_segment(task_id)?;
        self.delete(&format!("/tasks/{safe_id}")).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_token() {
        let auth = TodoistAuth::BearerToken("secret-api-token".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("secret-api-token"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let token = TodoistAuth::BearerToken("tok".into());
        assert!(!token.is_secretless());
        let cred = TodoistAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label() {
        let token = TodoistAuth::BearerToken("tok".into());
        assert_eq!(token.redacted_label(), "bearer_token:redacted");
    }

    #[test]
    fn auth_credential_label() {
        let cred = TodoistAuth::CredentialId(CredentialId::new());
        let label = cred.redacted_label();
        assert!(label.starts_with("credential_id:"));
    }

    #[test]
    fn client_new_default_url() {
        let client = TodoistClient::new(TodoistAuth::BearerToken("tok".into()), None).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn client_new_custom_url() {
        let client = TodoistClient::new(
            TodoistAuth::BearerToken("tok".into()),
            Some("https://test.example.com/api/"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://test.example.com/api");
    }

    #[test]
    fn client_debug_redacts() {
        let client = TodoistClient::new(TodoistAuth::BearerToken("secret".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("secret"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn client_trims_trailing_slashes() {
        let client = TodoistClient::new(
            TodoistAuth::BearerToken("tok".into()),
            Some("https://api.todoist.com/rest/v2///"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://api.todoist.com/rest/v2");
    }

    #[test]
    fn client_debug_shows_base_url() {
        let client = TodoistClient::new(TodoistAuth::BearerToken("tok".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains(DEFAULT_BASE_URL));
    }

    #[test]
    fn client_debug_contains_struct_name() {
        let client = TodoistClient::new(TodoistAuth::BearerToken("tok".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("TodoistClient"));
    }

    #[test]
    fn auth_debug_credential_id() {
        let id = CredentialId::new();
        let auth = TodoistAuth::CredentialId(id);
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn auth_clone_bearer() {
        let auth = TodoistAuth::BearerToken("tok".into());
        #[allow(clippy::redundant_clone)]
        let cloned = auth.clone();
        assert_eq!(cloned.redacted_label(), "bearer_token:redacted");
    }

    #[test]
    fn auth_clone_credential() {
        let auth = TodoistAuth::CredentialId(CredentialId::new());
        #[allow(clippy::redundant_clone)]
        let cloned = auth.clone();
        assert!(cloned.is_secretless());
    }

    #[test]
    fn default_base_url_value() {
        assert_eq!(DEFAULT_BASE_URL, "https://api.todoist.com/rest/v2");
    }

    #[test]
    fn auth_bearer_not_secretless() {
        let auth = TodoistAuth::BearerToken("token".into());
        assert!(!auth.is_secretless());
    }

    #[test]
    fn auth_credential_is_secretless() {
        let auth = TodoistAuth::CredentialId(CredentialId::new());
        assert!(auth.is_secretless());
    }

    #[test]
    fn auth_bearer_debug_no_token_leak() {
        let auth = TodoistAuth::BearerToken("my-super-long-api-token-12345".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("my-super-long-api-token-12345"));
        assert!(dbg.contains("BearerToken"));
    }

    #[test]
    fn client_custom_url_no_trailing_slash() {
        let client = TodoistClient::new(
            TodoistAuth::BearerToken("tok".into()),
            Some("https://custom.example.com"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://custom.example.com");
    }

    // ── Additional client coverage tests ──────────────────────────

    #[test]
    fn auth_redacted_label_does_not_contain_token() {
        let auth = TodoistAuth::BearerToken("my-api-token-12345".into());
        let label = auth.redacted_label();
        assert!(!label.contains("my-api-token-12345"));
        assert!(label.contains("redacted"));
    }

    #[test]
    fn auth_credential_label_contains_id() {
        let id = CredentialId::new();
        let id_str = id.to_string();
        let auth = TodoistAuth::CredentialId(id);
        let label = auth.redacted_label();
        assert!(label.contains(&id_str));
    }

    #[test]
    fn client_new_empty_string_url() {
        let client = TodoistClient::new(TodoistAuth::BearerToken("tok".into()), Some("")).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("TodoistClient"));
    }

    #[test]
    fn auth_debug_credential_id_contains_id_value() {
        let id = CredentialId::new();
        let id_str = id.to_string();
        let auth = TodoistAuth::CredentialId(id);
        let dbg = format!("{auth:?}");
        assert!(dbg.contains(&id_str));
    }

    #[test]
    fn client_credential_id_auth_debug() {
        let client =
            TodoistClient::new(TodoistAuth::CredentialId(CredentialId::new()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("CredentialId"));
        assert!(dbg.contains(DEFAULT_BASE_URL));
    }
}
