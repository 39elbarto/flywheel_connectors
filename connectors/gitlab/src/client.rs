//! `GitLab` API client.

use std::fmt;
use std::time::Duration;

use fcp_core::CredentialId;
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{GitLabError, GitLabResult},
    types::ApiErrorResponse,
};

/// Default `GitLab` API base URL.
pub const DEFAULT_BASE_URL: &str = "https://gitlab.com/api/v4";

/// Authentication mode for the `GitLab` API.
#[derive(Clone)]
pub enum GitLabAuth {
    /// Personal access token (PRIVATE-TOKEN header).
    PrivateToken(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl GitLabAuth {
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::PrivateToken(_) => "private_token:redacted".to_string(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for GitLabAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PrivateToken(_) => f.debug_tuple("PrivateToken").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// `GitLab` API client.
pub struct GitLabClient {
    client: Client,
    auth: GitLabAuth,
    base_url: String,
}

impl fmt::Debug for GitLabClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GitLabClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl GitLabClient {
    /// Create a new `GitLab` client.
    pub fn new(auth: GitLabAuth, base_url: Option<&str>) -> GitLabResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-gitlab/0.1.0")
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

    /// Create a new client with a custom reqwest client (for testing).
    pub fn with_client(client: Client, auth: GitLabAuth, base_url: &str) -> Self {
        Self {
            client,
            auth,
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            GitLabAuth::PrivateToken(token) => req.header("PRIVATE-TOKEN", token),
            GitLabAuth::CredentialId(id) => req.header("X-FCP-Credential-Id", id.to_string()),
        }
    }

    async fn handle_response(&self, resp: Response) -> GitLabResult<serde_json::Value> {
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

    async fn handle_error(&self, status: StatusCode, resp: Response) -> GitLabResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = resp.text().await.unwrap_or_default();
        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| {
                e.error.or_else(|| e.message.map(|m| m.to_string()))
            })
            .unwrap_or_else(|| body.clone());

        match status.as_u16() {
            401 => Err(GitLabError::Unauthorized),
            403 => Err(GitLabError::Forbidden),
            404 => Err(GitLabError::NotFound { resource: detail }),
            429 => Err(GitLabError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(GitLabError::Api { status_code: code, message: detail }),
        }
    }

    #[instrument(skip(self), fields(url))]
    async fn get(&self, path: &str) -> GitLabResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "GET request");
        let req = self.add_auth(self.client.get(&url));
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn post(&self, path: &str, body: &serde_json::Value) -> GitLabResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "POST request");
        let req = self.add_auth(self.client.post(&url).json(body));
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- Projects --

    /// List projects.
    pub async fn list_projects(&self, per_page: Option<i64>) -> GitLabResult<serde_json::Value> {
        let qs = per_page.map_or_else(String::new, |pp| format!("?per_page={pp}"));
        self.get(&format!("/projects{qs}")).await
    }

    // -- Issues --

    /// List issues in a project.
    pub async fn list_issues(&self, project_id: &str) -> GitLabResult<serde_json::Value> {
        self.get(&format!("/projects/{project_id}/issues")).await
    }

    /// Create an issue.
    pub async fn create_issue(
        &self,
        project_id: &str,
        body: &serde_json::Value,
    ) -> GitLabResult<serde_json::Value> {
        self.post(&format!("/projects/{project_id}/issues"), body).await
    }

    // -- Merge Requests --

    /// List merge requests.
    pub async fn list_merge_requests(&self, project_id: &str) -> GitLabResult<serde_json::Value> {
        self.get(&format!("/projects/{project_id}/merge_requests")).await
    }

    // -- Pipelines --

    /// List pipelines.
    pub async fn list_pipelines(&self, project_id: &str) -> GitLabResult<serde_json::Value> {
        self.get(&format!("/projects/{project_id}/pipelines")).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_token() {
        let auth = GitLabAuth::PrivateToken("glpat-secret".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("glpat-secret"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let token = GitLabAuth::PrivateToken("tok".into());
        assert!(!token.is_secretless());
        let cred = GitLabAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label() {
        let token = GitLabAuth::PrivateToken("tok".into());
        assert_eq!(token.redacted_label(), "private_token:redacted");
    }
}
