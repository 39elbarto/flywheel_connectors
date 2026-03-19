//! Asana API client.

use std::fmt;
use std::time::Duration;

use fcp_core::CredentialId;
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig};
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{AsanaError, AsanaResult},
    types::ApiErrorResponse,
};

/// Default Asana REST API base URL.
pub const DEFAULT_BASE_URL: &str = "https://app.asana.com/api/1.0";

/// Authentication mode for the Asana API.
#[derive(Clone)]
pub enum AsanaAuth {
    /// Personal access token (passed as `Authorization: Bearer <token>`).
    PersonalAccessToken(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl AsanaAuth {
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::PersonalAccessToken(_) => "personal_access_token:redacted".to_string(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for AsanaAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PersonalAccessToken(_) => f
                .debug_tuple("PersonalAccessToken")
                .field(&"<redacted>")
                .finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// Asana API client.
pub struct AsanaClient {
    client: Client,
    auth: AsanaAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl fmt::Debug for AsanaClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AsanaClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl AsanaClient {
    /// Create a new Asana client.
    pub fn new(auth: AsanaAuth, base_url: Option<&str>) -> AsanaResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-asana/0.1.0 (FCP connector)")
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

    /// Shut down the connector runtime.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            AsanaAuth::PersonalAccessToken(token) => {
                req.header("Authorization", format!("Bearer {token}"))
            }
            AsanaAuth::CredentialId(id) => req.header("X-FCP-Credential-Id", id.to_string()),
        }
    }

    async fn handle_response(&self, resp: Response) -> AsanaResult<serde_json::Value> {
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
    ) -> AsanaResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = resp.text().await.unwrap_or_default();

        // Asana returns {"errors": [{"message": "...", "help": "..."}]} on errors.
        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.errors)
            .and_then(|errors| errors.into_iter().next().and_then(|e| e.message))
            .unwrap_or_else(|| {
                if body.is_empty() {
                    format!("HTTP {}", status.as_u16())
                } else {
                    body.clone()
                }
            });

        match status.as_u16() {
            401 => Err(AsanaError::Unauthorized),
            403 => Err(AsanaError::Forbidden),
            404 => Err(AsanaError::NotFound { resource: detail }),
            429 => Err(AsanaError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(AsanaError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    #[instrument(skip(self), fields(url))]
    async fn get(&self, path: &str) -> AsanaResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "GET request");
        let req = self
            .add_auth(self.client.get(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn post(&self, path: &str, body: &serde_json::Value) -> AsanaResult<serde_json::Value> {
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
    async fn put(&self, path: &str, body: &serde_json::Value) -> AsanaResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "PUT request");
        let req = self
            .add_auth(self.client.put(&url))
            .header("Accept", "application/json")
            .json(body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self), fields(url))]
    async fn delete(&self, path: &str) -> AsanaResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "DELETE request");
        let req = self
            .add_auth(self.client.delete(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- Workspaces --

    /// List all workspaces.
    pub async fn list_workspaces(&self) -> AsanaResult<serde_json::Value> {
        self.get("/workspaces").await
    }

    // -- Projects --

    /// List all projects in a workspace.
    pub async fn list_projects(&self, workspace_gid: &str) -> AsanaResult<serde_json::Value> {
        self.get(&format!("/workspaces/{workspace_gid}/projects"))
            .await
    }

    /// Get a single project by GID.
    pub async fn get_project(&self, project_gid: &str) -> AsanaResult<serde_json::Value> {
        self.get(&format!("/projects/{project_gid}")).await
    }

    // -- Tasks --

    /// List tasks in a project.
    pub async fn list_tasks(&self, project_gid: &str) -> AsanaResult<serde_json::Value> {
        self.get(&format!("/projects/{project_gid}/tasks")).await
    }

    /// Get a single task by GID.
    pub async fn get_task(&self, task_gid: &str) -> AsanaResult<serde_json::Value> {
        self.get(&format!("/tasks/{task_gid}")).await
    }

    /// Create a new task.
    pub async fn create_task(&self, body: &serde_json::Value) -> AsanaResult<serde_json::Value> {
        self.post("/tasks", body).await
    }

    /// Update a task.
    pub async fn update_task(
        &self,
        task_gid: &str,
        body: &serde_json::Value,
    ) -> AsanaResult<serde_json::Value> {
        self.put(&format!("/tasks/{task_gid}"), body).await
    }

    /// Delete a task.
    pub async fn delete_task(&self, task_gid: &str) -> AsanaResult<serde_json::Value> {
        self.delete(&format!("/tasks/{task_gid}")).await
    }

    // -- Sections --

    /// List sections in a project.
    pub async fn list_sections(&self, project_gid: &str) -> AsanaResult<serde_json::Value> {
        self.get(&format!("/projects/{project_gid}/sections")).await
    }

    // -- Search --

    /// Search tasks in a workspace.
    pub async fn search_tasks(
        &self,
        workspace_gid: &str,
        query: &str,
    ) -> AsanaResult<serde_json::Value> {
        let encoded = urlencoding::encode(query);
        self.get(&format!(
            "/workspaces/{workspace_gid}/tasks/search?text={encoded}"
        ))
        .await
    }
}

/// Minimal URL encoding for search query parameters.
mod urlencoding {
    use std::fmt::Write;

    /// Percent-encode a string for use in URL query parameters.
    pub fn encode(input: &str) -> String {
        let mut result = String::with_capacity(input.len());
        for byte in input.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    result.push(byte as char);
                }
                b' ' => result.push_str("%20"),
                _ => {
                    result.push('%');
                    let _ = write!(result, "{byte:02X}");
                }
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_token() {
        let auth = AsanaAuth::PersonalAccessToken("secret-pat-token".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("secret-pat-token"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let token = AsanaAuth::PersonalAccessToken("tok".into());
        assert!(!token.is_secretless());
        let cred = AsanaAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label() {
        let token = AsanaAuth::PersonalAccessToken("tok".into());
        assert_eq!(token.redacted_label(), "personal_access_token:redacted");
    }

    #[test]
    fn auth_credential_label() {
        let cred = AsanaAuth::CredentialId(CredentialId::new());
        let label = cred.redacted_label();
        assert!(label.starts_with("credential_id:"));
    }

    #[test]
    fn client_new_default_url() {
        let client = AsanaClient::new(AsanaAuth::PersonalAccessToken("tok".into()), None).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn client_new_custom_url() {
        let client = AsanaClient::new(
            AsanaAuth::PersonalAccessToken("tok".into()),
            Some("https://test.example.com/api/"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://test.example.com/api");
    }

    #[test]
    fn client_debug_redacts() {
        let client =
            AsanaClient::new(AsanaAuth::PersonalAccessToken("secret".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("secret"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn url_encode_simple() {
        assert_eq!(urlencoding::encode("hello"), "hello");
    }

    #[test]
    fn url_encode_spaces() {
        assert_eq!(urlencoding::encode("hello world"), "hello%20world");
    }

    #[test]
    fn url_encode_special_chars() {
        assert_eq!(urlencoding::encode("a&b=c"), "a%26b%3Dc");
    }

    #[test]
    fn url_encode_preserves_unreserved() {
        assert_eq!(
            urlencoding::encode("test-value_1.0~beta"),
            "test-value_1.0~beta"
        );
    }

    // ── Additional client coverage ───────────────────────────────

    #[test]
    fn auth_debug_credential_id() {
        let cred = AsanaAuth::CredentialId(CredentialId::new());
        let dbg = format!("{cred:?}");
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn auth_clone() {
        let auth = AsanaAuth::PersonalAccessToken("secret".into());
        #[allow(clippy::redundant_clone)]
        let auth2 = auth.clone();
        assert_eq!(auth2.redacted_label(), "personal_access_token:redacted");
    }

    #[test]
    fn auth_credential_id_clone() {
        let id = CredentialId::new();
        let auth = AsanaAuth::CredentialId(id);
        #[allow(clippy::redundant_clone)]
        let auth2 = auth.clone();
        assert!(auth2.is_secretless());
    }

    #[test]
    fn client_debug_contains_base_url() {
        let client = AsanaClient::new(AsanaAuth::PersonalAccessToken("tok".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("AsanaClient"));
        assert!(dbg.contains(DEFAULT_BASE_URL));
    }

    #[test]
    fn client_custom_url_trimmed() {
        let client = AsanaClient::new(
            AsanaAuth::PersonalAccessToken("tok".into()),
            Some("https://api.example.com/api/1.0/"),
        )
        .unwrap();
        assert!(!client.base_url.ends_with('/'));
    }

    #[test]
    fn default_base_url_constant() {
        assert_eq!(DEFAULT_BASE_URL, "https://app.asana.com/api/1.0");
    }

    #[test]
    fn url_encode_empty_string() {
        assert_eq!(urlencoding::encode(""), "");
    }

    #[test]
    fn url_encode_all_special() {
        let result = urlencoding::encode("a&b=c+d#e%f");
        assert!(result.contains("%26")); // &
        assert!(result.contains("%3D")); // =
        assert!(result.contains("%2B")); // +
        assert!(result.contains("%23")); // #
        assert!(result.contains("%25")); // %
    }

    #[test]
    fn url_encode_unicode() {
        let result = urlencoding::encode("café");
        // The non-ASCII bytes get percent-encoded
        assert!(result.contains('%'));
        assert!(result.starts_with("caf"));
    }

    #[test]
    fn client_with_credential_id_auth() {
        let client = AsanaClient::new(AsanaAuth::CredentialId(CredentialId::new()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn url_encode_multiple_spaces() {
        let result = urlencoding::encode("a b c d");
        assert_eq!(result, "a%20b%20c%20d");
    }

    #[test]
    fn url_encode_numbers_and_letters() {
        assert_eq!(urlencoding::encode("ABC123xyz"), "ABC123xyz");
    }

    #[test]
    fn url_encode_tilde_preserved() {
        assert_eq!(urlencoding::encode("~user"), "~user");
    }

    #[test]
    fn url_encode_dot_preserved() {
        assert_eq!(urlencoding::encode("file.txt"), "file.txt");
    }

    #[test]
    fn url_encode_dash_preserved() {
        assert_eq!(urlencoding::encode("my-task"), "my-task");
    }

    #[test]
    fn url_encode_underscore_preserved() {
        assert_eq!(urlencoding::encode("my_task"), "my_task");
    }
}
