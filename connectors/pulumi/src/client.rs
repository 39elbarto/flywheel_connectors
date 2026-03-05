//! `Pulumi` API client.

use std::fmt;
use std::time::Duration;

use fcp_core::CredentialId;
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{PulumiError, PulumiResult},
    types::ApiErrorResponse,
};

/// Default `Pulumi` API base URL.
pub const DEFAULT_BASE_URL: &str = "https://api.pulumi.com/api";

/// Authentication mode for the `Pulumi` API.
#[derive(Clone)]
pub enum PulumiAuth {
    /// Bearer token (access token).
    BearerToken(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl PulumiAuth {
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

impl fmt::Debug for PulumiAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BearerToken(_) => f.debug_tuple("BearerToken").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// `Pulumi` API client.
pub struct PulumiClient {
    client: Client,
    auth: PulumiAuth,
    base_url: String,
}

impl fmt::Debug for PulumiClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PulumiClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl PulumiClient {
    /// Create a new `Pulumi` client.
    pub fn new(auth: PulumiAuth, base_url: Option<&str>) -> PulumiResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-pulumi/0.1.0 (FCP connector)")
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
            PulumiAuth::BearerToken(token) => req.bearer_auth(token),
            PulumiAuth::CredentialId(id) => req.header("X-FCP-Credential-Id", id.to_string()),
        }
    }

    async fn handle_response(&self, resp: Response) -> PulumiResult<serde_json::Value> {
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

    async fn handle_error(&self, status: StatusCode, resp: Response) -> PulumiResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = resp.text().await.unwrap_or_default();
        let message = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.message)
            .unwrap_or_else(|| body.clone());

        match status.as_u16() {
            401 => Err(PulumiError::Unauthorized),
            403 => Err(PulumiError::Forbidden),
            404 => Err(PulumiError::NotFound { resource: message }),
            429 => Err(PulumiError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(PulumiError::Api { status_code: code, message }),
        }
    }

    #[instrument(skip(self), fields(url))]
    async fn get(&self, path: &str) -> PulumiResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "GET request");
        let req = self.add_auth(self.client.get(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn post(&self, path: &str, body: &serde_json::Value) -> PulumiResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "POST request");
        let req = self.add_auth(self.client.post(&url))
            .header("Accept", "application/json")
            .json(body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self), fields(url))]
    async fn delete(&self, path: &str) -> PulumiResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "DELETE request");
        let req = self.add_auth(self.client.delete(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- Stacks --

    /// List stacks, optionally filtered by organization and/or project.
    pub async fn list_stacks(
        &self,
        organization: Option<&str>,
        project: Option<&str>,
    ) -> PulumiResult<serde_json::Value> {
        let qs = build_query(&[
            organization.map(|o| ("organization", o.to_string())),
            project.map(|p| ("project", p.to_string())),
        ]);
        self.get(&format!("/stacks{qs}")).await
    }

    /// Get a stack by organization, project, and stack name.
    pub async fn get_stack(
        &self,
        organization: &str,
        project: &str,
        stack: &str,
    ) -> PulumiResult<serde_json::Value> {
        self.get(&format!("/stacks/{organization}/{project}/{stack}")).await
    }

    /// Create a new stack.
    pub async fn create_stack(
        &self,
        organization: &str,
        project: &str,
        stack: &str,
    ) -> PulumiResult<serde_json::Value> {
        let body = serde_json::json!({"stackName": stack});
        self.post(&format!("/stacks/{organization}/{project}"), &body).await
    }

    /// Delete a stack.
    pub async fn delete_stack(
        &self,
        organization: &str,
        project: &str,
        stack: &str,
    ) -> PulumiResult<serde_json::Value> {
        self.delete(&format!("/stacks/{organization}/{project}/{stack}")).await
    }

    /// Export stack state.
    pub async fn export_stack(
        &self,
        organization: &str,
        project: &str,
        stack: &str,
    ) -> PulumiResult<serde_json::Value> {
        self.get(&format!("/stacks/{organization}/{project}/{stack}/export")).await
    }

    // -- Deployments --

    /// List deployment updates for a stack.
    pub async fn list_deployments(
        &self,
        organization: &str,
        project: &str,
        stack: &str,
    ) -> PulumiResult<serde_json::Value> {
        self.get(&format!("/stacks/{organization}/{project}/{stack}/updates")).await
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
        let auth = PulumiAuth::BearerToken("secret-access-token".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("secret-access-token"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let token = PulumiAuth::BearerToken("tok".into());
        assert!(!token.is_secretless());
        let cred = PulumiAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label() {
        let token = PulumiAuth::BearerToken("tok".into());
        assert_eq!(token.redacted_label(), "bearer_token:redacted");
    }

    #[test]
    fn auth_credential_id_label() {
        let cred = PulumiAuth::CredentialId(CredentialId::new());
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
            build_query(&[Some(("organization", "myorg".into()))]),
            "?organization=myorg"
        );
    }

    #[test]
    fn build_query_two() {
        assert_eq!(
            build_query(&[
                Some(("organization", "myorg".into())),
                Some(("project", "myproject".into())),
            ]),
            "?organization=myorg&project=myproject"
        );
    }

    #[test]
    fn build_query_mixed() {
        assert_eq!(
            build_query(&[Some(("organization", "myorg".into())), None]),
            "?organization=myorg"
        );
    }

    #[test]
    fn default_base_url_value() {
        assert_eq!(DEFAULT_BASE_URL, "https://api.pulumi.com/api");
    }

    #[test]
    fn client_new_with_defaults() {
        let client = PulumiClient::new(
            PulumiAuth::BearerToken("tok".into()),
            None,
        )
        .unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn client_new_with_custom_url() {
        let client = PulumiClient::new(
            PulumiAuth::BearerToken("tok".into()),
            Some("https://custom.pulumi.com/api/"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://custom.pulumi.com/api");
    }

    #[test]
    fn client_debug_format() {
        let client = PulumiClient::new(
            PulumiAuth::BearerToken("secret".into()),
            None,
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("secret"));
        assert!(dbg.contains("redacted"));
        assert!(dbg.contains("PulumiClient"));
    }
}
