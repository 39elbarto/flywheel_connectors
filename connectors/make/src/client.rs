//! `Make` API client.

use fcp_prelude::log_redaction::redact_url;
use std::fmt;
use std::time::Duration;

use fcp_prelude::CredentialId;
use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{MakeError, MakeResult},
    types::ApiErrorResponse,
};

/// Default `Make` REST API base URL.
pub const DEFAULT_BASE_URL: &str = "https://us1.make.com/api/v2";

/// Authentication mode for the `Make` API.
#[derive(Clone)]
pub enum MakeAuth {
    /// API token (passed as `Authorization: Token {api_token}`).
    ApiToken(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl MakeAuth {
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

impl fmt::Debug for MakeAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApiToken(_) => f.debug_tuple("ApiToken").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// `Make` API client.
pub struct MakeClient {
    client: Client,
    auth: MakeAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl fmt::Debug for MakeClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MakeClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl MakeClient {
    /// Create a new `Make` client.
    pub fn new(auth: MakeAuth, base_url: Option<&str>) -> MakeResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-make/0.1.0 (FCP connector)")
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
                max_retries: 3,
                ..HttpRetryConfig::default()
            },
        })
    }

    /// Trigger graceful shutdown of request contexts.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            MakeAuth::ApiToken(token) => req.header("Authorization", format!("Token {token}")),
            MakeAuth::CredentialId(id) => req.header("X-FCP-Credential-Id", id.to_string()),
        }
    }

    async fn handle_response(&self, resp: Response) -> MakeResult<serde_json::Value> {
        let status = resp.status();
        if status.is_success() {
            let body = resp.text().await?;
            decode_success_body(status, &body)
        } else {
            self.handle_error(status, resp).await
        }
    }

    async fn handle_error(
        &self,
        status: StatusCode,
        resp: Response,
    ) -> MakeResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = resp.text().await.unwrap_or_default();

        // Make returns {"message": "..."} or {"detail": "..."} on errors.
        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.message.or(e.detail))
            .unwrap_or_else(|| {
                if body.is_empty() {
                    format!("HTTP {}", status.as_u16())
                } else {
                    body.clone()
                }
            });

        match status.as_u16() {
            401 => Err(MakeError::Unauthorized),
            403 => Err(MakeError::Forbidden),
            404 => Err(MakeError::NotFound { resource: detail }),
            429 => Err(MakeError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(MakeError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    #[instrument(skip(self), fields(url))]
    async fn get(&self, path: &str) -> MakeResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "GET request");
        let req = self
            .add_auth(self.client.get(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn post(&self, path: &str, body: &serde_json::Value) -> MakeResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "POST request");
        let req = self
            .add_auth(self.client.post(&url))
            .header("Accept", "application/json")
            .json(body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- Scenarios --

    /// List all scenarios in a team.
    pub async fn list_scenarios(&self) -> MakeResult<serde_json::Value> {
        self.get("/scenarios").await
    }

    /// Trigger a scenario run.
    pub async fn run_scenario(&self, scenario_id: &str) -> MakeResult<serde_json::Value> {
        let safe_id = sanitize_path_segment(scenario_id, "scenario_id")?;
        self.post(&format!("/scenarios/{safe_id}/run"), &serde_json::json!({}))
            .await
    }

    // -- Executions --

    /// List recent executions for a scenario.
    pub async fn list_executions(&self, scenario_id: &str) -> MakeResult<serde_json::Value> {
        let safe_id = sanitize_path_segment(scenario_id, "scenario_id")?;
        self.get(&format!("/scenarios/{safe_id}/executions")).await
    }
}

/// Reject empty, slash-containing, and traversal-like path segments before egress.
fn sanitize_path_segment<'a>(value: &'a str, field: &str) -> MakeResult<&'a str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(MakeError::InvalidInput(format!(
            "{field} must not be empty"
        )));
    }
    let lower = trimmed.to_ascii_lowercase();
    if trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains("..")
        || lower.contains("%2f")
        || lower.contains("%5c")
    {
        return Err(MakeError::InvalidInput(format!(
            "{field} contains path traversal characters"
        )));
    }
    Ok(trimmed)
}

fn decode_success_body(status: StatusCode, body: &str) -> MakeResult<serde_json::Value> {
    if status == StatusCode::NO_CONTENT {
        return Ok(serde_json::json!({}));
    }
    if body.trim().is_empty() {
        return Err(MakeError::Api {
            status_code: status.as_u16(),
            message: "empty response body".into(),
        });
    }
    Ok(serde_json::from_str(body)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_token() {
        let auth = MakeAuth::ApiToken("secret-api-token".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("secret-api-token"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let token = MakeAuth::ApiToken("tok".into());
        assert!(!token.is_secretless());
        let cred = MakeAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label() {
        let token = MakeAuth::ApiToken("tok".into());
        assert_eq!(token.redacted_label(), "api_token:redacted");
    }

    #[test]
    fn decode_success_body_rejects_empty_ok() {
        let err = decode_success_body(StatusCode::OK, "").unwrap_err();
        assert!(matches!(
            err,
            MakeError::Api {
                status_code: 200,
                message
            } if message == "empty response body"
        ));
    }

    #[test]
    fn decode_success_body_rejects_whitespace_ok() {
        let err = decode_success_body(StatusCode::OK, "  \n\t").unwrap_err();
        assert!(matches!(
            err,
            MakeError::Api {
                status_code: 200,
                message
            } if message == "empty response body"
        ));
    }

    #[test]
    fn decode_success_body_allows_empty_no_content() {
        assert_eq!(
            decode_success_body(StatusCode::NO_CONTENT, "").unwrap(),
            serde_json::json!({})
        );
    }

    #[test]
    fn auth_credential_label() {
        let cred = MakeAuth::CredentialId(CredentialId::new());
        let label = cred.redacted_label();
        assert!(label.starts_with("credential_id:"));
    }

    #[test]
    fn client_new_default_url() {
        let client = MakeClient::new(MakeAuth::ApiToken("tok".into()), None).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn client_new_custom_url() {
        let client = MakeClient::new(
            MakeAuth::ApiToken("tok".into()),
            Some("https://test.example.com/api/"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://test.example.com/api");
    }

    #[test]
    fn client_debug_redacts() {
        let client = MakeClient::new(MakeAuth::ApiToken("secret".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("secret"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn client_new_strips_trailing_slash() {
        let client =
            MakeClient::new(MakeAuth::ApiToken("tok".into()), Some("https://x.com/api/")).unwrap();
        assert_eq!(client.base_url, "https://x.com/api");
    }

    #[test]
    fn client_new_no_trailing_slash_unchanged() {
        let client =
            MakeClient::new(MakeAuth::ApiToken("tok".into()), Some("https://x.com/api")).unwrap();
        assert_eq!(client.base_url, "https://x.com/api");
    }

    #[test]
    fn auth_api_token_debug_hides_value() {
        let auth = MakeAuth::ApiToken("my-super-secret-key-12345".into());
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("ApiToken"));
        assert!(!dbg.contains("my-super-secret-key-12345"));
    }

    #[test]
    fn auth_credential_id_debug_shows_id() {
        let id = CredentialId::new();
        let id_str = id.to_string();
        let auth = MakeAuth::CredentialId(id);
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("CredentialId"));
        assert!(dbg.contains(&id_str));
    }

    #[test]
    fn auth_clone() {
        let auth = MakeAuth::ApiToken("tok".into());
        let cloned = auth.clone();
        assert_eq!(auth.redacted_label(), cloned.redacted_label());
    }

    #[test]
    fn client_debug_contains_base_url() {
        let client = MakeClient::new(
            MakeAuth::ApiToken("tok".into()),
            Some("https://eu1.make.com/api/v2"),
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("MakeClient"));
        assert!(dbg.contains("eu1.make.com"));
    }

    #[test]
    fn default_base_url_is_us1() {
        assert!(DEFAULT_BASE_URL.contains("us1.make.com"));
        assert!(DEFAULT_BASE_URL.contains("/api/v2"));
    }

    #[test]
    fn auth_api_token_is_not_secretless() {
        let auth = MakeAuth::ApiToken("key-123".into());
        assert!(!auth.is_secretless());
        assert_eq!(auth.redacted_label(), "api_token:redacted");
    }

    #[test]
    fn auth_credential_is_secretless() {
        let auth = MakeAuth::CredentialId(CredentialId::new());
        assert!(auth.is_secretless());
        assert!(auth.redacted_label().starts_with("credential_id:"));
    }

    #[test]
    fn client_new_empty_url_string() {
        let client = MakeClient::new(MakeAuth::ApiToken("tok".into()), Some("")).unwrap();
        assert_eq!(client.base_url, "");
    }

    #[test]
    fn client_new_multiple_trailing_slashes() {
        let client =
            MakeClient::new(MakeAuth::ApiToken("tok".into()), Some("https://x.com///")).unwrap();
        assert!(!client.base_url.ends_with('/'));
    }
}
