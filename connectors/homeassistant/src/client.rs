//! `Home Assistant` API client.

use std::fmt;
use std::time::Duration;

use fcp_core::CredentialId;
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig};
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{HomeAssistantError, HomeAssistantResult},
    types::ApiErrorResponse,
};

/// Default `Home Assistant` API base URL.
pub const DEFAULT_BASE_URL: &str = "http://homeassistant.local:8123/api";

/// Authentication mode for the `Home Assistant` API.
#[derive(Clone)]
pub enum HomeAssistantAuth {
    /// Long-lived access token (Bearer).
    BearerToken(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl HomeAssistantAuth {
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::BearerToken(_) => "bearer_token:redacted".to_string(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    #[must_use]
    pub const fn has_token(&self) -> bool {
        matches!(self, Self::BearerToken(_))
    }

    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for HomeAssistantAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BearerToken(_) => f.debug_tuple("BearerToken").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// `Home Assistant` API client.
pub struct HomeAssistantClient {
    client: Client,
    auth: HomeAssistantAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl fmt::Debug for HomeAssistantClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HomeAssistantClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl HomeAssistantClient {
    /// Create a new `Home Assistant` client.
    pub fn new(auth: HomeAssistantAuth, base_url: Option<&str>) -> HomeAssistantResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-homeassistant/0.1.0 (FCP connector)")
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
            HomeAssistantAuth::BearerToken(token) => req.bearer_auth(token),
            HomeAssistantAuth::CredentialId(id) => {
                req.header("X-FCP-Credential-Id", id.to_string())
            }
        }
    }

    async fn handle_response(&self, resp: Response) -> HomeAssistantResult<serde_json::Value> {
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
    ) -> HomeAssistantResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = resp.text().await.unwrap_or_default();
        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.message)
            .unwrap_or_else(|| body.clone());

        match status.as_u16() {
            401 => Err(HomeAssistantError::Unauthorized),
            404 => Err(HomeAssistantError::EntityNotFound { entity_id: detail }),
            429 => Err(HomeAssistantError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            503 => Err(HomeAssistantError::Unavailable),
            code => Err(HomeAssistantError::Api {
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
    ) -> HomeAssistantResult<serde_json::Value> {
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
    async fn post(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> HomeAssistantResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "POST request");
        let req = self
            .add_auth(self.client.post(&url))
            .header("Accept", "application/json")
            .json(body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    /// Check connectivity by hitting the root API endpoint.
    pub async fn health_check(&self) -> HomeAssistantResult<()> {
        self.get("", None).await.map(|_| ())
    }

    // -- States --

    /// List all entity states.
    pub async fn list_states(&self) -> HomeAssistantResult<serde_json::Value> {
        self.get("/states", None).await
    }

    /// Get a single entity state.
    pub async fn get_state(&self, entity_id: &str) -> HomeAssistantResult<serde_json::Value> {
        self.get(&format!("/states/{entity_id}"), None).await
    }

    /// Set an entity state.
    pub async fn set_state(
        &self,
        entity_id: &str,
        body: &serde_json::Value,
    ) -> HomeAssistantResult<serde_json::Value> {
        self.post(&format!("/states/{entity_id}"), body).await
    }

    // -- Services --

    /// Call a service.
    pub async fn call_service(
        &self,
        domain: &str,
        service: &str,
        body: &serde_json::Value,
    ) -> HomeAssistantResult<serde_json::Value> {
        self.post(&format!("/services/{domain}/{service}"), body)
            .await
    }

    /// List all services.
    pub async fn list_services(&self) -> HomeAssistantResult<serde_json::Value> {
        self.get("/services", None).await
    }

    // -- History --

    /// Get state history for a period.
    pub async fn get_history(
        &self,
        timestamp: &str,
        filter_entity_id: Option<&str>,
        end_time: Option<&str>,
        minimal_response: Option<bool>,
        significant_changes_only: Option<bool>,
    ) -> HomeAssistantResult<serde_json::Value> {
        let mut q = Vec::new();
        if let Some(e) = filter_entity_id {
            q.push(("filter_entity_id", e.to_string()));
        }
        if let Some(e) = end_time {
            q.push(("end_time", e.to_string()));
        }
        if minimal_response.unwrap_or(false) {
            q.push(("minimal_response", String::new()));
        }
        if significant_changes_only.unwrap_or(false) {
            q.push(("significant_changes_only", String::new()));
        }
        self.get(
            &format!("/history/period/{timestamp}"),
            if q.is_empty() { None } else { Some(&q) },
        )
        .await
    }

    // -- Template API for areas/devices --

    /// Get all states (used to filter by domain prefix for automations, scenes, areas, devices).
    pub async fn get_states_by_domain(
        &self,
        domain_prefix: &str,
    ) -> HomeAssistantResult<Vec<serde_json::Value>> {
        let states = self.list_states().await?;
        let filtered = match states.as_array() {
            Some(arr) => arr
                .iter()
                .filter(|s| {
                    s.get("entity_id")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|id| id.starts_with(domain_prefix))
                })
                .cloned()
                .collect(),
            None => Vec::new(),
        };
        Ok(filtered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_token() {
        let auth = HomeAssistantAuth::BearerToken("secret-token".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("secret-token"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let token = HomeAssistantAuth::BearerToken("tok".into());
        assert!(!token.is_secretless());
        let cred = HomeAssistantAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label() {
        let token = HomeAssistantAuth::BearerToken("tok".into());
        assert_eq!(token.redacted_label(), "bearer_token:redacted");
    }

    #[test]
    fn auth_redacted_label_credential() {
        let cred = HomeAssistantAuth::CredentialId(CredentialId::new());
        assert!(cred.redacted_label().starts_with("credential_id:"));
    }

    #[test]
    fn default_base_url_has_api_prefix() {
        assert!(DEFAULT_BASE_URL.contains("/api"));
    }

    #[test]
    fn client_trims_trailing_slash() {
        let client = HomeAssistantClient::new(
            HomeAssistantAuth::BearerToken("tok".into()),
            Some("http://localhost:8123/api/"),
        )
        .unwrap();
        assert!(!client.base_url.ends_with('/'));
    }

    #[test]
    fn client_uses_default_url() {
        let client =
            HomeAssistantClient::new(HomeAssistantAuth::BearerToken("tok".into()), None).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn client_debug_format() {
        let client =
            HomeAssistantClient::new(HomeAssistantAuth::BearerToken("secret".into()), None)
                .unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("secret"));
        assert!(dbg.contains("HomeAssistantClient"));
    }

    #[test]
    fn auth_clone_bearer() {
        let auth = HomeAssistantAuth::BearerToken("tok123".into());
        let cloned = auth.clone();
        drop(auth);
        assert_eq!(cloned.redacted_label(), "bearer_token:redacted");
    }

    #[test]
    fn auth_clone_credential() {
        let auth = HomeAssistantAuth::CredentialId(CredentialId::new());
        let cloned = auth.clone();
        drop(auth);
        assert!(cloned.is_secretless());
    }

    #[test]
    fn client_debug_contains_base_url() {
        let client =
            HomeAssistantClient::new(HomeAssistantAuth::BearerToken("tok".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("base_url"));
    }

    #[test]
    fn client_new_with_credential_id() {
        let cred = CredentialId::new();
        let client = HomeAssistantClient::new(HomeAssistantAuth::CredentialId(cred), None).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn default_base_url_is_http() {
        assert!(DEFAULT_BASE_URL.starts_with("http://"));
    }

    #[test]
    fn default_base_url_contains_8123() {
        assert!(DEFAULT_BASE_URL.contains("8123"));
    }

    #[test]
    fn auth_bearer_is_not_secretless() {
        let auth = HomeAssistantAuth::BearerToken("any".into());
        assert!(!auth.is_secretless());
    }

    #[test]
    fn auth_credential_is_secretless() {
        let auth = HomeAssistantAuth::CredentialId(CredentialId::new());
        assert!(auth.is_secretless());
    }

    #[test]
    fn auth_debug_bearer_shows_tuple_name() {
        let auth = HomeAssistantAuth::BearerToken("secret".into());
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("BearerToken"));
    }

    #[test]
    fn auth_debug_credential_shows_id() {
        let cred = HomeAssistantAuth::CredentialId(CredentialId::new());
        let dbg = format!("{cred:?}");
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn client_strips_multiple_trailing_slashes() {
        let client = HomeAssistantClient::new(
            HomeAssistantAuth::BearerToken("k".into()),
            Some("http://localhost:8123/api////"),
        )
        .unwrap();
        assert!(!client.base_url.ends_with('/'));
    }

    #[test]
    fn client_custom_url_preserved() {
        let client = HomeAssistantClient::new(
            HomeAssistantAuth::BearerToken("tok".into()),
            Some("https://ha.example.com:443/api"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://ha.example.com:443/api");
    }
}
