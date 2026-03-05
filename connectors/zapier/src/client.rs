//! Zapier API client.

use std::fmt;
use std::time::Duration;

use fcp_core::CredentialId;
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{ZapierError, ZapierResult},
    types::ApiErrorResponse,
};

/// Default Zapier REST API base URL.
pub const DEFAULT_BASE_URL: &str = "https://api.zapier.com/v1";

/// Authentication mode for the Zapier API.
#[derive(Clone)]
pub enum ZapierAuth {
    /// Bearer token (`Authorization: Bearer <api_key>`).
    BearerToken(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl ZapierAuth {
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

impl fmt::Debug for ZapierAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BearerToken(_) => f.debug_tuple("BearerToken").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// Zapier API client.
pub struct ZapierClient {
    client: Client,
    auth: ZapierAuth,
    base_url: String,
}

impl fmt::Debug for ZapierClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ZapierClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl ZapierClient {
    /// Create a new Zapier client.
    pub fn new(auth: ZapierAuth, base_url: Option<&str>) -> ZapierResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .user_agent("fcp-zapier/0.1.0 (FCP connector)")
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
            ZapierAuth::BearerToken(token) => {
                req.header("Authorization", format!("Bearer {token}"))
            }
            ZapierAuth::CredentialId(id) => {
                req.header("X-FCP-Credential-Id", id.to_string())
            }
        }
    }

    async fn handle_response(&self, resp: Response) -> ZapierResult<serde_json::Value> {
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
    ) -> ZapierResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = resp.text().await.unwrap_or_default();

        // Zapier returns {"error": "message"} or {"detail": "message"} on errors.
        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.error.or(e.detail))
            .unwrap_or_else(|| {
                if body.is_empty() {
                    format!("HTTP {}", status.as_u16())
                } else {
                    body.clone()
                }
            });

        match status.as_u16() {
            401 => Err(ZapierError::Unauthorized),
            403 => Err(ZapierError::Forbidden),
            404 => Err(ZapierError::NotFound { resource: detail }),
            429 => Err(ZapierError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(ZapierError::Api { status_code: code, message: detail }),
        }
    }

    #[instrument(skip(self), fields(url))]
    async fn get(&self, path: &str) -> ZapierResult<serde_json::Value> {
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
    ) -> ZapierResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "POST request");
        let req = self
            .add_auth(self.client.post(&url))
            .header("Accept", "application/json")
            .json(body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- Zaps --

    /// List all zaps (NLA exposed actions) for the authenticated user.
    pub async fn list_zaps(&self) -> ZapierResult<serde_json::Value> {
        self.get("/exposed/").await
    }

    // -- NLA Actions --

    /// List available NLA actions for the authenticated user.
    pub async fn list_actions(&self) -> ZapierResult<serde_json::Value> {
        self.get("/exposed/").await
    }

    /// Execute a Zapier NLA action.
    pub async fn execute_action(
        &self,
        action_id: &str,
        params: &serde_json::Value,
    ) -> ZapierResult<serde_json::Value> {
        let mut body = if let Some(obj) = params.as_object() {
            let mut merged = serde_json::Map::new();
            for (k, v) in obj {
                merged.insert(k.clone(), v.clone());
            }
            serde_json::Value::Object(merged)
        } else {
            serde_json::json!({})
        };
        // Ensure instructions field exists
        if let Some(obj) = body.as_object_mut() {
            if !obj.contains_key("instructions") {
                obj.insert("instructions".into(), serde_json::Value::Null);
            }
        }
        self.post(&format!("/exposed/{action_id}/execute/"), &body).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_token() {
        let auth = ZapierAuth::BearerToken("secret-api-key".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("secret-api-key"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let token = ZapierAuth::BearerToken("tok".into());
        assert!(!token.is_secretless());
        let cred = ZapierAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label_bearer() {
        let token = ZapierAuth::BearerToken("tok".into());
        assert_eq!(token.redacted_label(), "bearer_token:redacted");
    }

    #[test]
    fn auth_credential_label() {
        let cred = ZapierAuth::CredentialId(CredentialId::new());
        let label = cred.redacted_label();
        assert!(label.starts_with("credential_id:"));
    }

    #[test]
    fn auth_debug_credential_id() {
        let cred = ZapierAuth::CredentialId(CredentialId::new());
        let dbg = format!("{cred:?}");
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn client_new_default_url() {
        let client =
            ZapierClient::new(ZapierAuth::BearerToken("tok".into()), None).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn client_new_custom_url() {
        let client = ZapierClient::new(
            ZapierAuth::BearerToken("tok".into()),
            Some("https://test.example.com/api/"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://test.example.com/api");
    }

    #[test]
    fn client_new_trims_trailing_slash() {
        let client = ZapierClient::new(
            ZapierAuth::BearerToken("tok".into()),
            Some("https://example.com/v1/"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://example.com/v1");
    }

    #[test]
    fn client_debug_redacts() {
        let client =
            ZapierClient::new(ZapierAuth::BearerToken("secret".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("secret"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn client_debug_shows_base_url() {
        let client =
            ZapierClient::new(ZapierAuth::BearerToken("tok".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("api.zapier.com"));
    }

    #[test]
    fn default_base_url_is_correct() {
        assert_eq!(DEFAULT_BASE_URL, "https://api.zapier.com/v1");
    }

    #[test]
    fn auth_bearer_clone() {
        let auth = ZapierAuth::BearerToken("tok".into());
        #[allow(clippy::redundant_clone)]
        let cloned = auth.clone();
        assert_eq!(cloned.redacted_label(), "bearer_token:redacted");
    }

    #[test]
    fn auth_credential_clone() {
        let auth = ZapierAuth::CredentialId(CredentialId::new());
        #[allow(clippy::redundant_clone)]
        let cloned = auth.clone();
        assert!(cloned.is_secretless());
    }
}
