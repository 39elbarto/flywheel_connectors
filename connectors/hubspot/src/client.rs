//! `HubSpot` API client.

use std::fmt;
use std::time::Duration;

use fcp_core::CredentialId;
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{HubSpotError, HubSpotResult},
    types::ApiErrorResponse,
};

/// Default `HubSpot` API base URL.
pub const DEFAULT_BASE_URL: &str = "https://api.hubapi.com";

/// Authentication mode for the `HubSpot` API.
#[derive(Clone)]
pub enum HubSpotAuth {
    /// Bearer token (private app token or OAuth access token).
    BearerToken(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl HubSpotAuth {
    /// Render a redacted label suitable for logs/diagnostics.
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::BearerToken(_) => "bearer_token:redacted".to_string(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    /// Whether this auth mode requires egress proxy credential injection.
    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for HubSpotAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BearerToken(_) => f.debug_tuple("BearerToken").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// `HubSpot` API client.
pub struct HubSpotClient {
    client: Client,
    auth: HubSpotAuth,
    base_url: String,
}

impl fmt::Debug for HubSpotClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HubSpotClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl HubSpotClient {
    /// Create a new `HubSpot` client.
    pub fn new(auth: HubSpotAuth, base_url: Option<&str>) -> HubSpotResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-hubspot/0.1.0")
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
    pub fn with_client(client: Client, auth: HubSpotAuth, base_url: &str) -> Self {
        Self {
            client,
            auth,
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            HubSpotAuth::BearerToken(token) => req.bearer_auth(token),
            HubSpotAuth::CredentialId(id) => req.header("X-FCP-Credential-Id", id.to_string()),
        }
    }

    async fn handle_response(&self, resp: Response) -> HubSpotResult<serde_json::Value> {
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
    ) -> HubSpotResult<serde_json::Value> {
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
            401 => Err(HubSpotError::Unauthorized),
            403 => Err(HubSpotError::Forbidden),
            404 => Err(HubSpotError::NotFound { resource: detail }),
            429 => Err(HubSpotError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(10) * 1000,
            }),
            code => Err(HubSpotError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    #[instrument(skip(self), fields(url))]
    async fn get(&self, path: &str) -> HubSpotResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "GET request");

        let req = self.client.get(&url);
        let req = self.add_auth(req);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn post(&self, path: &str, body: &serde_json::Value) -> HubSpotResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "POST request");

        let req = self.client.post(&url).json(body);
        let req = self.add_auth(req);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn patch(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> HubSpotResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "PATCH request");

        let req = self.client.patch(&url).json(body);
        let req = self.add_auth(req);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self), fields(url))]
    async fn delete(&self, path: &str) -> HubSpotResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "DELETE request");

        let req = self.client.delete(&url);
        let req = self.add_auth(req);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- Contacts --

    /// List contacts.
    pub async fn list_contacts(
        &self,
        limit: Option<i64>,
        after: Option<&str>,
        properties: Option<&[String]>,
    ) -> HubSpotResult<serde_json::Value> {
        let mut params = Vec::new();
        if let Some(l) = limit {
            params.push(format!("limit={l}"));
        }
        if let Some(a) = after {
            params.push(format!("after={a}"));
        }
        if let Some(props) = properties {
            for p in props {
                params.push(format!("properties={p}"));
            }
        }
        let qs = if params.is_empty() {
            String::new()
        } else {
            format!("?{}", params.join("&"))
        };
        self.get(&format!("/crm/v3/objects/contacts{qs}")).await
    }

    /// Get a contact by ID.
    pub async fn get_contact(
        &self,
        contact_id: &str,
        properties: Option<&[String]>,
    ) -> HubSpotResult<serde_json::Value> {
        let mut params = Vec::new();
        if let Some(props) = properties {
            for p in props {
                params.push(format!("properties={p}"));
            }
        }
        let qs = if params.is_empty() {
            String::new()
        } else {
            format!("?{}", params.join("&"))
        };
        self.get(&format!("/crm/v3/objects/contacts/{contact_id}{qs}"))
            .await
    }

    /// Create a contact.
    pub async fn create_contact(
        &self,
        body: &serde_json::Value,
    ) -> HubSpotResult<serde_json::Value> {
        self.post("/crm/v3/objects/contacts", body).await
    }

    /// Update a contact.
    pub async fn update_contact(
        &self,
        contact_id: &str,
        body: &serde_json::Value,
    ) -> HubSpotResult<serde_json::Value> {
        self.patch(&format!("/crm/v3/objects/contacts/{contact_id}"), body)
            .await
    }

    /// Delete a contact.
    pub async fn delete_contact(&self, contact_id: &str) -> HubSpotResult<serde_json::Value> {
        self.delete(&format!("/crm/v3/objects/contacts/{contact_id}"))
            .await
    }

    // -- Companies --

    /// List companies.
    pub async fn list_companies(
        &self,
        limit: Option<i64>,
        after: Option<&str>,
        properties: Option<&[String]>,
    ) -> HubSpotResult<serde_json::Value> {
        let mut params = Vec::new();
        if let Some(l) = limit {
            params.push(format!("limit={l}"));
        }
        if let Some(a) = after {
            params.push(format!("after={a}"));
        }
        if let Some(props) = properties {
            for p in props {
                params.push(format!("properties={p}"));
            }
        }
        let qs = if params.is_empty() {
            String::new()
        } else {
            format!("?{}", params.join("&"))
        };
        self.get(&format!("/crm/v3/objects/companies{qs}")).await
    }

    // -- Deals --

    /// List deals.
    pub async fn list_deals(
        &self,
        limit: Option<i64>,
        after: Option<&str>,
        properties: Option<&[String]>,
    ) -> HubSpotResult<serde_json::Value> {
        let mut params = Vec::new();
        if let Some(l) = limit {
            params.push(format!("limit={l}"));
        }
        if let Some(a) = after {
            params.push(format!("after={a}"));
        }
        if let Some(props) = properties {
            for p in props {
                params.push(format!("properties={p}"));
            }
        }
        let qs = if params.is_empty() {
            String::new()
        } else {
            format!("?{}", params.join("&"))
        };
        self.get(&format!("/crm/v3/objects/deals{qs}")).await
    }

    /// Create a deal.
    pub async fn create_deal(&self, body: &serde_json::Value) -> HubSpotResult<serde_json::Value> {
        self.post("/crm/v3/objects/deals", body).await
    }

    // -- Pipelines --

    /// List pipelines for an object type.
    pub async fn list_pipelines(&self, object_type: &str) -> HubSpotResult<serde_json::Value> {
        self.get(&format!("/crm/v3/pipelines/{object_type}")).await
    }

    // -- Analytics --

    /// Get analytics report (custom endpoint).
    pub async fn analytics_report(
        &self,
        body: &serde_json::Value,
    ) -> HubSpotResult<serde_json::Value> {
        self.post("/analytics/v2/reports", body).await
    }

    // -- Events --

    /// List webhook events (timeline events).
    pub async fn list_events(
        &self,
        object_type: Option<&str>,
        after: Option<i64>,
    ) -> HubSpotResult<serde_json::Value> {
        let mut params = Vec::new();
        if let Some(ot) = object_type {
            params.push(format!("objectType={ot}"));
        }
        if let Some(a) = after {
            params.push(format!("occurredAfter={a}"));
        }
        let qs = if params.is_empty() {
            String::new()
        } else {
            format!("?{}", params.join("&"))
        };
        self.get(&format!("/events/v3/events{qs}")).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_token() {
        let auth = HubSpotAuth::BearerToken("pat-na1-secret".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("pat-na1-secret"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let bearer = HubSpotAuth::BearerToken("tok".into());
        assert!(!bearer.is_secretless());

        let cred = HubSpotAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label() {
        let bearer = HubSpotAuth::BearerToken("tok".into());
        assert_eq!(bearer.redacted_label(), "bearer_token:redacted");

        let cred = HubSpotAuth::CredentialId(CredentialId::new());
        assert!(cred.redacted_label().starts_with("credential_id:"));
    }

    #[test]
    fn client_new_default_url() {
        let client = HubSpotClient::new(HubSpotAuth::BearerToken("tok".into()), None).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn client_new_custom_url() {
        let client = HubSpotClient::new(
            HubSpotAuth::BearerToken("tok".into()),
            Some("https://custom.hubapi.test/v3/"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://custom.hubapi.test/v3");
    }

    #[test]
    fn client_trims_trailing_slashes() {
        let client = HubSpotClient::new(
            HubSpotAuth::BearerToken("tok".into()),
            Some("https://example.com///"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://example.com");
    }

    #[test]
    fn client_debug_redacts_bearer() {
        let client =
            HubSpotClient::new(HubSpotAuth::BearerToken("super-secret-pat".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("super-secret-pat"));
        assert!(dbg.contains("redacted"));
        assert!(dbg.contains("HubSpotClient"));
    }

    #[test]
    fn client_debug_shows_base_url() {
        let client = HubSpotClient::new(HubSpotAuth::BearerToken("tok".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains(DEFAULT_BASE_URL));
    }

    #[test]
    fn auth_debug_credential_id() {
        let id = CredentialId::new();
        let auth = HubSpotAuth::CredentialId(id);
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn auth_clone() {
        let auth = HubSpotAuth::BearerToken("tok".into());
        #[allow(clippy::redundant_clone)]
        let cloned = auth.clone();
        assert_eq!(cloned.redacted_label(), "bearer_token:redacted");
    }

    #[test]
    fn auth_clone_credential() {
        let auth = HubSpotAuth::CredentialId(CredentialId::new());
        #[allow(clippy::redundant_clone)]
        let cloned = auth.clone();
        assert!(cloned.is_secretless());
    }

    #[test]
    fn default_base_url_value() {
        assert_eq!(DEFAULT_BASE_URL, "https://api.hubapi.com");
    }

    #[test]
    fn with_client_trims_slash() {
        let client = reqwest::Client::new();
        let hs = HubSpotClient::with_client(
            client,
            HubSpotAuth::BearerToken("t".into()),
            "https://test.com/",
        );
        assert_eq!(hs.base_url, "https://test.com");
    }

    #[test]
    fn with_client_no_slash() {
        let client = reqwest::Client::new();
        let hs = HubSpotClient::with_client(
            client,
            HubSpotAuth::BearerToken("t".into()),
            "https://test.com",
        );
        assert_eq!(hs.base_url, "https://test.com");
    }

    // ── Additional client tests ───────────────────────────────────

    #[test]
    fn default_base_url_starts_with_https() {
        assert!(DEFAULT_BASE_URL.starts_with("https://"));
    }

    #[test]
    fn default_base_url_no_trailing_slash() {
        assert!(!DEFAULT_BASE_URL.ends_with('/'));
    }

    #[test]
    fn auth_bearer_with_long_token() {
        let long_token = "pat-na1-".to_string() + &"x".repeat(500);
        let auth = HubSpotAuth::BearerToken(long_token);
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains(&"x".repeat(100)));
    }

    #[test]
    fn client_new_empty_base_url() {
        let client = HubSpotClient::new(HubSpotAuth::BearerToken("tok".into()), Some("")).unwrap();
        assert_eq!(client.base_url, "");
    }
}
