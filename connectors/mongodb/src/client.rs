//! `MongoDB` Atlas Data API client.

use std::fmt;
use std::time::Duration;

use fcp_core::CredentialId;
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig};
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{MongoDbError, MongoDbResult},
    types::ApiErrorResponse,
};

/// Default `MongoDB` Atlas Data API base URL.
///
/// Users must configure this to their actual Atlas App Services endpoint,
/// e.g., `https://data.mongodb-api.com/app/data-xxxxx/endpoint/data/v1`.
pub const DEFAULT_BASE_URL: &str = "https://data.mongodb-api.com/app/data-xxxxx/endpoint/data/v1";

/// Authentication mode for the `MongoDB` Atlas Data API.
#[derive(Clone)]
pub enum MongoDbAuth {
    /// API key (passed as `apiKey: <key>` header).
    ApiKey(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl MongoDbAuth {
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

impl fmt::Debug for MongoDbAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApiKey(_) => f.debug_tuple("ApiKey").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// `MongoDB` Atlas Data API client.
///
/// All requests to the Data API are POST requests.
pub struct MongoDbClient {
    client: Client,
    auth: MongoDbAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl fmt::Debug for MongoDbClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MongoDbClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl MongoDbClient {
    /// Create a new `MongoDB` Atlas Data API client.
    pub fn new(auth: MongoDbAuth, base_url: Option<&str>) -> MongoDbResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-mongodb/0.1.0 (FCP connector)")
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

    /// Shut down the client runtime.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            MongoDbAuth::ApiKey(key) => req.header("apiKey", key),
            MongoDbAuth::CredentialId(id) => req.header("X-FCP-Credential-Id", id.to_string()),
        }
    }

    async fn handle_response(&self, resp: Response) -> MongoDbResult<serde_json::Value> {
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
    ) -> MongoDbResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = resp.text().await.unwrap_or_default();

        // Atlas Data API returns {"error": "message", "error_code": "CODE", "link": "URL"}.
        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.error)
            .unwrap_or_else(|| {
                if body.is_empty() {
                    format!("HTTP {}", status.as_u16())
                } else {
                    body.clone()
                }
            });

        match status.as_u16() {
            401 => Err(MongoDbError::Unauthorized),
            403 => Err(MongoDbError::Forbidden),
            404 => Err(MongoDbError::NotFound { resource: detail }),
            429 => Err(MongoDbError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(MongoDbError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    /// POST a request to a Data API action endpoint.
    #[instrument(skip(self, body), fields(url))]
    async fn post_action(
        &self,
        action: &str,
        body: &serde_json::Value,
    ) -> MongoDbResult<serde_json::Value> {
        let url = format!("{}/action/{action}", self.base_url);
        debug!(url = %url, "POST request");
        let req = self
            .add_auth(self.client.post(&url))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- Data API Actions --

    /// Find a single document.
    pub async fn find_one(&self, body: &serde_json::Value) -> MongoDbResult<serde_json::Value> {
        self.post_action("findOne", body).await
    }

    /// Find multiple documents.
    pub async fn find(&self, body: &serde_json::Value) -> MongoDbResult<serde_json::Value> {
        self.post_action("find", body).await
    }

    /// Insert a single document.
    pub async fn insert_one(&self, body: &serde_json::Value) -> MongoDbResult<serde_json::Value> {
        self.post_action("insertOne", body).await
    }

    /// Insert multiple documents.
    pub async fn insert_many(&self, body: &serde_json::Value) -> MongoDbResult<serde_json::Value> {
        self.post_action("insertMany", body).await
    }

    /// Update a single document.
    pub async fn update_one(&self, body: &serde_json::Value) -> MongoDbResult<serde_json::Value> {
        self.post_action("updateOne", body).await
    }

    /// Update multiple documents.
    pub async fn update_many(&self, body: &serde_json::Value) -> MongoDbResult<serde_json::Value> {
        self.post_action("updateMany", body).await
    }

    /// Delete a single document.
    pub async fn delete_one(&self, body: &serde_json::Value) -> MongoDbResult<serde_json::Value> {
        self.post_action("deleteOne", body).await
    }

    /// Delete multiple documents.
    pub async fn delete_many(&self, body: &serde_json::Value) -> MongoDbResult<serde_json::Value> {
        self.post_action("deleteMany", body).await
    }

    /// Run an aggregation pipeline.
    pub async fn aggregate(&self, body: &serde_json::Value) -> MongoDbResult<serde_json::Value> {
        self.post_action("aggregate", body).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_key() {
        let auth = MongoDbAuth::ApiKey("secret-api-key-12345".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("secret-api-key-12345"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let key = MongoDbAuth::ApiKey("key".into());
        assert!(!key.is_secretless());
        let cred = MongoDbAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label() {
        let key = MongoDbAuth::ApiKey("key".into());
        assert_eq!(key.redacted_label(), "api_key:redacted");
    }

    #[test]
    fn auth_credential_label() {
        let cred = MongoDbAuth::CredentialId(CredentialId::new());
        let label = cred.redacted_label();
        assert!(label.starts_with("credential_id:"));
    }

    #[test]
    fn client_new_default_url() {
        let client = MongoDbClient::new(MongoDbAuth::ApiKey("key".into()), None).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn client_new_custom_url() {
        let client = MongoDbClient::new(
            MongoDbAuth::ApiKey("key".into()),
            Some("https://data.mongodb-api.com/app/my-app/endpoint/data/v1/"),
        )
        .unwrap();
        assert_eq!(
            client.base_url,
            "https://data.mongodb-api.com/app/my-app/endpoint/data/v1"
        );
    }

    #[test]
    fn client_debug_redacts() {
        let client = MongoDbClient::new(MongoDbAuth::ApiKey("supersecret".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("supersecret"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn client_strips_trailing_slash() {
        let client = MongoDbClient::new(
            MongoDbAuth::ApiKey("k".into()),
            Some("https://example.com/data/v1///"),
        )
        .unwrap();
        assert!(!client.base_url.ends_with('/'));
    }

    #[test]
    fn auth_debug_credential_shows_id() {
        let cred = MongoDbAuth::CredentialId(CredentialId::new());
        let dbg = format!("{cred:?}");
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn auth_clone() {
        let auth = MongoDbAuth::ApiKey("key123".into());
        let cloned = auth.clone();
        drop(auth);
        assert_eq!(cloned.redacted_label(), "api_key:redacted");
    }

    #[test]
    fn auth_credential_clone() {
        let auth = MongoDbAuth::CredentialId(CredentialId::new());
        let cloned = auth.clone();
        drop(auth);
        assert!(cloned.is_secretless());
    }

    #[test]
    fn client_debug_contains_base_url() {
        let client = MongoDbClient::new(MongoDbAuth::ApiKey("k".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("MongoDbClient"));
        assert!(dbg.contains("base_url"));
    }

    #[test]
    fn client_custom_url_no_trailing_slash() {
        let client = MongoDbClient::new(
            MongoDbAuth::ApiKey("k".into()),
            Some("https://custom.example.com/data/v1"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://custom.example.com/data/v1");
    }

    #[test]
    fn client_new_with_credential_id() {
        let cred = CredentialId::new();
        let client = MongoDbClient::new(MongoDbAuth::CredentialId(cred), None).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn default_base_url_contains_mongodb() {
        assert!(DEFAULT_BASE_URL.contains("mongodb"));
    }

    #[test]
    fn default_base_url_is_https() {
        assert!(DEFAULT_BASE_URL.starts_with("https://"));
    }

    #[test]
    fn auth_api_key_is_not_secretless() {
        let auth = MongoDbAuth::ApiKey("any-key".into());
        assert!(!auth.is_secretless());
    }

    #[test]
    fn auth_credential_id_is_secretless() {
        let auth = MongoDbAuth::CredentialId(CredentialId::new());
        assert!(auth.is_secretless());
    }

    #[test]
    fn auth_debug_api_key_shows_tuple_name() {
        let auth = MongoDbAuth::ApiKey("secret".into());
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("ApiKey"));
    }

    #[test]
    fn client_strips_multiple_trailing_slashes() {
        let client = MongoDbClient::new(
            MongoDbAuth::ApiKey("k".into()),
            Some("https://example.com/v1////"),
        )
        .unwrap();
        // trim_end_matches removes all trailing '/'
        assert!(!client.base_url.ends_with('/'));
    }
}
