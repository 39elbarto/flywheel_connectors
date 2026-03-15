//! `MotherDuck` Cloud API client.

use std::fmt;
use std::time::Duration;

use fcp_core::CredentialId;
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig};
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{DuckDbError, DuckDbResult},
    types::ApiErrorResponse,
};

/// Default `MotherDuck` Cloud API base URL.
pub const DEFAULT_BASE_URL: &str = "https://app.motherduck.com/api/v0";

/// Authentication mode for the `MotherDuck` API.
#[derive(Clone)]
pub enum DuckDbAuth {
    /// Service token (passed as `Authorization: Bearer <token>`).
    ServiceToken(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl DuckDbAuth {
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::ServiceToken(_) => "service_token:redacted".to_string(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for DuckDbAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ServiceToken(_) => f.debug_tuple("ServiceToken").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// `MotherDuck` Cloud API client.
pub struct DuckDbClient {
    client: Client,
    auth: DuckDbAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl fmt::Debug for DuckDbClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DuckDbClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl DuckDbClient {
    /// Create a new `MotherDuck` client.
    pub fn new(auth: DuckDbAuth, base_url: Option<&str>) -> DuckDbResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-duckdb/0.1.0 (FCP connector)")
            .build()?;

        Ok(Self {
            client,
            auth,
            base_url: base_url
                .unwrap_or(DEFAULT_BASE_URL)
                .trim_end_matches('/')
                .to_string(),
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default()
                    .with_request_timeout(Duration::from_secs(30)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 2,
                ..HttpRetryConfig::default()
            },
        })
    }

    /// Gracefully shut down the connector runtime.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            DuckDbAuth::ServiceToken(token) => {
                req.header("Authorization", format!("Bearer {token}"))
            }
            DuckDbAuth::CredentialId(id) => req.header("X-FCP-Credential-Id", id.to_string()),
        }
    }

    async fn handle_response(&self, resp: Response) -> DuckDbResult<serde_json::Value> {
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
    ) -> DuckDbResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = resp.text().await.unwrap_or_default();

        // MotherDuck returns {"error": "...", "message": "..."} on errors.
        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.message.or(e.error))
            .unwrap_or_else(|| {
                if body.is_empty() {
                    format!("HTTP {}", status.as_u16())
                } else {
                    body.clone()
                }
            });

        match status.as_u16() {
            401 => Err(DuckDbError::Unauthorized),
            403 => Err(DuckDbError::Forbidden),
            404 => Err(DuckDbError::NotFound { resource: detail }),
            429 => Err(DuckDbError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(DuckDbError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    #[instrument(skip(self), fields(url))]
    async fn get(&self, path: &str) -> DuckDbResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "GET request");
        let req = self
            .add_auth(self.client.get(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn post(&self, path: &str, body: &serde_json::Value) -> DuckDbResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "POST request");
        let req = self
            .add_auth(self.client.post(&url))
            .header("Accept", "application/json")
            .json(body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- SQL --

    /// Execute a SQL query via the `MotherDuck` SQL endpoint.
    pub async fn execute_query(&self, body: &serde_json::Value) -> DuckDbResult<serde_json::Value> {
        self.post("/sql", body).await
    }

    // -- Databases --

    /// List all databases in the `MotherDuck` account.
    pub async fn list_databases(&self) -> DuckDbResult<serde_json::Value> {
        self.get("/databases").await
    }

    /// Get details of a specific database.
    pub async fn get_database(&self, db_name: &str) -> DuckDbResult<serde_json::Value> {
        self.get(&format!("/databases/{db_name}")).await
    }

    // -- Tables --

    /// List tables in a `MotherDuck` database.
    pub async fn list_tables(&self, db_name: &str) -> DuckDbResult<serde_json::Value> {
        self.get(&format!("/databases/{db_name}/tables")).await
    }

    /// Get details of a specific table.
    pub async fn get_table(
        &self,
        db_name: &str,
        table_name: &str,
    ) -> DuckDbResult<serde_json::Value> {
        self.get(&format!("/databases/{db_name}/tables/{table_name}"))
            .await
    }

    // -- Schemas --

    /// List schemas in a `MotherDuck` database.
    pub async fn list_schemas(&self, db_name: &str) -> DuckDbResult<serde_json::Value> {
        self.get(&format!("/databases/{db_name}/schemas")).await
    }

    // -- Queries --

    /// Get the status of a previously submitted query.
    pub async fn get_query_status(&self, query_id: &str) -> DuckDbResult<serde_json::Value> {
        self.get(&format!("/queries/{query_id}")).await
    }

    // -- Shares --

    /// List all shared databases.
    pub async fn list_shares(&self) -> DuckDbResult<serde_json::Value> {
        self.get("/shares").await
    }

    /// Create a new database share.
    pub async fn create_share(&self, body: &serde_json::Value) -> DuckDbResult<serde_json::Value> {
        self.post("/shares", body).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_token() {
        let auth = DuckDbAuth::ServiceToken("my-secret-service-token".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("my-secret-service-token"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let token = DuckDbAuth::ServiceToken("tok".into());
        assert!(!token.is_secretless());
        let cred = DuckDbAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label() {
        let token = DuckDbAuth::ServiceToken("tok".into());
        assert_eq!(token.redacted_label(), "service_token:redacted");
    }

    #[test]
    fn auth_credential_label() {
        let cred = DuckDbAuth::CredentialId(CredentialId::new());
        let label = cred.redacted_label();
        assert!(label.starts_with("credential_id:"));
    }

    #[test]
    fn client_new_default_url() {
        let client = DuckDbClient::new(DuckDbAuth::ServiceToken("tok".into()), None).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn client_new_custom_url() {
        let client = DuckDbClient::new(
            DuckDbAuth::ServiceToken("tok".into()),
            Some("https://test.example.com/api/"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://test.example.com/api");
    }

    #[test]
    fn client_debug_redacts() {
        let client = DuckDbClient::new(DuckDbAuth::ServiceToken("secret".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("secret"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn default_base_url_is_motherduck() {
        assert!(DEFAULT_BASE_URL.contains("motherduck.com"));
        assert!(DEFAULT_BASE_URL.starts_with("https://"));
    }

    #[test]
    fn auth_clone() {
        let auth = DuckDbAuth::ServiceToken("tok".into());
        #[allow(clippy::redundant_clone)]
        let cloned = auth.clone();
        assert_eq!(cloned.redacted_label(), "service_token:redacted");
    }

    #[test]
    fn client_strips_trailing_slash() {
        let client = DuckDbClient::new(
            DuckDbAuth::ServiceToken("tok".into()),
            Some("https://example.com/api///"),
        )
        .unwrap();
        assert!(!client.base_url.ends_with('/'));
    }

    #[test]
    fn auth_debug_credential_id_format() {
        let cred = DuckDbAuth::CredentialId(CredentialId::new());
        let dbg = format!("{cred:?}");
        assert!(dbg.contains("CredentialId"));
        assert!(!dbg.contains("redacted"));
    }

    #[test]
    fn client_debug_contains_base_url() {
        let client = DuckDbClient::new(
            DuckDbAuth::ServiceToken("tok".into()),
            Some("https://custom.example.com/v0"),
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("custom.example.com"));
    }

    #[test]
    fn client_new_with_credential_id() {
        let client =
            DuckDbClient::new(DuckDbAuth::CredentialId(CredentialId::new()), None).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn client_debug_credential_id() {
        let client =
            DuckDbClient::new(DuckDbAuth::CredentialId(CredentialId::new()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("CredentialId"));
        assert!(dbg.contains("DuckDbClient"));
    }

    #[test]
    fn auth_service_token_is_not_secretless() {
        let auth = DuckDbAuth::ServiceToken("tok".into());
        assert!(!auth.is_secretless());
    }

    #[test]
    fn auth_credential_id_is_secretless() {
        let auth = DuckDbAuth::CredentialId(CredentialId::new());
        assert!(auth.is_secretless());
    }

    #[test]
    fn client_custom_url_no_trailing_slash() {
        let client = DuckDbClient::new(
            DuckDbAuth::ServiceToken("tok".into()),
            Some("https://example.com/api"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://example.com/api");
    }

    #[test]
    fn auth_credential_id_secretless_verified() {
        let cred_id = CredentialId::new();
        let auth = DuckDbAuth::CredentialId(cred_id);
        assert!(auth.is_secretless());
        let label = auth.redacted_label();
        assert!(label.starts_with("credential_id:"));
    }

    #[test]
    fn default_base_url_is_https() {
        assert!(DEFAULT_BASE_URL.starts_with("https://"));
    }

    #[test]
    fn default_base_url_has_v0() {
        assert!(DEFAULT_BASE_URL.contains("/v0"));
    }
}
