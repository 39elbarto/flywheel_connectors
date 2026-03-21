//! `MySQL` REST API client.

use std::fmt;
use std::time::Duration;

use fcp_core::CredentialId;
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig};
use reqwest::{Client, Response, StatusCode};
use serde_json::json;
use tracing::{debug, instrument};

use crate::{
    error::{MysqlError, MysqlResult},
    types::ApiErrorResponse,
};

/// Validate a SQL identifier to prevent injection attacks.
///
/// Allows alphanumeric characters, underscores, and dots (for qualified names
/// like `schema.table`). Must start with a letter or underscore.
fn validate_sql_identifier<'a>(value: &'a str, field: &str) -> MysqlResult<&'a str> {
    if value.trim().is_empty() {
        return Err(MysqlError::InvalidInput(format!(
            "{field} must not be empty"
        )));
    }
    // Must start with a letter or underscore
    let first = value.chars().next().unwrap();
    if !first.is_ascii_alphabetic() && first != '_' {
        return Err(MysqlError::InvalidInput(format!(
            "{field} must start with a letter or underscore"
        )));
    }
    // Only allow alphanumeric, underscore, dot (for qualified names)
    for ch in value.chars() {
        if !ch.is_ascii_alphanumeric() && ch != '_' && ch != '.' {
            return Err(MysqlError::InvalidInput(format!(
                "{field} contains invalid character '{ch}'"
            )));
        }
    }
    // Reject consecutive dots or leading/trailing dots
    if value.starts_with('.') || value.ends_with('.') || value.contains("..") {
        return Err(MysqlError::InvalidInput(format!(
            "{field} has invalid dot placement"
        )));
    }
    Ok(value)
}

/// Default `MySQL` REST API base URL.
///
/// Users must configure this to their actual `MySQL` proxy endpoint.
pub const DEFAULT_BASE_URL: &str = "https://db.example.com";

/// Authentication mode for the `MySQL` REST API.
#[derive(Clone)]
pub enum MysqlAuth {
    /// API key (passed as Bearer token).
    ApiKey(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl MysqlAuth {
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::ApiKey(_) => "api_key:redacted".to_string(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    #[must_use]
    pub const fn mode_label(&self) -> &'static str {
        match self {
            Self::ApiKey(_) => "api_key",
            Self::CredentialId(_) => "credential_id",
        }
    }

    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }

    #[must_use]
    pub const fn permissions_guidance(&self) -> &'static str {
        match self {
            Self::ApiKey(_) => {
                "API-key mode still depends on the upstream REST proxy mapping that token to read, write, schema, and health endpoints for a dedicated staging database."
            }
            Self::CredentialId(_) => {
                "credential_id mode requires the host or egress proxy to inject a concrete upstream credential before live health checks can prove connectivity or permissions."
            }
        }
    }
}

impl fmt::Debug for MysqlAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApiKey(_) => f.debug_tuple("ApiKey").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// `MySQL` REST API client.
///
/// Sends SQL queries and schema requests via HTTP to a `MySQL` REST proxy endpoint.
pub struct MysqlClient {
    client: Client,
    auth: MysqlAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl fmt::Debug for MysqlClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MysqlClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

#[allow(clippy::missing_errors_doc)]
impl MysqlClient {
    /// Create a new `MySQL` REST API client.
    pub fn new(auth: MysqlAuth, base_url: Option<&str>) -> MysqlResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-mysql/0.1.0 (FCP connector)")
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

    /// Runtime reference for health reporting.
    #[must_use]
    pub const fn runtime(&self) -> &ConnectorRuntime {
        &self.runtime
    }

    /// Retry configuration reference.
    #[must_use]
    pub const fn retry_config(&self) -> &HttpRetryConfig {
        &self.retry_config
    }

    /// Base URL configured for the proxy.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            MysqlAuth::ApiKey(key) => req.bearer_auth(key),
            MysqlAuth::CredentialId(id) => req.header("X-FCP-Credential-Id", id.to_string()),
        }
    }

    /// Execute a SQL query (SELECT or read-only).
    #[instrument(skip(self), fields(base_url = %self.base_url))]
    pub async fn query(
        &self,
        sql: &str,
        params: &[serde_json::Value],
    ) -> MysqlResult<serde_json::Value> {
        debug!(
            sql_len = sql.len(),
            param_count = params.len(),
            "executing query"
        );

        let url = format!("{}/query", self.base_url);
        let body = json!({
            "sql": sql,
            "params": params,
        });

        let req = self.add_auth(self.client.post(&url)).json(&body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    /// Execute a SQL statement (INSERT, UPDATE, DELETE).
    #[instrument(skip(self), fields(base_url = %self.base_url))]
    pub async fn execute(
        &self,
        sql: &str,
        params: &[serde_json::Value],
    ) -> MysqlResult<serde_json::Value> {
        debug!(
            sql_len = sql.len(),
            param_count = params.len(),
            "executing statement"
        );

        let url = format!("{}/execute", self.base_url);
        let body = json!({
            "sql": sql,
            "params": params,
        });

        let req = self.add_auth(self.client.post(&url)).json(&body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    /// Execute EXPLAIN on a query.
    #[instrument(skip(self), fields(base_url = %self.base_url))]
    pub async fn explain(&self, sql: &str) -> MysqlResult<serde_json::Value> {
        debug!(sql_len = sql.len(), "explaining query");

        let url = format!("{}/explain", self.base_url);
        let body = json!({ "sql": sql });

        let req = self.add_auth(self.client.post(&url)).json(&body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    /// List tables in the current database.
    #[instrument(skip(self), fields(base_url = %self.base_url))]
    pub async fn list_tables(&self) -> MysqlResult<serde_json::Value> {
        debug!("listing tables");

        let url = format!("{}/schema/tables", self.base_url);
        let req = self.add_auth(self.client.get(&url));
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    /// List columns for a table.
    #[instrument(skip(self), fields(base_url = %self.base_url))]
    pub async fn list_columns(&self, table: &str) -> MysqlResult<serde_json::Value> {
        let table = validate_sql_identifier(table, "table")?;
        debug!(table, "listing columns");

        let url = format!("{}/schema/columns/{table}", self.base_url);
        let req = self.add_auth(self.client.get(&url));
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    /// List indexes for a table.
    #[instrument(skip(self), fields(base_url = %self.base_url))]
    pub async fn list_indexes(&self, table: &str) -> MysqlResult<serde_json::Value> {
        let table = validate_sql_identifier(table, "table")?;
        debug!(table, "listing indexes");

        let url = format!("{}/schema/indexes/{table}", self.base_url);
        let req = self.add_auth(self.client.get(&url));
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    /// Health check: simple probe to the `MySQL` proxy.
    #[instrument(skip(self), fields(base_url = %self.base_url))]
    pub async fn health_check(&self) -> MysqlResult<bool> {
        self.probe_health().await.map(|_| true)
    }

    /// Retrieve the health payload from the configured proxy.
    #[instrument(skip(self), fields(base_url = %self.base_url))]
    pub async fn probe_health(&self) -> MysqlResult<serde_json::Value> {
        debug!("running health probe");

        let url = format!("{}/health", self.base_url);
        let req = self.add_auth(self.client.get(&url));
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    /// Handle the HTTP response, extracting errors from the body.
    async fn handle_response(&self, resp: Response) -> MysqlResult<serde_json::Value> {
        let status = resp.status();

        if status.is_success() {
            let body = resp.json::<serde_json::Value>().await?;
            return Ok(body);
        }

        // Extract Retry-After header before consuming the body
        let retry_after_ms = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .map_or(1000, |secs| secs * 1000);

        // Try to parse error body
        let body_text = resp.text().await.unwrap_or_default();
        if let Ok(api_err) = serde_json::from_str::<ApiErrorResponse>(&body_text) {
            let message = api_err
                .message
                .unwrap_or_else(|| format!("MySQL error ({status})"));

            return match status {
                StatusCode::UNAUTHORIZED => Err(MysqlError::Auth(message)),
                StatusCode::FORBIDDEN => Err(MysqlError::PermissionDenied(message)),
                StatusCode::TOO_MANY_REQUESTS => Err(MysqlError::RateLimited { retry_after_ms }),
                StatusCode::CONFLICT => Err(MysqlError::ConstraintViolation(message)),
                _ => Err(MysqlError::Api {
                    status_code: status.as_u16(),
                    message,
                }),
            };
        }

        // Fallback: no parseable error body
        if status == StatusCode::TOO_MANY_REQUESTS {
            return Err(MysqlError::RateLimited { retry_after_ms });
        }

        Err(MysqlError::Api {
            status_code: status.as_u16(),
            message: if body_text.is_empty() {
                format!("HTTP {status}")
            } else {
                body_text
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_core::FcpError;

    #[test]
    fn auth_api_key_redacts_in_debug() {
        let auth = MysqlAuth::ApiKey("secret_key_123".into());
        let debug_str = format!("{auth:?}");
        assert!(!debug_str.contains("secret_key_123"));
        assert!(debug_str.contains("redacted"));
    }

    #[test]
    fn auth_credential_id_shows_id() {
        let auth = MysqlAuth::CredentialId(
            CredentialId::parse("550e8400-e29b-41d4-a716-446655440001").unwrap(),
        );
        let debug_str = format!("{auth:?}");
        assert!(debug_str.contains("550e8400"));
    }

    #[test]
    fn auth_redacted_label() {
        let token_auth = MysqlAuth::ApiKey("test-token".into());
        assert_eq!(token_auth.redacted_label(), "api_key:redacted");
        assert!(!token_auth.is_secretless());

        let cred = MysqlAuth::CredentialId(
            CredentialId::parse("550e8400-e29b-41d4-a716-446655440002").unwrap(),
        );
        assert!(cred.redacted_label().contains("550e8400"));
        assert!(cred.is_secretless());
    }

    #[test]
    fn client_creation_with_defaults() {
        let client = MysqlClient::new(MysqlAuth::ApiKey("test-key".into()), None);
        assert!(client.is_ok());
    }

    #[test]
    fn client_creation_with_custom_url() {
        let client = MysqlClient::new(
            MysqlAuth::ApiKey("test-key".into()),
            Some("https://mysql.example.com/api"),
        );
        assert!(client.is_ok());
    }

    #[test]
    fn client_debug_redacts_auth() {
        let client = MysqlClient::new(MysqlAuth::ApiKey("super_secret_key".into()), None).unwrap();
        let debug_str = format!("{client:?}");
        assert!(!debug_str.contains("super_secret_key"));
    }

    #[test]
    fn client_url_strips_trailing_slash() {
        let client = MysqlClient::new(
            MysqlAuth::ApiKey("key".into()),
            Some("https://example.com/"),
        )
        .unwrap();
        let debug_str = format!("{client:?}");
        assert!(debug_str.contains("https://example.com"));
    }

    #[test]
    fn retry_config_has_sane_defaults() {
        let client = MysqlClient::new(MysqlAuth::ApiKey("key".into()), None).unwrap();
        assert_eq!(client.retry_config().max_retries, 2);
    }

    // ── validate_sql_identifier tests ───────────────────────────────

    #[test]
    fn validate_sql_identifier_simple() {
        assert_eq!(validate_sql_identifier("users", "table").unwrap(), "users");
    }

    #[test]
    fn validate_sql_identifier_qualified_name() {
        assert_eq!(
            validate_sql_identifier("mydb.users", "table").unwrap(),
            "mydb.users"
        );
    }

    #[test]
    fn validate_sql_identifier_allows_underscore_start() {
        assert_eq!(
            validate_sql_identifier("_internal", "table").unwrap(),
            "_internal"
        );
    }

    #[test]
    fn validate_sql_identifier_allows_mixed_case() {
        assert_eq!(
            validate_sql_identifier("MyTable123", "table").unwrap(),
            "MyTable123"
        );
    }

    #[test]
    fn validate_sql_identifier_rejects_empty() {
        let err = validate_sql_identifier("", "table").unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn validate_sql_identifier_rejects_whitespace_only() {
        let err = validate_sql_identifier("   ", "table").unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn validate_sql_identifier_rejects_starting_digit() {
        let err = validate_sql_identifier("1bad", "table").unwrap_err();
        assert!(err.to_string().contains("must start with"));
    }

    #[test]
    fn validate_sql_identifier_rejects_semicolon() {
        let err = validate_sql_identifier("users; DROP TABLE x", "table").unwrap_err();
        assert!(err.to_string().contains("invalid character"));
    }

    #[test]
    fn validate_sql_identifier_rejects_single_quote() {
        let err = validate_sql_identifier("users' OR '1'='1", "table").unwrap_err();
        assert!(err.to_string().contains("invalid character"));
    }

    #[test]
    fn validate_sql_identifier_rejects_dash() {
        let err = validate_sql_identifier("my-table", "table").unwrap_err();
        assert!(err.to_string().contains("invalid character"));
    }

    #[test]
    fn validate_sql_identifier_rejects_space() {
        let err = validate_sql_identifier("my table", "table").unwrap_err();
        assert!(err.to_string().contains("invalid character"));
    }

    #[test]
    fn validate_sql_identifier_rejects_trailing_dot() {
        let err = validate_sql_identifier("users.", "table").unwrap_err();
        assert!(err.to_string().contains("invalid dot placement"));
    }

    #[test]
    fn validate_sql_identifier_rejects_consecutive_dots() {
        let err = validate_sql_identifier("mydb..users", "table").unwrap_err();
        assert!(err.to_string().contains("invalid dot placement"));
    }

    #[test]
    fn validate_sql_identifier_rejects_leading_dot() {
        let err = validate_sql_identifier(".users", "table").unwrap_err();
        assert!(err.to_string().contains("must start with"));
    }

    #[test]
    fn validate_invalid_input_not_retryable() {
        let err = MysqlError::InvalidInput("test".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn validate_invalid_input_to_fcp_error() {
        let err = MysqlError::InvalidInput("bad table".into());
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::InvalidRequest { .. }));
    }
}
