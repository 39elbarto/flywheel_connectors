//! `PostgreSQL` REST API client (`Supabase`/`PostgREST`-compatible).

use std::fmt;
use std::time::Duration;

use fcp_core::CredentialId;
use reqwest::{Client, Response, StatusCode};
use serde_json::json;
use tracing::{debug, instrument};

use crate::{
    error::{PostgresError, PostgresResult},
    types::ApiErrorResponse,
};

/// Default `PostgreSQL` REST API base URL.
///
/// Users must configure this to their actual `Supabase`/`PostgREST` endpoint.
pub const DEFAULT_BASE_URL: &str = "https://db.example.com";

/// Authentication mode for the `PostgreSQL` REST API.
#[derive(Clone)]
pub enum PostgresAuth {
    /// API key (passed as Bearer token).
    ApiKey(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl PostgresAuth {
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

impl fmt::Debug for PostgresAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApiKey(_) => f.debug_tuple("ApiKey").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// `PostgreSQL` REST API client.
///
/// Sends SQL queries and schema requests via HTTP to a `Supabase`/`PostgREST`-compatible endpoint.
pub struct PostgresClient {
    client: Client,
    auth: PostgresAuth,
    base_url: String,
}

impl fmt::Debug for PostgresClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PostgresClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl PostgresClient {
    /// Create a new `PostgreSQL` REST API client.
    pub fn new(auth: PostgresAuth, base_url: Option<&str>) -> PostgresResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-postgresql/0.1.0 (FCP connector)")
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
            PostgresAuth::ApiKey(key) => req.bearer_auth(key),
            PostgresAuth::CredentialId(id) => req.header("X-FCP-Credential-Id", id.to_string()),
        }
    }

    async fn handle_response(&self, resp: Response) -> PostgresResult<serde_json::Value> {
        let status = resp.status();
        if status.is_success() {
            let body = resp.text().await?;
            if body.is_empty() {
                return Ok(json!({}));
            }
            let parsed: serde_json::Value = serde_json::from_str(&body)?;
            // Check for error field in response
            if let Some(error) = parsed.get("error").and_then(serde_json::Value::as_str) {
                return Err(PostgresError::Query(error.to_string()));
            }
            Ok(parsed)
        } else {
            self.handle_error(status, resp).await
        }
    }

    async fn handle_error(
        &self,
        status: StatusCode,
        resp: Response,
    ) -> PostgresResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = resp.text().await.unwrap_or_default();

        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.message)
            .unwrap_or_else(|| {
                if body.is_empty() {
                    format!("HTTP {}", status.as_u16())
                } else {
                    body.clone()
                }
            });

        match status.as_u16() {
            401 => Err(PostgresError::Auth(detail)),
            403 => Err(PostgresError::PermissionDenied(detail)),
            409 => Err(PostgresError::ConstraintViolation(detail)),
            429 => Err(PostgresError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            408 => Err(PostgresError::Timeout(detail)),
            code => Err(PostgresError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    // -- Query operations --

    /// Execute a parameterized SQL query (returns rows).
    #[instrument(skip(self, params))]
    pub async fn query(
        &self,
        sql: &str,
        params: &[serde_json::Value],
        timeout_ms: Option<u64>,
    ) -> PostgresResult<serde_json::Value> {
        let url = format!("{}/rest/v1/rpc/query", self.base_url);
        debug!(url = %url, "POST pg.query");
        let mut body = json!({
            "sql": sql,
            "params": params,
        });
        if let Some(t) = timeout_ms {
            body["timeout_ms"] = json!(t);
        }
        let req = self
            .add_auth(self.client.post(&url))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(&body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    /// Execute a non-returning SQL statement (returns `affected_rows`).
    #[instrument(skip(self, params))]
    pub async fn execute(
        &self,
        sql: &str,
        params: &[serde_json::Value],
    ) -> PostgresResult<serde_json::Value> {
        let url = format!("{}/rest/v1/rpc/query", self.base_url);
        debug!(url = %url, "POST pg.execute");
        let body = json!({
            "sql": sql,
            "params": params,
            "mode": "execute",
        });
        let req = self
            .add_auth(self.client.post(&url))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(&body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    /// Explain a query plan.
    #[instrument(skip(self, params))]
    pub async fn explain(
        &self,
        sql: &str,
        params: &[serde_json::Value],
    ) -> PostgresResult<serde_json::Value> {
        let url = format!("{}/rest/v1/rpc/explain", self.base_url);
        debug!(url = %url, "POST pg.explain");
        let body = json!({
            "sql": sql,
            "params": params,
        });
        let req = self
            .add_auth(self.client.post(&url))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(&body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- Schema operations --

    /// List tables in the database.
    #[instrument(skip(self))]
    pub async fn schema_tables(&self, schema: Option<&str>) -> PostgresResult<serde_json::Value> {
        let mut url = format!("{}/rest/v1/schema/tables", self.base_url);
        if let Some(s) = schema {
            url = format!("{url}?schema={s}");
        }
        debug!(url = %url, "GET pg.schema.tables");
        let req = self
            .add_auth(self.client.get(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    /// Get columns for a table.
    #[instrument(skip(self))]
    pub async fn schema_columns(&self, table: &str) -> PostgresResult<serde_json::Value> {
        let url = format!("{}/rest/v1/schema/columns?table={table}", self.base_url);
        debug!(url = %url, "GET pg.schema.columns");
        let req = self
            .add_auth(self.client.get(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    /// List indexes for a table.
    #[instrument(skip(self))]
    pub async fn schema_indexes(&self, table: &str) -> PostgresResult<serde_json::Value> {
        let url = format!("{}/rest/v1/schema/indexes?table={table}", self.base_url);
        debug!(url = %url, "GET pg.schema.indexes");
        let req = self
            .add_auth(self.client.get(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- Transaction operations --

    /// Begin a transaction.
    #[instrument(skip(self))]
    pub async fn transaction_begin(
        &self,
        isolation_level: Option<&str>,
    ) -> PostgresResult<serde_json::Value> {
        let url = format!("{}/rest/v1/rpc/transaction", self.base_url);
        debug!(url = %url, "POST pg.transaction.begin");
        let mut body = json!({ "action": "begin" });
        if let Some(level) = isolation_level {
            body["isolation_level"] = json!(level);
        }
        let req = self
            .add_auth(self.client.post(&url))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(&body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    /// Commit a transaction.
    #[instrument(skip(self))]
    pub async fn transaction_commit(&self, txn_id: &str) -> PostgresResult<serde_json::Value> {
        let url = format!("{}/rest/v1/rpc/transaction", self.base_url);
        debug!(url = %url, "POST pg.transaction.commit");
        let body = json!({
            "action": "commit",
            "txn_id": txn_id,
        });
        let req = self
            .add_auth(self.client.post(&url))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(&body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    /// Rollback a transaction.
    #[instrument(skip(self))]
    pub async fn transaction_rollback(&self, txn_id: &str) -> PostgresResult<serde_json::Value> {
        let url = format!("{}/rest/v1/rpc/transaction", self.base_url);
        debug!(url = %url, "POST pg.transaction.rollback");
        let body = json!({
            "action": "rollback",
            "txn_id": txn_id,
        });
        let req = self
            .add_auth(self.client.post(&url))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(&body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- Batch and prepared operations --

    /// Execute multiple statements in order.
    #[instrument(skip(self, statements, params))]
    pub async fn batch(
        &self,
        statements: &[String],
        params: &[Vec<serde_json::Value>],
    ) -> PostgresResult<serde_json::Value> {
        let url = format!("{}/rest/v1/rpc/batch", self.base_url);
        debug!(url = %url, "POST pg.batch");
        let body = json!({
            "statements": statements,
            "params": params,
        });
        let req = self
            .add_auth(self.client.post(&url))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(&body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    /// Execute a named prepared statement.
    #[instrument(skip(self, params))]
    pub async fn prepared(
        &self,
        name: &str,
        params: &[serde_json::Value],
    ) -> PostgresResult<serde_json::Value> {
        let url = format!("{}/rest/v1/rpc/prepared", self.base_url);
        debug!(url = %url, "POST pg.prepared");
        let body = json!({
            "name": name,
            "params": params,
        });
        let req = self
            .add_auth(self.client.post(&url))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(&body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- Health --

    /// Check database connectivity.
    #[instrument(skip(self))]
    pub async fn health(&self) -> PostgresResult<serde_json::Value> {
        let url = format!("{}/rest/v1/health", self.base_url);
        debug!(url = %url, "GET pg.health");
        let req = self
            .add_auth(self.client.get(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }
}
