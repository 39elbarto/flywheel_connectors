//! Elasticsearch API client.

use std::fmt;
use std::time::Duration;

use fcp_core::CredentialId;
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{ElasticsearchError, ElasticsearchResult},
    types::ApiErrorResponse,
};

/// Default Elasticsearch Cloud base URL (placeholder — must be configured).
pub const DEFAULT_BASE_URL: &str = "https://localhost:9200";

/// Authentication mode for the Elasticsearch API.
#[derive(Clone)]
pub enum ElasticsearchAuth {
    /// API key (base64-encoded `id:api_key`).
    ApiKey(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl ElasticsearchAuth {
    /// Render a redacted label suitable for logs/diagnostics.
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::ApiKey(_) => "api_key:redacted".to_string(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    /// Whether this auth mode requires egress proxy credential injection.
    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for ElasticsearchAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApiKey(_) => f.debug_tuple("ApiKey").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// Elasticsearch API client.
pub struct ElasticsearchClient {
    client: Client,
    auth: ElasticsearchAuth,
    base_url: String,
}

impl fmt::Debug for ElasticsearchClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ElasticsearchClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl ElasticsearchClient {
    /// Create a new Elasticsearch client.
    pub fn new(auth: ElasticsearchAuth, base_url: Option<&str>) -> ElasticsearchResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-elasticsearch/0.1.0")
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
    pub fn with_client(client: Client, auth: ElasticsearchAuth, base_url: &str) -> Self {
        Self {
            client,
            auth,
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            ElasticsearchAuth::ApiKey(key) => req.header("Authorization", format!("ApiKey {key}")),
            ElasticsearchAuth::CredentialId(id) => {
                req.header("X-FCP-Credential-Id", id.to_string())
            }
        }
    }

    async fn handle_response(&self, resp: Response) -> ElasticsearchResult<serde_json::Value> {
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
    ) -> ElasticsearchResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = resp.text().await.unwrap_or_default();
        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.error)
            .and_then(|e| e.reason)
            .unwrap_or_else(|| body.clone());

        match status.as_u16() {
            401 => Err(ElasticsearchError::Unauthorized),
            403 => Err(ElasticsearchError::Forbidden),
            404 => Err(ElasticsearchError::NotFound { resource: detail }),
            429 => Err(ElasticsearchError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(ElasticsearchError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    #[instrument(skip(self), fields(url))]
    async fn get(&self, path: &str) -> ElasticsearchResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "GET request");

        let req = self.client.get(&url);
        let req = self.add_auth(req);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn post(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> ElasticsearchResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "POST request");

        let req = self.client.post(&url).json(body);
        let req = self.add_auth(req);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn post_ndjson(
        &self,
        path: &str,
        body: &str,
    ) -> ElasticsearchResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "POST NDJSON request");

        let req = self
            .client
            .post(&url)
            .header("Content-Type", "application/x-ndjson")
            .body(body.to_string());
        let req = self.add_auth(req);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn put(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> ElasticsearchResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "PUT request");

        let req = self.client.put(&url).json(body);
        let req = self.add_auth(req);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self), fields(url))]
    async fn delete(&self, path: &str) -> ElasticsearchResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "DELETE request");

        let req = self.client.delete(&url);
        let req = self.add_auth(req);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- Search --

    /// Search documents.
    pub async fn search(
        &self,
        index: &str,
        query: Option<&serde_json::Value>,
        size: Option<i64>,
        from: Option<i64>,
        sort: Option<&serde_json::Value>,
    ) -> ElasticsearchResult<serde_json::Value> {
        let mut body = serde_json::json!({});
        if let Some(q) = query {
            body["query"] = q.clone();
        }
        if let Some(s) = size {
            body["size"] = serde_json::json!(s);
        }
        if let Some(f) = from {
            body["from"] = serde_json::json!(f);
        }
        if let Some(s) = sort {
            body["sort"] = s.clone();
        }
        self.post(&format!("/{index}/_search"), &body).await
    }

    /// Get a document by ID.
    pub async fn get_document(
        &self,
        index: &str,
        document_id: &str,
    ) -> ElasticsearchResult<serde_json::Value> {
        self.get(&format!("/{index}/_doc/{document_id}")).await
    }

    // -- Indexing --

    /// Index (create or update) a document.
    pub async fn index_document(
        &self,
        index: &str,
        document_id: Option<&str>,
        document: &serde_json::Value,
    ) -> ElasticsearchResult<serde_json::Value> {
        match document_id {
            Some(id) => self.put(&format!("/{index}/_doc/{id}"), document).await,
            None => self.post(&format!("/{index}/_doc"), document).await,
        }
    }

    /// Bulk operations.
    pub async fn bulk(
        &self,
        operations: &[serde_json::Value],
    ) -> ElasticsearchResult<serde_json::Value> {
        let mut ndjson = String::new();
        for op in operations {
            ndjson.push_str(&serde_json::to_string(op).unwrap_or_default());
            ndjson.push('\n');
        }
        self.post_ndjson("/_bulk", &ndjson).await
    }

    // -- Indices --

    /// List indices.
    pub async fn list_indices(
        &self,
        pattern: Option<&str>,
    ) -> ElasticsearchResult<serde_json::Value> {
        let idx = pattern.unwrap_or("*");
        self.get(&format!("/_cat/indices/{idx}?format=json")).await
    }

    /// Delete an index.
    pub async fn delete_index(&self, index: &str) -> ElasticsearchResult<serde_json::Value> {
        self.delete(&format!("/{index}")).await
    }

    // -- Cluster --

    /// Get cluster health.
    pub async fn cluster_health(&self) -> ElasticsearchResult<serde_json::Value> {
        self.get("/_cluster/health").await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_key() {
        let auth = ElasticsearchAuth::ApiKey("base64secret".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("base64secret"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let api_key = ElasticsearchAuth::ApiKey("key".into());
        assert!(!api_key.is_secretless());

        let cred = ElasticsearchAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label() {
        let api_key = ElasticsearchAuth::ApiKey("key".into());
        assert_eq!(api_key.redacted_label(), "api_key:redacted");

        let cred = ElasticsearchAuth::CredentialId(CredentialId::new());
        assert!(cred.redacted_label().starts_with("credential_id:"));
    }
}
