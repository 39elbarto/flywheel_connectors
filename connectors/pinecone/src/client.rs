//! Pinecone REST API client.
//!
//! Pinecone uses two API planes:
//! - Control plane (`https://api.pinecone.io`) for index management
//! - Data plane (`https://{index-host}`) for vector operations

use std::fmt;

use fcp_core::CredentialId;
use reqwest::{Client, StatusCode, header};
use tracing::{debug, warn};

use crate::{
    error::{PineconeError, PineconeResult},
    types::{
        ApiErrorResponse, FetchResponse, Index, IndexStats, ListIndexesResponse, QueryResponse,
        UpsertResponse, Vector,
    },
};

/// Default Pinecone control plane URL.
pub const DEFAULT_CONTROL_PLANE_URL: &str = "https://api.pinecone.io";

/// Authentication mode for Pinecone.
#[derive(Clone)]
pub enum PineconeAuth {
    /// Direct API key.
    ApiKey(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl PineconeAuth {
    /// Render a redacted label suitable for logs/diagnostics.
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::ApiKey(key) => {
                let prefix = if key.len() > 8 {
                    &key[..8]
                } else {
                    key.as_str()
                };
                format!("api_key:{prefix}***")
            }
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    /// Whether this auth mode requires egress proxy credential injection.
    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for PineconeAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApiKey(_) => f
                .debug_struct("ApiKey")
                .field("key", &"<redacted>")
                .finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// Pinecone REST API client.
pub struct PineconeClient {
    http: Client,
    auth: PineconeAuth,
    control_plane_url: String,
    data_plane_url: Option<String>,
    max_retries: u32,
}

impl fmt::Debug for PineconeClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PineconeClient")
            .field("auth", &self.auth)
            .field("control_plane_url", &self.control_plane_url)
            .field("data_plane_url", &self.data_plane_url)
            .finish_non_exhaustive()
    }
}

impl PineconeClient {
    /// Create a new Pinecone client with an API key.
    pub fn new(api_key: &str) -> PineconeResult<Self> {
        Self::new_with_auth(PineconeAuth::ApiKey(api_key.to_string()))
    }

    /// Create a new Pinecone client with explicit auth mode.
    pub fn new_with_auth(auth: PineconeAuth) -> PineconeResult<Self> {
        let mut headers = header::HeaderMap::new();
        match &auth {
            PineconeAuth::ApiKey(key) => {
                headers.insert(
                    "Api-Key",
                    key.parse().map_err(|_| {
                        PineconeError::InvalidConfig("Invalid API key format".into())
                    })?,
                );
            }
            PineconeAuth::CredentialId(id) => {
                headers.insert(
                    "X-FCP-Credential-ID",
                    id.to_string().parse().map_err(|_| {
                        PineconeError::InvalidConfig("Invalid credential ID format".into())
                    })?,
                );
            }
        }

        let http = Client::builder()
            .default_headers(headers)
            .user_agent("fcp-pinecone/0.1.0")
            .build()
            .map_err(PineconeError::Http)?;

        Ok(Self {
            http,
            auth,
            control_plane_url: DEFAULT_CONTROL_PLANE_URL.to_string(),
            data_plane_url: None,
            max_retries: 2,
        })
    }

    /// Perform a lightweight health check (list indexes).
    ///
    /// # Errors
    ///
    /// Returns an error if the API call fails.
    pub async fn health_check(&self) -> PineconeResult<()> {
        let _ = self.list_indexes().await?;
        Ok(())
    }

    /// Set a custom control plane URL (for testing).
    #[must_use]
    pub fn with_control_plane_url(mut self, url: &str) -> Self {
        self.control_plane_url = url.to_string();
        self
    }

    /// Set a custom data plane URL (for testing or when index host is known).
    #[must_use]
    pub fn with_data_plane_url(mut self, url: &str) -> Self {
        self.data_plane_url = Some(url.to_string());
        self
    }

    /// Set the maximum number of retries.
    #[must_use]
    pub const fn with_retry_config(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    fn data_plane_base(&self) -> PineconeResult<&str> {
        self.data_plane_url.as_deref().ok_or_else(|| {
            PineconeError::InvalidConfig(
                "Data plane URL not configured. Call describe_index first or set data_plane_url."
                    .into(),
            )
        })
    }

    // ── Control plane operations ──────────────────────────────────

    /// List all indexes.
    pub async fn list_indexes(&self) -> PineconeResult<ListIndexesResponse> {
        let url = format!("{}/indexes", self.control_plane_url);
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Describe a specific index.
    pub async fn describe_index(&self, index_name: &str) -> PineconeResult<Index> {
        let url = format!("{}/indexes/{index_name}", self.control_plane_url);
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Create a new index.
    pub async fn create_index(
        &self,
        name: &str,
        dimension: u32,
        metric: &str,
        spec: Option<&serde_json::Value>,
    ) -> PineconeResult<Index> {
        let url = format!("{}/indexes", self.control_plane_url);
        let mut body = serde_json::json!({
            "name": name,
            "dimension": dimension,
            "metric": metric,
        });
        if let Some(s) = spec {
            body["spec"] = s.clone();
        }
        let data = self.post_json(&url, &body).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Delete an index by name.
    pub async fn delete_index(&self, index_name: &str) -> PineconeResult<()> {
        let url = format!("{}/indexes/{index_name}", self.control_plane_url);
        self.execute_delete(&url).await?;
        Ok(())
    }

    // ── Data plane operations ─────────────────────────────────────

    /// Get index statistics.
    pub async fn describe_index_stats(
        &self,
        filter: Option<&serde_json::Value>,
    ) -> PineconeResult<IndexStats> {
        let base = self.data_plane_base()?;
        let url = format!("{base}/describe_index_stats");
        let body = match filter {
            Some(f) => serde_json::json!({ "filter": f }),
            None => serde_json::json!({}),
        };
        let data = self.post_json(&url, &body).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Query vectors by similarity.
    pub async fn query(
        &self,
        vector: Option<&[f32]>,
        id: Option<&str>,
        top_k: u32,
        namespace: Option<&str>,
        filter: Option<&serde_json::Value>,
        include_metadata: bool,
        include_values: bool,
    ) -> PineconeResult<QueryResponse> {
        let base = self.data_plane_base()?;
        let url = format!("{base}/query");
        let mut body = serde_json::json!({
            "topK": top_k,
            "includeMetadata": include_metadata,
            "includeValues": include_values,
        });
        if let Some(v) = vector {
            body["vector"] = serde_json::to_value(v).unwrap_or_default();
        }
        if let Some(i) = id {
            body["id"] = serde_json::Value::String(i.to_string());
        }
        if let Some(ns) = namespace {
            body["namespace"] = serde_json::Value::String(ns.to_string());
        }
        if let Some(f) = filter {
            body["filter"] = f.clone();
        }
        let data = self.post_json(&url, &body).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Fetch vectors by ID.
    pub async fn fetch(
        &self,
        ids: &[String],
        namespace: Option<&str>,
    ) -> PineconeResult<FetchResponse> {
        let base = self.data_plane_base()?;
        let mut url = format!("{base}/vectors/fetch");
        let mut params = Vec::new();
        for id in ids {
            params.push(format!("ids={id}"));
        }
        if let Some(ns) = namespace {
            params.push(format!("namespace={ns}"));
        }
        if !params.is_empty() {
            url = format!("{url}?{}", params.join("&"));
        }
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Upsert vectors.
    pub async fn upsert(
        &self,
        vectors: &[Vector],
        namespace: Option<&str>,
    ) -> PineconeResult<UpsertResponse> {
        let base = self.data_plane_base()?;
        let url = format!("{base}/vectors/upsert");
        let mut body = serde_json::json!({ "vectors": vectors });
        if let Some(ns) = namespace {
            body["namespace"] = serde_json::Value::String(ns.to_string());
        }
        let data = self.post_json(&url, &body).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Delete vectors.
    pub async fn delete(
        &self,
        ids: Option<&[String]>,
        delete_all: bool,
        namespace: Option<&str>,
        filter: Option<&serde_json::Value>,
    ) -> PineconeResult<serde_json::Value> {
        let base = self.data_plane_base()?;
        let url = format!("{base}/vectors/delete");
        let mut body = serde_json::json!({});
        if let Some(i) = ids {
            body["ids"] = serde_json::to_value(i).unwrap_or_default();
        }
        if delete_all {
            body["deleteAll"] = serde_json::Value::Bool(true);
        }
        if let Some(ns) = namespace {
            body["namespace"] = serde_json::Value::String(ns.to_string());
        }
        if let Some(f) = filter {
            body["filter"] = f.clone();
        }
        self.post_json(&url, &body).await
    }

    // ── HTTP helpers ──────────────────────────────────────────────

    async fn get(&self, url: &str) -> PineconeResult<serde_json::Value> {
        self.execute(|| self.http.get(url)).await
    }

    async fn post_json(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> PineconeResult<serde_json::Value> {
        self.execute(|| self.http.post(url).json(body)).await
    }

    async fn execute_delete(&self, url: &str) -> PineconeResult<serde_json::Value> {
        self.execute(|| self.http.delete(url)).await
    }

    async fn execute(
        &self,
        build_request: impl Fn() -> reqwest::RequestBuilder,
    ) -> PineconeResult<serde_json::Value> {
        let mut last_err = None;

        for attempt in 0..=self.max_retries {
            if attempt > 0 {
                let delay = std::time::Duration::from_millis(500 * u64::from(attempt));
                debug!(attempt, delay_ms = delay.as_millis(), "retrying request");
                fcp_async_core::time::sleep(delay).await;
            }

            let result = build_request().send().await;

            match result {
                Ok(response) => {
                    let status = response.status();

                    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                        let body = response.text().await.unwrap_or_default();
                        return Err(PineconeError::Api {
                            message: format!("Authentication failed: {body}"),
                            status_code: Some(status.as_u16()),
                        });
                    }

                    if status == StatusCode::NOT_FOUND {
                        let body = response.text().await.unwrap_or_default();
                        return Err(PineconeError::Api {
                            message: format!("Not found: {body}"),
                            status_code: Some(404),
                        });
                    }

                    if status == StatusCode::TOO_MANY_REQUESTS {
                        let retry_after = response
                            .headers()
                            .get("retry-after")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.parse::<u64>().ok())
                            .map_or(60_000, |s| s * 1000);

                        let err = PineconeError::RateLimit {
                            retry_after_ms: retry_after,
                        };
                        if attempt < self.max_retries {
                            warn!(attempt, "rate limited, will retry");
                            last_err = Some(err);
                            continue;
                        }
                        return Err(err);
                    }

                    if status.is_server_error() {
                        let body = response.text().await.unwrap_or_default();
                        let err = PineconeError::Api {
                            message: format!("Server error {status}: {body}"),
                            status_code: Some(status.as_u16()),
                        };
                        if attempt < self.max_retries {
                            warn!(attempt, status = %status, "server error, will retry");
                            last_err = Some(err);
                            continue;
                        }
                        return Err(err);
                    }

                    if !status.is_success() {
                        let body = response.text().await.unwrap_or_default();
                        let api_err: Option<ApiErrorResponse> = serde_json::from_str(&body).ok();
                        let message = api_err
                            .as_ref()
                            .and_then(|e| {
                                e.message
                                    .clone()
                                    .or_else(|| e.error.as_ref().and_then(|d| d.message.clone()))
                            })
                            .unwrap_or_else(|| format!("HTTP {status}: {body}"));
                        return Err(PineconeError::Api {
                            message,
                            status_code: Some(status.as_u16()),
                        });
                    }

                    let body = response.text().await.map_err(PineconeError::Http)?;
                    if body.is_empty() {
                        return Ok(serde_json::json!({}));
                    }
                    let data: serde_json::Value = serde_json::from_str(&body)?;
                    return Ok(data);
                }
                Err(e) => {
                    if attempt < self.max_retries {
                        warn!(attempt, error = %e, "request failed, will retry");
                        last_err = Some(PineconeError::Http(e));
                        continue;
                    }
                    return Err(PineconeError::Http(e));
                }
            }
        }

        Err(last_err.unwrap_or(PineconeError::Api {
            message: "Max retries exceeded".into(),
            status_code: None,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    #[fcp_async_core::runtime::test]
    async fn test_list_indexes() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/indexes"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "indexes": [
                    {
                        "name": "my-index",
                        "dimension": 1536,
                        "metric": "cosine",
                        "host": "my-index-abc123.svc.pinecone.io"
                    }
                ]
            })))
            .mount(&mock_server)
            .await;

        let client = PineconeClient::new("test-api-key")
            .unwrap()
            .with_control_plane_url(&mock_server.uri());

        let result = client.list_indexes().await.unwrap();
        assert_eq!(result.indexes.len(), 1);
        assert_eq!(result.indexes[0].name, "my-index");
        assert_eq!(result.indexes[0].dimension, 1536);
    }

    #[fcp_async_core::runtime::test]
    async fn test_describe_index() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/indexes/my-index"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "my-index",
                "dimension": 1536,
                "metric": "cosine",
                "host": "my-index-abc123.svc.pinecone.io",
                "status": { "ready": true, "state": "Ready" }
            })))
            .mount(&mock_server)
            .await;

        let client = PineconeClient::new("test-api-key")
            .unwrap()
            .with_control_plane_url(&mock_server.uri());

        let index = client.describe_index("my-index").await.unwrap();
        assert_eq!(index.name, "my-index");
        assert_eq!(index.dimension, 1536);
        assert_eq!(index.metric, "cosine");
        assert!(index.status.as_ref().unwrap().ready.unwrap());
    }

    #[fcp_async_core::runtime::test]
    async fn test_create_index() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/indexes"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "name": "new-index",
                "dimension": 1536,
                "metric": "cosine",
                "host": "new-index-abc.svc.pinecone.io",
                "status": { "ready": false, "state": "Initializing" }
            })))
            .mount(&mock_server)
            .await;

        let client = PineconeClient::new("test-api-key")
            .unwrap()
            .with_control_plane_url(&mock_server.uri());

        let index = client
            .create_index("new-index", 1536, "cosine", None)
            .await
            .unwrap();
        assert_eq!(index.name, "new-index");
        assert_eq!(index.dimension, 1536);
        assert!(!index.status.as_ref().unwrap().ready.unwrap());
    }

    #[fcp_async_core::runtime::test]
    async fn test_delete_index() {
        let mock_server = MockServer::start().await;

        Mock::given(method("DELETE"))
            .and(path("/indexes/old-index"))
            .respond_with(ResponseTemplate::new(202))
            .mount(&mock_server)
            .await;

        let client = PineconeClient::new("test-api-key")
            .unwrap()
            .with_control_plane_url(&mock_server.uri());

        let result = client.delete_index("old-index").await;
        assert!(result.is_ok());
    }

    #[fcp_async_core::runtime::test]
    async fn test_describe_index_stats() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/describe_index_stats"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "namespaces": {
                    "": { "vector_count": 1000 },
                    "ns1": { "vector_count": 500 }
                },
                "dimension": 1536,
                "index_fullness": 0.15,
                "total_vector_count": 1500
            })))
            .mount(&mock_server)
            .await;

        let client = PineconeClient::new("test-api-key")
            .unwrap()
            .with_data_plane_url(&mock_server.uri());

        let stats = client.describe_index_stats(None).await.unwrap();
        assert_eq!(stats.dimension, Some(1536));
        assert_eq!(stats.total_vector_count, 1500);
        let ns = stats.namespaces.as_ref().unwrap();
        assert_eq!(ns.len(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn test_query() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/query"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "matches": [
                    { "id": "vec-1", "score": 0.95, "metadata": { "text": "hello" } },
                    { "id": "vec-2", "score": 0.85 }
                ],
                "namespace": ""
            })))
            .mount(&mock_server)
            .await;

        let client = PineconeClient::new("test-api-key")
            .unwrap()
            .with_data_plane_url(&mock_server.uri());

        let result = client
            .query(Some(&[0.1, 0.2, 0.3]), None, 10, None, None, true, false)
            .await
            .unwrap();
        assert_eq!(result.matches.len(), 2);
        assert_eq!(result.matches[0].id, "vec-1");
        assert!((result.matches[0].score.unwrap() - 0.95).abs() < f64::EPSILON);
    }

    #[fcp_async_core::runtime::test]
    async fn test_fetch() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/vectors/fetch"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "vectors": {
                    "vec-1": {
                        "id": "vec-1",
                        "values": [0.1, 0.2, 0.3]
                    },
                    "vec-2": {
                        "id": "vec-2",
                        "values": [0.4, 0.5, 0.6]
                    }
                },
                "namespace": ""
            })))
            .mount(&mock_server)
            .await;

        let client = PineconeClient::new("test-api-key")
            .unwrap()
            .with_data_plane_url(&mock_server.uri());

        let ids = vec!["vec-1".to_string(), "vec-2".to_string()];
        let result = client.fetch(&ids, None).await.unwrap();
        assert_eq!(result.vectors.len(), 2);
        assert!(result.vectors.contains_key("vec-1"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_upsert() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/vectors/upsert"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "upserted_count": 2
            })))
            .mount(&mock_server)
            .await;

        let client = PineconeClient::new("test-api-key")
            .unwrap()
            .with_data_plane_url(&mock_server.uri());

        let vectors = vec![
            Vector {
                id: "vec-1".into(),
                values: Some(vec![0.1, 0.2, 0.3]),
                metadata: None,
                sparse_values: None,
            },
            Vector {
                id: "vec-2".into(),
                values: Some(vec![0.4, 0.5, 0.6]),
                metadata: None,
                sparse_values: None,
            },
        ];
        let result = client.upsert(&vectors, None).await.unwrap();
        assert_eq!(result.upserted_count, 2);
    }

    #[fcp_async_core::runtime::test]
    async fn test_delete() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/vectors/delete"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&mock_server)
            .await;

        let client = PineconeClient::new("test-api-key")
            .unwrap()
            .with_data_plane_url(&mock_server.uri());

        let ids = vec!["vec-1".to_string(), "vec-2".to_string()];
        let result = client.delete(Some(&ids), false, None, None).await;
        assert!(result.is_ok());
    }

    #[fcp_async_core::runtime::test]
    async fn test_unauthorized() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/indexes"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&mock_server)
            .await;

        let client = PineconeClient::new("bad-key")
            .unwrap()
            .with_control_plane_url(&mock_server.uri())
            .with_retry_config(0);

        let result = client.list_indexes().await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PineconeError::Api {
                status_code: Some(401),
                ..
            }
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/indexes/missing"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "message": "Index not found: missing"
            })))
            .mount(&mock_server)
            .await;

        let client = PineconeClient::new("test-api-key")
            .unwrap()
            .with_control_plane_url(&mock_server.uri())
            .with_retry_config(0);

        let result = client.describe_index("missing").await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PineconeError::Api {
                status_code: Some(404),
                ..
            }
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_rate_limited() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/indexes"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&mock_server)
            .await;

        let client = PineconeClient::new("test-api-key")
            .unwrap()
            .with_control_plane_url(&mock_server.uri())
            .with_retry_config(0);

        let result = client.list_indexes().await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PineconeError::RateLimit { .. }
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_server_error_retry() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/indexes"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
            .expect(2)
            .mount(&mock_server)
            .await;

        let client = PineconeClient::new("test-api-key")
            .unwrap()
            .with_control_plane_url(&mock_server.uri())
            .with_retry_config(1);

        let result = client.list_indexes().await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PineconeError::Api {
                status_code: Some(500),
                ..
            }
        ));
    }

    #[test]
    fn test_error_is_retryable() {
        let err = PineconeError::RateLimit {
            retry_after_ms: 1000,
        };
        assert!(err.is_retryable());

        let err = PineconeError::InvalidConfig("bad".into());
        assert!(!err.is_retryable());

        let err = PineconeError::Api {
            message: "Server error".into(),
            status_code: Some(500),
        };
        assert!(err.is_retryable());

        let err = PineconeError::Api {
            message: "Bad request".into(),
            status_code: Some(400),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_data_plane_url_required() {
        let client = PineconeClient::new("test-api-key").unwrap();
        assert!(client.data_plane_base().is_err());
    }
}
