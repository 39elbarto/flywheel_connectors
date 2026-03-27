//! Qdrant REST API client.
//!
//! Qdrant uses JSON POST bodies for most data operations and GET for collection reads.
//! Auth via `api-key` header.

use std::time::Duration;

use fcp_sdk::migration::{
    AttemptOutcome, ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig, RetryLoop,
};
use reqwest::{Client, StatusCode, header};
use tracing::debug;

use crate::{
    error::{QdrantError, QdrantResult},
    types::{CollectionInfo, CountResult, ListCollectionsResult, ScrollResult},
};

/// Qdrant REST API client.
pub struct QdrantClient {
    http: Client,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl QdrantClient {
    /// Create a new Qdrant client with an API key and cluster URL.
    pub fn new(api_key: &str, cluster_url: &str) -> QdrantResult<Self> {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::HeaderName::from_static("api-key"),
            api_key.parse().map_err(|_| QdrantError::InvalidConfig {
                message: "Invalid API key format".into(),
            })?,
        );

        let http = Client::builder()
            .default_headers(headers)
            .user_agent("fcp-qdrant/0.1.0")
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(QdrantError::Http)?;

        Ok(Self {
            http,
            base_url: cluster_url.trim_end_matches('/').to_string(),
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(30)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 2,
                ..HttpRetryConfig::default()
            },
        })
    }

    /// Set a custom base URL (for testing).
    #[must_use]
    pub fn with_base_url(mut self, url: &str) -> Self {
        self.base_url = url.trim_end_matches('/').to_string();
        self
    }

    /// Set the maximum number of retries.
    #[must_use]
    pub fn with_retry_config(mut self, max_retries: u32) -> Self {
        self.retry_config = HttpRetryConfig {
            max_retries,
            ..HttpRetryConfig::default()
        };
        self
    }

    /// Trigger graceful shutdown.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    // -- Collection operations --

    /// List all collections.
    pub async fn list_collections(&self) -> QdrantResult<ListCollectionsResult> {
        let url = format!("{}/collections", self.base_url);
        let data = self.get(&url).await?;
        let result = data
            .get("result")
            .cloned()
            .unwrap_or(serde_json::json!({ "collections": [] }));
        Ok(serde_json::from_value(result)?)
    }

    /// Get collection info.
    pub async fn collection_info(&self, collection_name: &str) -> QdrantResult<CollectionInfo> {
        let url = format!("{}/collections/{collection_name}", self.base_url);
        let data = self.get(&url).await?;
        let result = data.get("result").cloned().unwrap_or(serde_json::json!({}));
        Ok(serde_json::from_value(result)?)
    }

    /// Create a collection.
    pub async fn create_collection(
        &self,
        collection_name: &str,
        body: &serde_json::Value,
    ) -> QdrantResult<serde_json::Value> {
        let url = format!("{}/collections/{collection_name}", self.base_url);
        self.put_json(&url, body).await
    }

    /// Delete a collection.
    pub async fn delete_collection(
        &self,
        collection_name: &str,
    ) -> QdrantResult<serde_json::Value> {
        let url = format!("{}/collections/{collection_name}", self.base_url);
        self.delete(&url).await
    }

    // -- Point read operations --

    /// Search for similar points by vector.
    pub async fn search(
        &self,
        collection_name: &str,
        body: &serde_json::Value,
    ) -> QdrantResult<Vec<serde_json::Value>> {
        let url = format!(
            "{}/collections/{collection_name}/points/search",
            self.base_url
        );
        let data = self.post_json(&url, body).await?;
        let result = data
            .get("result")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        Ok(result)
    }

    /// Query points using Qdrant query API.
    pub async fn query_points(
        &self,
        collection_name: &str,
        body: &serde_json::Value,
    ) -> QdrantResult<Vec<serde_json::Value>> {
        let url = format!(
            "{}/collections/{collection_name}/points/query",
            self.base_url
        );
        let data = self.post_json(&url, body).await?;
        if let Some(result) = data.get("result") {
            if let Some(array) = result.as_array() {
                return Ok(array.clone());
            }
            if let Some(points) = result.get("points").and_then(|value| value.as_array()) {
                return Ok(points.clone());
            }
        }
        Ok(Vec::new())
    }

    /// Batch query points using Qdrant query API.
    pub async fn batch_query_points(
        &self,
        collection_name: &str,
        queries: &[serde_json::Value],
    ) -> QdrantResult<Vec<serde_json::Value>> {
        let url = format!(
            "{}/collections/{collection_name}/points/query/batch",
            self.base_url
        );
        let body = serde_json::json!({ "searches": queries });
        let data = self.post_json(&url, &body).await?;
        let result = data
            .get("result")
            .and_then(|value| value.as_array())
            .cloned()
            .unwrap_or_default();
        Ok(result)
    }

    /// Get points by IDs.
    pub async fn get_points(
        &self,
        collection_name: &str,
        body: &serde_json::Value,
    ) -> QdrantResult<Vec<serde_json::Value>> {
        let url = format!("{}/collections/{collection_name}/points", self.base_url);
        let data = self.post_json(&url, body).await?;
        let result = data
            .get("result")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        Ok(result)
    }

    /// Scroll through points.
    pub async fn scroll(
        &self,
        collection_name: &str,
        body: &serde_json::Value,
    ) -> QdrantResult<ScrollResult> {
        let url = format!(
            "{}/collections/{collection_name}/points/scroll",
            self.base_url
        );
        let data = self.post_json(&url, body).await?;
        let result = data.get("result").cloned().unwrap_or(serde_json::json!({
            "points": [],
            "next_page_offset": null
        }));
        Ok(serde_json::from_value(result)?)
    }

    /// Count points in a collection.
    pub async fn count(
        &self,
        collection_name: &str,
        body: &serde_json::Value,
    ) -> QdrantResult<CountResult> {
        let url = format!(
            "{}/collections/{collection_name}/points/count",
            self.base_url
        );
        let data = self.post_json(&url, body).await?;
        let result = data
            .get("result")
            .cloned()
            .unwrap_or(serde_json::json!({ "count": 0 }));
        Ok(serde_json::from_value(result)?)
    }

    // -- Point write operations --

    /// Upsert points.
    pub async fn upsert_points(
        &self,
        collection_name: &str,
        body: &serde_json::Value,
    ) -> QdrantResult<serde_json::Value> {
        let url = format!("{}/collections/{collection_name}/points", self.base_url);
        let data = self.put_json(&url, body).await?;
        Ok(data)
    }

    /// Delete points.
    pub async fn delete_points(
        &self,
        collection_name: &str,
        body: &serde_json::Value,
    ) -> QdrantResult<serde_json::Value> {
        let url = format!(
            "{}/collections/{collection_name}/points/delete",
            self.base_url
        );
        let data = self.post_json(&url, body).await?;
        Ok(data)
    }

    // -- HTTP helpers --

    async fn get(&self, url: &str) -> QdrantResult<serde_json::Value> {
        self.execute(|| self.http.get(url)).await
    }

    async fn post_json(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> QdrantResult<serde_json::Value> {
        self.execute(|| self.http.post(url).json(body)).await
    }

    async fn put_json(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> QdrantResult<serde_json::Value> {
        self.execute(|| self.http.put(url).json(body)).await
    }

    async fn delete(&self, url: &str) -> QdrantResult<serde_json::Value> {
        self.execute(|| self.http.delete(url)).await
    }

    async fn execute(
        &self,
        build_request: impl Fn() -> reqwest::RequestBuilder,
    ) -> QdrantResult<serde_json::Value> {
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let req = build_request();
            async move {
                debug!(attempt, "Qdrant request");
                let result = req.send().await;

                match result {
                    Ok(response) => {
                        let status = response.status();

                        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                            return AttemptOutcome::Terminal(QdrantError::Api {
                                message: "Qdrant API authentication failed".into(),
                                status_code: Some(status.as_u16()),
                            });
                        }

                        if status == StatusCode::NOT_FOUND {
                            let body = response.text().await.unwrap_or_default();
                            return AttemptOutcome::Terminal(QdrantError::Api {
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
                            return AttemptOutcome::Retryable {
                                error: QdrantError::RateLimit {
                                    retry_after_ms: retry_after,
                                },
                                retry_after: Some(Duration::from_millis(retry_after)),
                            };
                        }

                        if status.is_server_error() {
                            let body = response.text().await.unwrap_or_default();
                            return AttemptOutcome::Retryable {
                                error: QdrantError::Api {
                                    message: format!("Server error {status}: {body}"),
                                    status_code: Some(status.as_u16()),
                                },
                                retry_after: None,
                            };
                        }

                        if !status.is_success() {
                            let body = response.text().await.unwrap_or_default();
                            return AttemptOutcome::Terminal(QdrantError::Api {
                                message: format!("HTTP {status}: {body}"),
                                status_code: Some(status.as_u16()),
                            });
                        }

                        let body = match response.text().await {
                            Ok(b) => b,
                            Err(e) => return AttemptOutcome::Terminal(QdrantError::Http(e)),
                        };
                        match serde_json::from_str(&body) {
                            Ok(data) => AttemptOutcome::Success(data),
                            Err(e) => AttemptOutcome::Terminal(QdrantError::from(e)),
                        }
                    }
                    Err(e) if e.is_timeout() || e.is_connect() => AttemptOutcome::Retryable {
                        error: QdrantError::Http(e),
                        retry_after: None,
                    },
                    Err(e) => AttemptOutcome::Terminal(QdrantError::Http(e)),
                }
            }
        })
        .await
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
    async fn test_list_collections() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/collections"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "ok",
                "result": {
                    "collections": [
                        { "name": "docs" },
                        { "name": "images" }
                    ]
                },
                "time": 0.001
            })))
            .mount(&mock_server)
            .await;

        let client = QdrantClient::new("test-key", &mock_server.uri()).unwrap();

        let result = client.list_collections().await.unwrap();
        assert_eq!(result.collections.len(), 2);
        assert_eq!(result.collections[0].name, "docs");
        assert_eq!(result.collections[1].name, "images");
    }

    #[fcp_async_core::runtime::test]
    async fn test_collection_info() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/collections/docs"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "ok",
                "result": {
                    "status": "green",
                    "vectors_count": 1000,
                    "points_count": 500,
                    "segments_count": 2,
                    "config": { "params": { "vectors": { "size": 384, "distance": "Cosine" } } }
                },
                "time": 0.002
            })))
            .mount(&mock_server)
            .await;

        let client = QdrantClient::new("test-key", &mock_server.uri()).unwrap();

        let info = client.collection_info("docs").await.unwrap();
        assert_eq!(info.status, "green");
        assert_eq!(info.vectors_count, Some(1000));
        assert_eq!(info.points_count, Some(500));
    }

    #[fcp_async_core::runtime::test]
    async fn test_create_collection() {
        let mock_server = MockServer::start().await;

        Mock::given(method("PUT"))
            .and(path("/collections/docs"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "ok",
                "result": { "status": "acknowledged" },
                "time": 0.01
            })))
            .mount(&mock_server)
            .await;

        let client = QdrantClient::new("test-key", &mock_server.uri()).unwrap();

        let body = serde_json::json!({
            "vectors": { "size": 3, "distance": "Cosine" }
        });
        let result = client.create_collection("docs", &body).await.unwrap();
        assert_eq!(result["status"], "ok");
    }

    #[fcp_async_core::runtime::test]
    async fn test_delete_collection() {
        let mock_server = MockServer::start().await;

        Mock::given(method("DELETE"))
            .and(path("/collections/docs"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "ok",
                "result": { "status": "completed" },
                "time": 0.01
            })))
            .mount(&mock_server)
            .await;

        let client = QdrantClient::new("test-key", &mock_server.uri()).unwrap();
        let result = client.delete_collection("docs").await.unwrap();
        assert_eq!(result["status"], "ok");
    }

    #[fcp_async_core::runtime::test]
    async fn test_search() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/collections/docs/points/search"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "ok",
                "result": [
                    { "id": 1, "version": 1, "score": 0.95, "payload": { "text": "hello" } },
                    { "id": 2, "version": 1, "score": 0.85, "payload": { "text": "world" } }
                ],
                "time": 0.01
            })))
            .mount(&mock_server)
            .await;

        let client = QdrantClient::new("test-key", &mock_server.uri()).unwrap();

        let body = serde_json::json!({
            "vector": [0.1, 0.2, 0.3],
            "limit": 10,
            "with_payload": true
        });
        let result = client.search("docs", &body).await.unwrap();
        assert_eq!(result.len(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn test_query_points() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/collections/docs/points/query"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "ok",
                "result": {
                    "points": [
                        { "id": 1, "score": 0.92, "payload": { "text": "hello" } },
                        { "id": 2, "score": 0.88, "payload": { "text": "world" } }
                    ]
                },
                "time": 0.01
            })))
            .mount(&mock_server)
            .await;

        let client = QdrantClient::new("test-key", &mock_server.uri()).unwrap();
        let body = serde_json::json!({
            "query": [0.1, 0.2, 0.3],
            "limit": 2,
            "with_payload": true
        });
        let result = client.query_points("docs", &body).await.unwrap();
        assert_eq!(result.len(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn test_query_points_array_result() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/collections/docs/points/query"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "ok",
                "result": [
                    { "id": 11, "score": 0.91 },
                    { "id": 12, "score": 0.84 }
                ],
                "time": 0.01
            })))
            .mount(&mock_server)
            .await;

        let client = QdrantClient::new("test-key", &mock_server.uri()).unwrap();
        let body = serde_json::json!({
            "query": [0.1, 0.2, 0.3],
            "limit": 2
        });
        let result = client.query_points("docs", &body).await.unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0]["id"], 11);
    }

    #[fcp_async_core::runtime::test]
    async fn test_batch_query_points() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/collections/docs/points/query/batch"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "ok",
                "result": [
                    { "points": [{ "id": 1, "score": 0.9 }] },
                    { "points": [{ "id": 2, "score": 0.8 }] }
                ],
                "time": 0.02
            })))
            .mount(&mock_server)
            .await;

        let client = QdrantClient::new("test-key", &mock_server.uri()).unwrap();
        let queries = vec![
            serde_json::json!({ "query": [0.1, 0.2, 0.3], "limit": 1 }),
            serde_json::json!({ "query": [0.4, 0.5, 0.6], "limit": 1 }),
        ];
        let result = client.batch_query_points("docs", &queries).await.unwrap();
        assert_eq!(result.len(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_points() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/collections/docs/points"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "ok",
                "result": [
                    { "id": 1, "payload": { "text": "hello" } },
                    { "id": 2, "payload": { "text": "world" } }
                ],
                "time": 0.005
            })))
            .mount(&mock_server)
            .await;

        let client = QdrantClient::new("test-key", &mock_server.uri()).unwrap();

        let body = serde_json::json!({ "ids": [1, 2], "with_payload": true });
        let result = client.get_points("docs", &body).await.unwrap();
        assert_eq!(result.len(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn test_scroll() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/collections/docs/points/scroll"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "ok",
                "result": {
                    "points": [
                        { "id": 1, "payload": { "text": "hello" } }
                    ],
                    "next_page_offset": 2
                },
                "time": 0.003
            })))
            .mount(&mock_server)
            .await;

        let client = QdrantClient::new("test-key", &mock_server.uri()).unwrap();

        let body = serde_json::json!({ "limit": 1, "with_payload": true });
        let result = client.scroll("docs", &body).await.unwrap();
        assert_eq!(result.points.len(), 1);
        assert!(result.next_page_offset.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_count() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/collections/docs/points/count"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "ok",
                "result": { "count": 42 },
                "time": 0.001
            })))
            .mount(&mock_server)
            .await;

        let client = QdrantClient::new("test-key", &mock_server.uri()).unwrap();

        let body = serde_json::json!({ "exact": true });
        let result = client.count("docs", &body).await.unwrap();
        assert_eq!(result.count, 42);
    }

    #[fcp_async_core::runtime::test]
    async fn test_upsert_points() {
        let mock_server = MockServer::start().await;

        Mock::given(method("PUT"))
            .and(path("/collections/docs/points"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "ok",
                "result": { "operation_id": 1, "status": "completed" },
                "time": 0.05
            })))
            .mount(&mock_server)
            .await;

        let client = QdrantClient::new("test-key", &mock_server.uri()).unwrap();

        let body = serde_json::json!({
            "points": [
                { "id": 1, "vector": [0.1, 0.2, 0.3], "payload": { "text": "hello" } }
            ]
        });
        let result = client.upsert_points("docs", &body).await.unwrap();
        assert!(result.get("result").is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_delete_points() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/collections/docs/points/delete"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "ok",
                "result": { "operation_id": 2, "status": "completed" },
                "time": 0.02
            })))
            .mount(&mock_server)
            .await;

        let client = QdrantClient::new("test-key", &mock_server.uri()).unwrap();

        let body = serde_json::json!({ "points": [1, 2, 3] });
        let result = client.delete_points("docs", &body).await.unwrap();
        assert!(result.get("result").is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_unauthorized() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/collections"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&mock_server)
            .await;

        let client = QdrantClient::new("bad-key", &mock_server.uri())
            .unwrap()
            .with_retry_config(0);

        let result = client.list_collections().await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            QdrantError::Api {
                status_code: Some(401),
                ..
            }
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/collections/missing"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "status": { "error": "Not found" },
                "result": null,
                "time": 0.0
            })))
            .mount(&mock_server)
            .await;

        let client = QdrantClient::new("test-key", &mock_server.uri())
            .unwrap()
            .with_retry_config(0);

        let result = client.collection_info("missing").await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            QdrantError::Api {
                status_code: Some(404),
                ..
            }
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_rate_limited() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/collections"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "1"))
            .mount(&mock_server)
            .await;

        let client = QdrantClient::new("test-key", &mock_server.uri())
            .unwrap()
            .with_retry_config(1);

        let result = client.list_collections().await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), QdrantError::RateLimit { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invalid_json_response() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/collections"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not-json"))
            .mount(&mock_server)
            .await;

        let client = QdrantClient::new("test-key", &mock_server.uri()).unwrap();
        let result = client.list_collections().await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), QdrantError::Serialization(_)));
    }

    #[test]
    fn test_error_is_retryable() {
        let err = QdrantError::RateLimit {
            retry_after_ms: 1000,
        };
        assert!(err.is_retryable());

        let err = QdrantError::InvalidConfig {
            message: "bad config".into(),
        };
        assert!(!err.is_retryable());

        let err = QdrantError::Api {
            message: "Server error".into(),
            status_code: Some(500),
        };
        assert!(err.is_retryable());

        let err = QdrantError::Api {
            message: "Bad request".into(),
            status_code: Some(400),
        };
        assert!(!err.is_retryable());
    }
}
