//! GraphQL HTTP client implementation.

use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fcp_async_core::{sync::Mutex, time};
use futures_util::future::{BoxFuture, FutureExt, Shared};
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue, RETRY_AFTER};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tracing::debug;

use crate::error::{GraphqlClientError, GraphqlError};
use crate::operation::{
    GraphqlBatchItem, GraphqlOperation, GraphqlQuery, GraphqlRequest, GraphqlResponse,
};
use crate::retry::{RetryDecision, RetryPolicy};
use crate::schema::SchemaCache;

/// Schema validation policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SchemaValidationMode {
    /// Disable schema validation.
    #[default]
    Off,
    /// Validate response schema only.
    ResponseOnly,
    /// Validate variables and response schema.
    VariablesAndResponse,
}

type SharedRequestFuture = Shared<BoxFuture<'static, Result<Vec<u8>, GraphqlClientError>>>;

/// GraphQL client metrics.
#[derive(Debug, Default)]
#[allow(clippy::struct_field_names)]
pub struct GraphqlClientMetrics {
    requests_total: AtomicU64,
    requests_success: AtomicU64,
    requests_error: AtomicU64,
    requests_retried: AtomicU64,
}

impl GraphqlClientMetrics {
    /// Snapshot current metrics.
    #[must_use]
    pub fn snapshot(&self) -> GraphqlClientMetricsSnapshot {
        GraphqlClientMetricsSnapshot {
            requests_total: self.requests_total.load(Ordering::Relaxed),
            requests_success: self.requests_success.load(Ordering::Relaxed),
            requests_error: self.requests_error.load(Ordering::Relaxed),
            requests_retried: self.requests_retried.load(Ordering::Relaxed),
        }
    }
}

/// Metrics snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_field_names)]
pub struct GraphqlClientMetricsSnapshot {
    /// Total requests.
    pub requests_total: u64,
    /// Successful requests.
    pub requests_success: u64,
    /// Failed requests.
    pub requests_error: u64,
    /// Retries performed.
    pub requests_retried: u64,
}

#[derive(Debug, Clone)]
struct DedupState {
    inner: Arc<Mutex<HashMap<u64, SharedRequestFuture>>>,
}

impl DedupState {
    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

/// GraphQL client configuration.
#[derive(Debug, Clone)]
pub struct GraphqlClientConfig {
    /// Service name for error mapping.
    pub service_name: String,
    /// Default headers applied to every request.
    pub headers: HeaderMap,
    /// Request timeout.
    pub timeout: Duration,
    /// Retry policy.
    pub retry: RetryPolicy,
    /// Schema validation mode.
    pub validation: SchemaValidationMode,
    /// Deduplicate in-flight requests.
    pub dedup_in_flight: bool,
}

impl Default for GraphqlClientConfig {
    fn default() -> Self {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        Self {
            service_name: "graphql".to_string(),
            headers,
            timeout: Duration::from_secs(30),
            retry: RetryPolicy::default(),
            validation: SchemaValidationMode::Off,
            dedup_in_flight: false,
        }
    }
}

/// GraphQL client builder.
#[derive(Debug, Clone)]
pub struct GraphqlClientBuilder {
    endpoint: String,
    config: GraphqlClientConfig,
}

impl GraphqlClientBuilder {
    /// Create a new builder.
    #[must_use]
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            config: GraphqlClientConfig::default(),
        }
    }

    /// Set the service name for error mapping.
    #[must_use]
    pub fn with_service_name(mut self, service_name: impl Into<String>) -> Self {
        self.config.service_name = service_name.into();
        self
    }

    /// Add a header.
    #[must_use]
    pub fn with_header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.config.headers.insert(name, value);
        self
    }

    /// Add a bearer token header.
    #[must_use]
    pub fn with_bearer_token(mut self, token: impl AsRef<str>) -> Self {
        let value = format!("Bearer {}", token.as_ref());
        if let Ok(header) = HeaderValue::from_str(&value) {
            self.config
                .headers
                .insert(reqwest::header::AUTHORIZATION, header);
        }
        self
    }

    /// Set timeout.
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.config.timeout = timeout;
        self
    }

    /// Set retry policy.
    #[must_use]
    pub const fn with_retry_policy(mut self, retry: RetryPolicy) -> Self {
        self.config.retry = retry;
        self
    }

    /// Enable in-flight deduplication.
    #[must_use]
    pub const fn with_dedup_in_flight(mut self, enabled: bool) -> Self {
        self.config.dedup_in_flight = enabled;
        self
    }

    /// Set schema validation mode.
    #[must_use]
    pub const fn with_validation_mode(mut self, mode: SchemaValidationMode) -> Self {
        self.config.validation = mode;
        self
    }

    /// Build the client.
    pub fn build(self) -> Result<GraphqlClient, GraphqlClientError> {
        GraphqlClient::with_config(self.endpoint, self.config)
    }
}

/// GraphQL client.
#[derive(Debug, Clone)]
pub struct GraphqlClient {
    endpoint: String,
    http: reqwest::Client,
    config: GraphqlClientConfig,
    schema_cache: Arc<SchemaCache>,
    dedup_state: Option<DedupState>,
    metrics: Arc<GraphqlClientMetrics>,
}

impl GraphqlClient {
    /// Create a new client with default configuration.
    #[must_use]
    pub fn new(endpoint: impl Into<String>) -> Self {
        let endpoint = endpoint.into();
        let config = GraphqlClientConfig::default();
        Self::with_config(endpoint.clone(), config).unwrap_or_else(|_| {
            Self::new_with_client(
                endpoint,
                reqwest::Client::new(),
                GraphqlClientConfig::default(),
            )
        })
    }

    /// Create a client with custom configuration.
    pub fn with_config(
        endpoint: impl Into<String>,
        config: GraphqlClientConfig,
    ) -> Result<Self, GraphqlClientError> {
        let http = reqwest::Client::builder()
            .default_headers(config.headers.clone())
            .timeout(config.timeout)
            .build()?;
        Ok(Self::new_with_client(endpoint, http, config))
    }

    fn new_with_client(
        endpoint: impl Into<String>,
        http: reqwest::Client,
        config: GraphqlClientConfig,
    ) -> Self {
        let dedup_state = if config.dedup_in_flight {
            Some(DedupState::new())
        } else {
            None
        };
        Self {
            endpoint: endpoint.into(),
            http,
            config,
            schema_cache: Arc::new(SchemaCache::default()),
            dedup_state,
            metrics: Arc::new(GraphqlClientMetrics::default()),
        }
    }

    /// Return client metrics snapshot.
    #[must_use]
    pub fn metrics(&self) -> GraphqlClientMetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Execute a typed operation and return the full response.
    pub async fn execute<O: GraphqlOperation>(
        &self,
        variables: O::Variables,
    ) -> Result<GraphqlResponse<O::ResponseData>, GraphqlClientError> {
        let request = GraphqlRequest::new(GraphqlQuery::from_static(O::QUERY), variables)
            .with_operation_name(O::OPERATION_NAME);
        self.execute_request(
            request,
            O::variables_schema(),
            O::response_schema(),
            O::is_idempotent(),
        )
        .await
    }

    /// Execute a typed operation and return data only (error on GraphQL errors).
    pub async fn execute_strict<O: GraphqlOperation>(
        &self,
        variables: O::Variables,
    ) -> Result<O::ResponseData, GraphqlClientError> {
        let response = self.execute::<O>(variables).await?;
        if !response.errors.is_empty() {
            return Err(GraphqlClientError::GraphqlErrors {
                errors: response.errors,
            });
        }
        response.data.ok_or_else(|| GraphqlClientError::Protocol {
            message: "missing GraphQL data".to_string(),
        })
    }

    /// Execute an arbitrary request.
    pub async fn execute_request<V, R>(
        &self,
        request: GraphqlRequest<V>,
        variables_schema: Option<&'static str>,
        response_schema: Option<&'static str>,
        idempotent: bool,
    ) -> Result<GraphqlResponse<R>, GraphqlClientError>
    where
        V: Serialize,
        R: DeserializeOwned + Serialize,
    {
        if let (SchemaValidationMode::VariablesAndResponse, Some(schema)) =
            (self.config.validation, variables_schema)
        {
            let value = serde_json::to_value(&request.variables)?;
            self.schema_cache.validate(schema, &value)?;
        }

        let mut body_map = serde_json::Map::new();
        body_map.insert(
            "query".to_string(),
            serde_json::Value::String(request.query.as_str().to_string()),
        );
        body_map.insert(
            "variables".to_string(),
            serde_json::to_value(&request.variables)?,
        );
        if let Some(operation_name) = request.operation_name {
            body_map.insert(
                "operationName".to_string(),
                serde_json::Value::String(operation_name),
            );
        }
        let body = serde_json::Value::Object(body_map);

        let bytes = self.execute_bytes(body, idempotent).await?;
        let response: GraphqlResponse<R> = serde_json::from_slice(&bytes)?;

        if let (
            SchemaValidationMode::VariablesAndResponse | SchemaValidationMode::ResponseOnly,
            Some(schema),
        ) = (self.config.validation, response_schema)
        {
            if let Some(ref data) = response.data {
                let value = serde_json::to_value(data)?;
                self.schema_cache.validate(schema, &value)?;
            }
        }

        if response.errors.is_empty() {
            self.metrics
                .requests_success
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.metrics.requests_error.fetch_add(1, Ordering::Relaxed);
        }

        Ok(response)
    }

    /// Execute a batch of identical typed operations.
    pub async fn execute_batch<O: GraphqlOperation>(
        &self,
        variables: Vec<O::Variables>,
    ) -> Result<Vec<GraphqlResponse<O::ResponseData>>, GraphqlClientError> {
        let items: Vec<GraphqlBatchItem<O::Variables>> = variables
            .into_iter()
            .map(|vars| {
                GraphqlBatchItem::new(GraphqlQuery::from_static(O::QUERY), vars)
                    .with_operation_name(O::OPERATION_NAME)
            })
            .collect();
        self.execute_batch_request(
            items,
            O::variables_schema(),
            O::response_schema(),
            O::is_idempotent(),
        )
        .await
    }

    /// Execute a batch request with shared schemas.
    pub async fn execute_batch_request<V, R>(
        &self,
        items: Vec<GraphqlBatchItem<V>>,
        variables_schema: Option<&'static str>,
        response_schema: Option<&'static str>,
        idempotent: bool,
    ) -> Result<Vec<GraphqlResponse<R>>, GraphqlClientError>
    where
        V: Serialize,
        R: DeserializeOwned + Serialize,
    {
        if let (SchemaValidationMode::VariablesAndResponse, Some(schema)) =
            (self.config.validation, variables_schema)
        {
            for item in &items {
                let value = serde_json::to_value(&item.variables)?;
                self.schema_cache.validate(schema, &value)?;
            }
        }

        let body = serde_json::to_value(&items)?;
        let bytes = self.execute_bytes(body, idempotent).await?;
        let response: Vec<GraphqlResponse<R>> = serde_json::from_slice(&bytes)?;

        if let (
            SchemaValidationMode::VariablesAndResponse | SchemaValidationMode::ResponseOnly,
            Some(schema),
        ) = (self.config.validation, response_schema)
        {
            for item in &response {
                if let Some(ref data) = item.data {
                    let value = serde_json::to_value(data)?;
                    self.schema_cache.validate(schema, &value)?;
                }
            }
        }

        if response.iter().all(|item| item.errors.is_empty()) {
            self.metrics
                .requests_success
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.metrics.requests_error.fetch_add(1, Ordering::Relaxed);
        }

        Ok(response)
    }

    async fn execute_bytes(
        &self,
        body: serde_json::Value,
        idempotent: bool,
    ) -> Result<Vec<u8>, GraphqlClientError> {
        let body_bytes = serde_json::to_vec(&body)?;
        self.metrics.requests_total.fetch_add(1, Ordering::Relaxed);

        if let Some(state) = &self.dedup_state {
            let key = hash_bytes(&body_bytes);
            let mut guard = state.inner.lock().await;
            if let Some(shared) = guard.get(&key).cloned() {
                drop(guard);
                return shared.await;
            }

            let client = self.clone();
            let payload = body_bytes.clone();
            let future = async move { client.send_with_retry(payload, idempotent).await }
                .boxed()
                .shared();
            guard.insert(key, future.clone());
            drop(guard);

            let result = future.await;
            state.inner.lock().await.remove(&key);
            return result;
        }

        self.send_with_retry(body_bytes, idempotent).await
    }

    async fn send_with_retry(
        &self,
        body_bytes: Vec<u8>,
        idempotent: bool,
    ) -> Result<Vec<u8>, GraphqlClientError> {
        let mut attempt = 1;
        loop {
            let result = self.send_once(&body_bytes).await;
            match result {
                Ok(bytes) => return Ok(bytes),
                Err(err) => {
                    let decision = self.config.retry.decide(&err, attempt, idempotent);
                    match decision {
                        RetryDecision::RetryAfter(delay) => {
                            self.metrics
                                .requests_retried
                                .fetch_add(1, Ordering::Relaxed);
                            debug!("retrying GraphQL request after {:?}", delay);
                            time::sleep(delay).await;
                            attempt += 1;
                        }
                        RetryDecision::DoNotRetry => return Err(err),
                    }
                }
            }
        }
    }

    async fn send_once(&self, body_bytes: &[u8]) -> Result<Vec<u8>, GraphqlClientError> {
        let response = self
            .http
            .post(&self.endpoint)
            .body(body_bytes.to_vec())
            .send()
            .await?;

        let status = response.status();
        let retry_after = parse_retry_after(response.headers());
        let bytes = response.bytes().await?;

        if !status.is_success() {
            let body = truncate_body(&bytes);
            self.metrics.requests_error.fetch_add(1, Ordering::Relaxed);
            return Err(GraphqlClientError::HttpStatus {
                status,
                body,
                retry_after,
            });
        }

        Ok(bytes.to_vec())
    }
}

fn parse_retry_after(headers: &HeaderMap) -> Option<Duration> {
    let header = headers.get(RETRY_AFTER)?;
    let value = header.to_str().ok()?;
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }
    None
}

fn truncate_body(bytes: &[u8]) -> String {
    const MAX_LEN: usize = 4096;
    let mut body = String::from_utf8_lossy(bytes).to_string();
    if body.len() > MAX_LEN {
        body.truncate(MAX_LEN);
        body.push('…');
    }
    body
}

fn hash_bytes(bytes: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    bytes.hash(&mut hasher);
    hasher.finish()
}

impl GraphqlClient {
    /// Convert GraphQL errors to a client error.
    #[allow(clippy::missing_const_for_fn)]
    pub fn graphql_errors(errors: Vec<GraphqlError>) -> GraphqlClientError {
        GraphqlClientError::GraphqlErrors { errors }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue};
    use std::time::Duration;

    // ---- SchemaValidationMode ----

    #[test]
    fn schema_validation_mode_default_is_off() {
        assert_eq!(SchemaValidationMode::default(), SchemaValidationMode::Off);
    }

    #[test]
    fn schema_validation_mode_eq() {
        assert_eq!(
            SchemaValidationMode::ResponseOnly,
            SchemaValidationMode::ResponseOnly
        );
        assert_ne!(SchemaValidationMode::Off, SchemaValidationMode::ResponseOnly);
        assert_ne!(
            SchemaValidationMode::ResponseOnly,
            SchemaValidationMode::VariablesAndResponse
        );
    }

    #[test]
    fn schema_validation_mode_debug() {
        let dbg = format!("{:?}", SchemaValidationMode::VariablesAndResponse);
        assert!(dbg.contains("VariablesAndResponse"));
    }

    #[test]
    fn schema_validation_mode_clone_copy() {
        let mode = SchemaValidationMode::ResponseOnly;
        let cloned = mode;
        assert_eq!(mode, cloned);
    }

    // ---- GraphqlClientMetrics ----

    #[test]
    fn metrics_default_all_zero() {
        let metrics = GraphqlClientMetrics::default();
        let snap = metrics.snapshot();
        assert_eq!(snap.requests_total, 0);
        assert_eq!(snap.requests_success, 0);
        assert_eq!(snap.requests_error, 0);
        assert_eq!(snap.requests_retried, 0);
    }

    #[test]
    fn metrics_snapshot_reflects_increments() {
        let metrics = GraphqlClientMetrics::default();
        metrics.requests_total.fetch_add(5, Ordering::Relaxed);
        metrics.requests_success.fetch_add(3, Ordering::Relaxed);
        metrics.requests_error.fetch_add(1, Ordering::Relaxed);
        metrics.requests_retried.fetch_add(2, Ordering::Relaxed);
        let snap = metrics.snapshot();
        assert_eq!(snap.requests_total, 5);
        assert_eq!(snap.requests_success, 3);
        assert_eq!(snap.requests_error, 1);
        assert_eq!(snap.requests_retried, 2);
    }

    #[test]
    fn metrics_snapshot_eq() {
        let a = GraphqlClientMetricsSnapshot {
            requests_total: 10,
            requests_success: 8,
            requests_error: 2,
            requests_retried: 1,
        };
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn metrics_snapshot_debug() {
        let snap = GraphqlClientMetricsSnapshot {
            requests_total: 1,
            requests_success: 1,
            requests_error: 0,
            requests_retried: 0,
        };
        let dbg = format!("{snap:?}");
        assert!(dbg.contains("requests_total"));
        assert!(dbg.contains("requests_success"));
    }

    // ---- GraphqlClientConfig ----

    #[test]
    fn config_default_values() {
        let config = GraphqlClientConfig::default();
        assert_eq!(config.service_name, "graphql");
        assert_eq!(config.timeout, Duration::from_secs(30));
        assert_eq!(config.validation, SchemaValidationMode::Off);
        assert!(!config.dedup_in_flight);
        assert_eq!(
            config.headers.get(CONTENT_TYPE),
            Some(&HeaderValue::from_static("application/json"))
        );
    }

    #[test]
    fn config_debug() {
        let config = GraphqlClientConfig::default();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("graphql"));
    }

    // ---- GraphqlClientBuilder ----

    #[test]
    fn builder_new_defaults() {
        let builder = GraphqlClientBuilder::new("https://api.example.com/graphql");
        assert_eq!(builder.endpoint, "https://api.example.com/graphql");
        assert_eq!(builder.config.service_name, "graphql");
    }

    #[test]
    fn builder_with_service_name() {
        let builder = GraphqlClientBuilder::new("https://api.test.com/graphql")
            .with_service_name("github");
        assert_eq!(builder.config.service_name, "github");
    }

    #[test]
    fn builder_with_header() {
        let builder = GraphqlClientBuilder::new("https://api.test.com/graphql").with_header(
            HeaderName::from_static("x-custom"),
            HeaderValue::from_static("value"),
        );
        assert_eq!(
            builder.config.headers.get("x-custom"),
            Some(&HeaderValue::from_static("value"))
        );
    }

    #[test]
    fn builder_with_bearer_token() {
        let builder = GraphqlClientBuilder::new("https://api.test.com/graphql")
            .with_bearer_token("tok_abc123");
        let auth = builder.config.headers.get(AUTHORIZATION).unwrap();
        assert_eq!(auth.to_str().unwrap(), "Bearer tok_abc123");
    }

    #[test]
    fn builder_with_timeout() {
        let builder = GraphqlClientBuilder::new("https://api.test.com/graphql")
            .with_timeout(Duration::from_secs(60));
        assert_eq!(builder.config.timeout, Duration::from_secs(60));
    }

    #[test]
    fn builder_with_retry_policy() {
        let policy = RetryPolicy {
            max_attempts: 5,
            ..RetryPolicy::default()
        };
        let builder = GraphqlClientBuilder::new("https://api.test.com/graphql")
            .with_retry_policy(policy);
        assert_eq!(builder.config.retry.max_attempts, 5);
    }

    #[test]
    fn builder_with_dedup_in_flight() {
        let builder = GraphqlClientBuilder::new("https://api.test.com/graphql")
            .with_dedup_in_flight(true);
        assert!(builder.config.dedup_in_flight);
    }

    #[test]
    fn builder_with_validation_mode() {
        let builder = GraphqlClientBuilder::new("https://api.test.com/graphql")
            .with_validation_mode(SchemaValidationMode::VariablesAndResponse);
        assert_eq!(
            builder.config.validation,
            SchemaValidationMode::VariablesAndResponse
        );
    }

    #[test]
    fn builder_chaining() {
        let builder = GraphqlClientBuilder::new("https://api.test.com/graphql")
            .with_service_name("github")
            .with_bearer_token("token")
            .with_timeout(Duration::from_secs(10))
            .with_dedup_in_flight(true)
            .with_validation_mode(SchemaValidationMode::ResponseOnly);
        assert_eq!(builder.config.service_name, "github");
        assert_eq!(builder.config.timeout, Duration::from_secs(10));
        assert!(builder.config.dedup_in_flight);
        assert_eq!(
            builder.config.validation,
            SchemaValidationMode::ResponseOnly
        );
    }

    #[test]
    fn builder_build_succeeds() {
        let client = GraphqlClientBuilder::new("https://api.test.com/graphql")
            .with_service_name("test")
            .build();
        assert!(client.is_ok());
    }

    // ---- GraphqlClient ----

    #[test]
    fn client_new_defaults() {
        let client = GraphqlClient::new("https://api.test.com/graphql");
        assert_eq!(client.endpoint, "https://api.test.com/graphql");
        let snap = client.metrics();
        assert_eq!(snap.requests_total, 0);
    }

    #[test]
    fn client_with_config_succeeds() {
        let config = GraphqlClientConfig::default();
        let client = GraphqlClient::with_config("https://api.test.com/graphql", config);
        assert!(client.is_ok());
    }

    #[test]
    fn client_dedup_state_none_by_default() {
        let client = GraphqlClient::new("https://api.test.com/graphql");
        assert!(client.dedup_state.is_none());
    }

    #[test]
    fn client_dedup_state_some_when_enabled() {
        let config = GraphqlClientConfig {
            dedup_in_flight: true,
            ..GraphqlClientConfig::default()
        };
        let client = GraphqlClient::with_config("https://api.test.com/graphql", config).unwrap();
        assert!(client.dedup_state.is_some());
    }

    #[test]
    fn client_metrics_initial_snapshot() {
        let client = GraphqlClient::new("https://api.test.com/graphql");
        let snap = client.metrics();
        assert_eq!(
            snap,
            GraphqlClientMetricsSnapshot {
                requests_total: 0,
                requests_success: 0,
                requests_error: 0,
                requests_retried: 0,
            }
        );
    }

    #[test]
    fn client_graphql_errors_helper() {
        let errors = vec![GraphqlError {
            message: "not found".into(),
            locations: vec![],
            path: vec![],
            extensions: None,
        }];
        let err = GraphqlClient::graphql_errors(errors);
        match err {
            GraphqlClientError::GraphqlErrors { errors } => {
                assert_eq!(errors.len(), 1);
                assert_eq!(errors[0].message, "not found");
            }
            other => panic!("expected GraphqlErrors, got {other:?}"),
        }
    }

    #[test]
    fn client_graphql_errors_empty() {
        let err = GraphqlClient::graphql_errors(vec![]);
        match err {
            GraphqlClientError::GraphqlErrors { errors } => {
                assert!(errors.is_empty());
            }
            other => panic!("expected GraphqlErrors, got {other:?}"),
        }
    }

    #[test]
    fn client_clone() {
        let client = GraphqlClient::new("https://api.test.com/graphql");
        let cloned = client.clone();
        assert_eq!(cloned.endpoint, client.endpoint);
    }

    #[test]
    fn client_debug() {
        let client = GraphqlClient::new("https://api.test.com/graphql");
        let dbg = format!("{client:?}");
        assert!(dbg.contains("GraphqlClient"));
        assert!(dbg.contains("api.test.com"));
    }

    // ---- parse_retry_after ----

    #[test]
    fn parse_retry_after_with_seconds() {
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, HeaderValue::from_static("30"));
        assert_eq!(parse_retry_after(&headers), Some(Duration::from_secs(30)));
    }

    #[test]
    fn parse_retry_after_missing_header() {
        let headers = HeaderMap::new();
        assert_eq!(parse_retry_after(&headers), None);
    }

    #[test]
    fn parse_retry_after_non_numeric() {
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, HeaderValue::from_static("not-a-number"));
        assert_eq!(parse_retry_after(&headers), None);
    }

    #[test]
    fn parse_retry_after_zero() {
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, HeaderValue::from_static("0"));
        assert_eq!(parse_retry_after(&headers), Some(Duration::from_secs(0)));
    }

    // ---- truncate_body ----

    #[test]
    fn truncate_body_short_string() {
        let short = b"hello world";
        assert_eq!(truncate_body(short), "hello world");
    }

    #[test]
    fn truncate_body_exactly_4096() {
        let body = vec![b'x'; 4096];
        let result = truncate_body(&body);
        assert_eq!(result.len(), 4096);
        assert!(!result.ends_with('…'));
    }

    #[test]
    fn truncate_body_exceeds_4096() {
        let body = vec![b'x'; 5000];
        let result = truncate_body(&body);
        assert!(result.len() <= 4100); // 4096 + ellipsis
        assert!(result.ends_with('…'));
    }

    #[test]
    fn truncate_body_invalid_utf8() {
        let body = vec![0xFF, 0xFE, 0xFD];
        let result = truncate_body(&body);
        assert!(!result.is_empty()); // from_utf8_lossy replaces invalid bytes
    }

    #[test]
    fn truncate_body_empty() {
        let result = truncate_body(b"");
        assert!(result.is_empty());
    }

    // ---- hash_bytes ----

    #[test]
    fn hash_bytes_deterministic() {
        let data = b"test payload";
        assert_eq!(hash_bytes(data), hash_bytes(data));
    }

    #[test]
    fn hash_bytes_different_input_different_hash() {
        assert_ne!(hash_bytes(b"hello"), hash_bytes(b"world"));
    }

    #[test]
    fn hash_bytes_empty() {
        let _ = hash_bytes(b""); // should not panic
    }
}
