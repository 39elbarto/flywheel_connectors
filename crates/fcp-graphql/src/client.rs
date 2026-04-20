//! GraphQL HTTP client implementation.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fcp_async_core::http::{HttpClient, HttpClientBuilder, Method};
use fcp_async_core::{AsyncError, sync::Mutex, task, time};
use futures_util::future::{BoxFuture, FutureExt, Shared};
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
type HeaderList = Vec<(String, String)>;

const AUTHORIZATION_HEADER: &str = "Authorization";
const CONTENT_TYPE_HEADER: &str = "Content-Type";
const JSON_CONTENT_TYPE: &str = "application/json";
const RETRY_AFTER_HEADER: &str = "Retry-After";

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

/// In-flight dedup keyed on the request body bytes.
///
/// Previously keyed on a `u64` `DefaultHasher` (SipHash) output —
/// collision-prone in principle (two distinct bodies hashing to the
/// same `u64` would be merged into one in-flight entry, serving the
/// second caller the response intended for the first). Adversarial
/// collisions only need knowledge of the hasher seed and `DefaultHasher`
/// is not HashDoS-resistant (br-flywheel_connectors-upp69).
///
/// Using the raw body bytes as the key makes the dedup map
/// collision-free: key equality is byte-for-byte request equality.
/// The memory cost is one additional `Vec<u8>` per in-flight entry,
/// bounded by concurrency and released by [`DedupGuard::drop`].
#[derive(Debug, Clone)]
struct DedupState {
    inner: Arc<Mutex<HashMap<Vec<u8>, SharedRequestFuture>>>,
}

impl DedupState {
    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

/// RAII guard that removes a dedup entry from the map when the owning
/// caller exits — whether via normal return, cancellation (the outer
/// future being dropped mid-`await`), or panic. Without this, a cancelled
/// owner leaves the map entry resident forever, so every subsequent
/// same-body caller hits the cached (stale) result and the map grows
/// monotonically with unique cancelled-request bodies.
struct DedupGuard {
    state: DedupState,
    key: Vec<u8>,
}

impl Drop for DedupGuard {
    fn drop(&mut self) {
        // Common case: the lock is uncontended because the owner has
        // already finished its `shared.await` and no other caller is
        // mutating the map at this instant — remove synchronously.
        if let Ok(mut inner) = self.state.inner.try_lock() {
            inner.remove(&self.key);
            return;
        }

        // Contended case: defer to a short spawned task so Drop stays
        // synchronous. The task captures `state` + `key` by move; it
        // cannot outlive the Arc because DedupState holds an Arc to the
        // map. `mem::take` is fine here: we're in Drop and the key slot
        // will never be read again.
        let state = self.state.clone();
        let key = std::mem::take(&mut self.key);
        task::spawn(async move {
            state.inner.lock().await.remove(&key);
        });
    }
}

fn upsert_header(headers: &mut HeaderList, name: impl Into<String>, value: impl Into<String>) {
    let name = name.into();
    let value = value.into();
    if let Some((_, existing_value)) = headers
        .iter_mut()
        .find(|(existing_name, _)| existing_name.eq_ignore_ascii_case(&name))
    {
        *existing_value = value;
    } else {
        headers.push((name, value));
    }
}

fn header_value<'a>(headers: &'a HeaderList, name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn is_sensitive_header_name(name: &str) -> bool {
    let normalized = name.to_ascii_lowercase().replace('_', "-");
    matches!(
        normalized.as_str(),
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "set-cookie"
            | "x-api-key"
            | "api-key"
            | "x-auth-token"
            | "x-access-token"
            | "x-refresh-token"
    ) || normalized.contains("token")
        || normalized.contains("apikey")
        || normalized.contains("secret")
        || normalized.ends_with("-key")
}

/// GraphQL client configuration.
#[derive(Clone)]
pub struct GraphqlClientConfig {
    /// Service name for error mapping.
    pub service_name: String,
    /// Default headers applied to every request.
    pub headers: HeaderList,
    /// Request timeout.
    pub timeout: Duration,
    /// Retry policy.
    pub retry: RetryPolicy,
    /// Schema validation mode.
    pub validation: SchemaValidationMode,
    /// Deduplicate in-flight requests.
    pub dedup_in_flight: bool,
}

impl fmt::Debug for GraphqlClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redact secret-bearing headers to prevent credential leaks in logs.
        let safe_headers: Vec<(&str, &str)> = self
            .headers
            .iter()
            .map(|(k, v)| {
                if is_sensitive_header_name(k) {
                    (k.as_str(), "[REDACTED]")
                } else {
                    (k.as_str(), v.as_str())
                }
            })
            .collect();
        f.debug_struct("GraphqlClientConfig")
            .field("service_name", &self.service_name)
            .field("headers", &safe_headers)
            .field("timeout", &self.timeout)
            .field("retry", &self.retry)
            .field("validation", &self.validation)
            .field("dedup_in_flight", &self.dedup_in_flight)
            .finish()
    }
}

impl Default for GraphqlClientConfig {
    fn default() -> Self {
        let mut headers = HeaderList::new();
        upsert_header(&mut headers, CONTENT_TYPE_HEADER, JSON_CONTENT_TYPE);
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
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        upsert_header(&mut self.config.headers, name, value);
        self
    }

    /// Add a bearer token header.
    #[must_use]
    pub fn with_bearer_token(mut self, token: impl AsRef<str>) -> Self {
        upsert_header(
            &mut self.config.headers,
            AUTHORIZATION_HEADER,
            format!("Bearer {}", token.as_ref()),
        );
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
pub struct GraphqlClient {
    endpoint: String,
    http: Arc<HttpClient>,
    config: GraphqlClientConfig,
    schema_cache: Arc<SchemaCache>,
    dedup_state: Option<DedupState>,
    metrics: Arc<GraphqlClientMetrics>,
}

impl Clone for GraphqlClient {
    fn clone(&self) -> Self {
        Self {
            endpoint: self.endpoint.clone(),
            http: Arc::clone(&self.http),
            config: self.config.clone(),
            schema_cache: Arc::clone(&self.schema_cache),
            dedup_state: self.dedup_state.clone(),
            metrics: Arc::clone(&self.metrics),
        }
    }
}

impl fmt::Debug for GraphqlClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GraphqlClient")
            .field("endpoint", &self.endpoint)
            .field("config", &self.config)
            .field("dedup_in_flight", &self.dedup_state.is_some())
            .field("metrics", &self.metrics.snapshot())
            .finish_non_exhaustive()
    }
}

impl GraphqlClient {
    /// Create a new client with default configuration.
    #[must_use]
    pub fn new(endpoint: impl Into<String>) -> Self {
        let endpoint = endpoint.into();
        let config = GraphqlClientConfig::default();
        Self::new_with_client(endpoint, Arc::new(HttpClientBuilder::new().build()), config)
    }

    /// Create a client with custom configuration.
    pub fn with_config(
        endpoint: impl Into<String>,
        config: GraphqlClientConfig,
    ) -> Result<Self, GraphqlClientError> {
        Ok(Self::new_with_client(
            endpoint,
            Arc::new(HttpClientBuilder::new().build()),
            config,
        ))
    }

    fn new_with_client(
        endpoint: impl Into<String>,
        http: Arc<HttpClient>,
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
            // Key on the raw body bytes — collision-free. See DedupState
            // docs for the rationale vs. the prior u64 SipHash key.
            let mut guard = state.inner.lock().await;
            if let Some(shared) = guard.get(&body_bytes).cloned() {
                drop(guard);
                return shared.await;
            }

            let client = self.clone();
            let payload = body_bytes.clone();
            let future = async move { client.send_with_retry(payload, idempotent).await }
                .boxed()
                .shared();
            guard.insert(body_bytes.clone(), future.clone());
            drop(guard);

            // The cleanup guard removes our entry from the dedup map no
            // matter how we exit this scope: return, cancellation, or
            // panic. Previously the explicit `remove` after `future.await`
            // only fired on normal completion, so a cancelled owner
            // leaked the entry and future duplicates saw a stale cached
            // Shared<> indefinitely.
            let _cleanup = DedupGuard {
                state: state.clone(),
                key: body_bytes,
            };
            return future.await;
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
        let cx = fcp_async_core::compatibility_cx();
        let response = match time::timeout(
            self.config.timeout,
            self.http.request(
                &cx,
                Method::Post,
                &self.endpoint,
                self.config.headers.clone(),
                body_bytes.to_vec(),
            ),
        )
        .await
        {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => return Err(error.into()),
            Err(async_error) => {
                return Err(map_request_async_error(async_error, self.config.timeout));
            }
        };

        let status = response.status_code();
        let retry_after = parse_retry_after(&response.headers);
        let bytes = response.body;

        if !status.is_success() {
            let body = truncate_body(&bytes);
            self.metrics.requests_error.fetch_add(1, Ordering::Relaxed);
            return Err(GraphqlClientError::HttpStatus {
                status,
                body,
                retry_after,
            });
        }

        Ok(bytes)
    }
}

fn map_request_async_error(error: AsyncError, timeout: Duration) -> GraphqlClientError {
    match error {
        AsyncError::Timeout { .. } => {
            GraphqlClientError::Http(crate::error::HttpErrorInfo::timeout(timeout))
        }
        AsyncError::Cancelled => GraphqlClientError::Http(crate::error::HttpErrorInfo::cancelled()),
        AsyncError::ProtocolIo { message }
        | AsyncError::Join { message }
        | AsyncError::Runtime { message } => GraphqlClientError::Protocol { message },
        AsyncError::ChannelClosed => GraphqlClientError::Protocol {
            message: "HTTP request channel closed".to_string(),
        },
        AsyncError::ChannelFull => GraphqlClientError::Protocol {
            message: "HTTP request channel full".to_string(),
        },
    }
}

fn parse_retry_after(headers: &HeaderList) -> Option<Duration> {
    let value = header_value(headers, RETRY_AFTER_HEADER)?;
    value.parse::<u64>().ok().map(Duration::from_secs)
}

fn truncate_body(bytes: &[u8]) -> String {
    const MAX_LEN: usize = 4096;
    // Truncate at the byte level BEFORE converting to UTF-8 to avoid
    // allocating arbitrarily large strings from malicious responses.
    // Add 4 bytes of headroom for multi-byte char boundary alignment.
    let slice = if bytes.len() > MAX_LEN + 4 {
        &bytes[..MAX_LEN + 4]
    } else {
        bytes
    };
    let mut body = String::from_utf8_lossy(slice).to_string();
    if body.len() > MAX_LEN {
        // Find a valid UTF-8 char boundary at or before MAX_LEN
        let mut end = MAX_LEN;
        while !body.is_char_boundary(end) {
            end -= 1;
        }
        body.truncate(end);
        body.push('…');
    }
    body
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
        assert_ne!(
            SchemaValidationMode::Off,
            SchemaValidationMode::ResponseOnly
        );
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
            header_value(&config.headers, CONTENT_TYPE_HEADER),
            Some(JSON_CONTENT_TYPE)
        );
    }

    #[test]
    fn config_debug() {
        let config = GraphqlClientConfig {
            headers: vec![
                (
                    AUTHORIZATION_HEADER.to_string(),
                    "Bearer top-secret".to_string(),
                ),
                ("Cookie".to_string(), "session=abc123".to_string()),
                ("X-Api-Key".to_string(), "key-123".to_string()),
                ("X-Request-Id".to_string(), "req-42".to_string()),
            ],
            ..GraphqlClientConfig::default()
        };
        let dbg = format!("{config:?}");
        assert!(dbg.contains("graphql"));
        assert!(dbg.contains("[REDACTED]"));
        assert!(dbg.contains("X-Request-Id"));
        assert!(dbg.contains("req-42"));
        assert!(!dbg.contains("top-secret"));
        assert!(!dbg.contains("session=abc123"));
        assert!(!dbg.contains("key-123"));
    }

    #[test]
    fn config_debug_redacts_compact_api_key_spellings() {
        let config = GraphqlClientConfig {
            headers: vec![
                ("ApiKey".to_string(), "compact-secret".to_string()),
                ("X-ApiKey".to_string(), "prefixed-secret".to_string()),
                ("X-Request-Id".to_string(), "req-77".to_string()),
            ],
            ..GraphqlClientConfig::default()
        };

        let dbg = format!("{config:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(dbg.contains("X-Request-Id"));
        assert!(dbg.contains("req-77"));
        assert!(!dbg.contains("compact-secret"));
        assert!(!dbg.contains("prefixed-secret"));
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
        let builder =
            GraphqlClientBuilder::new("https://api.test.com/graphql").with_service_name("github");
        assert_eq!(builder.config.service_name, "github");
    }

    #[test]
    fn builder_with_header() {
        let builder = GraphqlClientBuilder::new("https://api.test.com/graphql")
            .with_header("x-custom", "value");
        assert_eq!(
            header_value(&builder.config.headers, "x-custom"),
            Some("value")
        );
    }

    #[test]
    fn builder_with_bearer_token() {
        let builder = GraphqlClientBuilder::new("https://api.test.com/graphql")
            .with_bearer_token("tok_abc123");
        assert_eq!(
            header_value(&builder.config.headers, AUTHORIZATION_HEADER),
            Some("Bearer tok_abc123")
        );
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
        let builder =
            GraphqlClientBuilder::new("https://api.test.com/graphql").with_retry_policy(policy);
        assert_eq!(builder.config.retry.max_attempts, 5);
    }

    #[test]
    fn builder_with_dedup_in_flight() {
        let builder =
            GraphqlClientBuilder::new("https://api.test.com/graphql").with_dedup_in_flight(true);
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
        let headers = vec![(RETRY_AFTER_HEADER.to_string(), "30".to_string())];
        assert_eq!(parse_retry_after(&headers), Some(Duration::from_secs(30)));
    }

    #[test]
    fn parse_retry_after_missing_header() {
        let headers = Vec::new();
        assert_eq!(parse_retry_after(&headers), None);
    }

    #[test]
    fn parse_retry_after_non_numeric() {
        let headers = vec![(RETRY_AFTER_HEADER.to_string(), "not-a-number".to_string())];
        assert_eq!(parse_retry_after(&headers), None);
    }

    #[test]
    fn parse_retry_after_zero() {
        let headers = vec![(RETRY_AFTER_HEADER.to_string(), "0".to_string())];
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

    // ---- additional edge case tests ----

    #[test]
    fn truncate_body_multibyte_utf8_at_boundary() {
        // Place a multi-byte UTF-8 char (emoji = 4 bytes) straddling the 4096 boundary
        let mut body = vec![b'x'; 4094];
        // Append a 4-byte UTF-8 char: 🦀 = F0 9F A6 80
        body.extend_from_slice("🦀".as_bytes());
        assert_eq!(body.len(), 4098);
        let result = truncate_body(&body);
        // Should truncate before the emoji to maintain valid UTF-8
        assert!(result.ends_with('…'));
        // The truncated string must be valid UTF-8 (from_utf8_lossy guarantees this,
        // but the truncation must find a char boundary)
        assert!(result.len() <= 4097); // 4094 'x' + ellipsis (3 bytes)
    }

    #[test]
    fn truncate_body_multibyte_utf8_two_byte_at_boundary() {
        // Place a 2-byte UTF-8 char (é = C3 A9) so it straddles 4096
        let mut body = vec![b'x'; 4095];
        body.extend_from_slice("é".as_bytes()); // 2 bytes
        assert_eq!(body.len(), 4097);
        let result = truncate_body(&body);
        assert!(result.ends_with('…'));
    }

    #[test]
    fn parse_retry_after_large_value() {
        let headers = vec![(RETRY_AFTER_HEADER.to_string(), "3600".to_string())];
        assert_eq!(parse_retry_after(&headers), Some(Duration::from_secs(3600)));
    }

    #[test]
    fn parse_retry_after_empty_string() {
        let headers = vec![(RETRY_AFTER_HEADER.to_string(), String::new())];
        assert_eq!(parse_retry_after(&headers), None);
    }

    #[test]
    fn builder_debug_contains_endpoint() {
        let builder = GraphqlClientBuilder::new("https://api.test.com/graphql");
        let dbg = format!("{builder:?}");
        assert!(dbg.contains("api.test.com"));
        assert!(dbg.contains("GraphqlClientBuilder"));
    }

    #[test]
    fn config_clone_preserves_all_fields() {
        let config = GraphqlClientConfig {
            service_name: "custom".to_string(),
            timeout: Duration::from_secs(99),
            dedup_in_flight: true,
            validation: SchemaValidationMode::ResponseOnly,
            ..GraphqlClientConfig::default()
        };
        let cloned = config.clone();
        assert_eq!(config.service_name, cloned.service_name);
        assert_eq!(config.timeout, cloned.timeout);
        assert_eq!(config.dedup_in_flight, cloned.dedup_in_flight);
        assert_eq!(config.validation, cloned.validation);
        assert_eq!(cloned.service_name, "custom");
        assert_eq!(cloned.timeout, Duration::from_secs(99));
        assert!(cloned.dedup_in_flight);
        assert_eq!(cloned.validation, SchemaValidationMode::ResponseOnly);
    }

    #[test]
    fn metrics_snapshot_clone() {
        let snap = GraphqlClientMetricsSnapshot {
            requests_total: 10,
            requests_success: 8,
            requests_error: 2,
            requests_retried: 1,
        };
        let cloned = snap;
        assert_eq!(snap, cloned);
    }

    #[test]
    fn builder_with_empty_bearer_token() {
        let builder =
            GraphqlClientBuilder::new("https://api.test.com/graphql").with_bearer_token("");
        assert_eq!(
            header_value(&builder.config.headers, AUTHORIZATION_HEADER),
            Some("Bearer ")
        );
    }

    #[test]
    fn client_with_dedup_config_produces_some_dedup_state() {
        let client = GraphqlClientBuilder::new("https://api.test.com/graphql")
            .with_dedup_in_flight(true)
            .build()
            .unwrap();
        assert!(client.dedup_state.is_some());
    }

    #[test]
    fn client_graphql_errors_multiple() {
        let errors = vec![
            GraphqlError {
                message: "error 1".into(),
                locations: vec![],
                path: vec![],
                extensions: None,
            },
            GraphqlError {
                message: "error 2".into(),
                locations: vec![],
                path: vec![],
                extensions: None,
            },
        ];
        let err = GraphqlClient::graphql_errors(errors);
        match err {
            GraphqlClientError::GraphqlErrors { errors } => {
                assert_eq!(errors.len(), 2);
            }
            other => panic!("expected GraphqlErrors, got {other:?}"),
        }
    }

    // ---- upsert_header ----

    #[test]
    fn upsert_header_inserts_new() {
        let mut headers: HeaderList = Vec::new();
        upsert_header(&mut headers, "X-Custom", "value1");
        assert_eq!(headers.len(), 1);
        assert_eq!(header_value(&headers, "X-Custom"), Some("value1"));
    }

    #[test]
    fn upsert_header_replaces_existing() {
        let mut headers: HeaderList = Vec::new();
        upsert_header(&mut headers, "X-Custom", "old");
        upsert_header(&mut headers, "X-Custom", "new");
        assert_eq!(headers.len(), 1);
        assert_eq!(header_value(&headers, "X-Custom"), Some("new"));
    }

    #[test]
    fn upsert_header_case_insensitive() {
        let mut headers: HeaderList = Vec::new();
        upsert_header(&mut headers, "Content-Type", "text/plain");
        upsert_header(&mut headers, "content-type", "application/json");
        assert_eq!(headers.len(), 1);
        assert_eq!(
            header_value(&headers, "Content-Type"),
            Some("application/json")
        );
    }

    #[test]
    fn upsert_header_multiple_different_headers() {
        let mut headers: HeaderList = Vec::new();
        upsert_header(&mut headers, "Accept", "text/html");
        upsert_header(&mut headers, "Authorization", "Bearer tok");
        assert_eq!(headers.len(), 2);
    }

    // ---- header_value ----

    #[test]
    fn header_value_found() {
        let headers = vec![("X-Test".to_string(), "val".to_string())];
        assert_eq!(header_value(&headers, "X-Test"), Some("val"));
    }

    #[test]
    fn header_value_not_found() {
        let headers: HeaderList = Vec::new();
        assert_eq!(header_value(&headers, "Missing"), None);
    }

    #[test]
    fn header_value_case_insensitive() {
        let headers = vec![("Authorization".to_string(), "Bearer x".to_string())];
        assert_eq!(header_value(&headers, "authorization"), Some("Bearer x"));
    }

    // ---- Builder additional tests ----

    #[test]
    fn builder_header_overwrites_existing_case_insensitive() {
        let builder = GraphqlClientBuilder::new("https://api.test.com/graphql")
            .with_header("Content-Type", "text/plain");
        // Should overwrite the default Content-Type
        assert_eq!(
            header_value(&builder.config.headers, "Content-Type"),
            Some("text/plain")
        );
    }

    #[test]
    fn builder_bearer_token_overwrites_previous() {
        let builder = GraphqlClientBuilder::new("https://api.test.com/graphql")
            .with_bearer_token("old_token")
            .with_bearer_token("new_token");
        assert_eq!(
            header_value(&builder.config.headers, AUTHORIZATION_HEADER),
            Some("Bearer new_token")
        );
    }

    #[test]
    fn builder_clone() {
        let builder = GraphqlClientBuilder::new("https://api.test.com/graphql")
            .with_service_name("test")
            .with_timeout(Duration::from_secs(15));
        let cloned = builder.clone();
        assert_eq!(builder.endpoint, cloned.endpoint);
        assert_eq!(builder.config.service_name, cloned.config.service_name);
        assert_eq!(builder.config.timeout, cloned.config.timeout);
    }

    // ---- Client additional tests ----

    #[test]
    fn client_clone_shares_metrics() {
        let client = GraphqlClient::new("https://api.test.com/graphql");
        let cloned = client.clone();
        // Both point to same Arc<Metrics>
        assert!(Arc::ptr_eq(&client.metrics, &cloned.metrics));
    }

    #[test]
    fn client_clone_shares_schema_cache() {
        let client = GraphqlClient::new("https://api.test.com/graphql");
        let cloned = client.clone();
        assert!(Arc::ptr_eq(&client.schema_cache, &cloned.schema_cache));
    }

    #[test]
    fn client_clone_shares_http_client() {
        let client = GraphqlClient::new("https://api.test.com/graphql");
        let cloned = client.clone();
        assert!(Arc::ptr_eq(&client.http, &cloned.http));
    }

    #[test]
    fn client_debug_with_dedup() {
        let client = GraphqlClientBuilder::new("https://api.test.com/graphql")
            .with_dedup_in_flight(true)
            .build()
            .unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("dedup_in_flight"));
        assert!(dbg.contains("true"));
    }

    #[test]
    fn client_debug_without_dedup() {
        let client = GraphqlClient::new("https://api.test.com/graphql");
        let dbg = format!("{client:?}");
        assert!(dbg.contains("dedup_in_flight"));
        assert!(dbg.contains("false"));
    }

    // ---- truncate_body additional edge cases ----

    #[test]
    fn truncate_body_single_byte() {
        assert_eq!(truncate_body(b"x"), "x");
    }

    #[test]
    fn truncate_body_exactly_one_over_limit() {
        let body = vec![b'a'; 4097];
        let result = truncate_body(&body);
        assert!(result.ends_with('…'));
    }

    #[test]
    fn truncate_body_all_spaces() {
        let body = vec![b' '; 5000];
        let result = truncate_body(&body);
        assert!(result.ends_with('…'));
        assert!(result.len() <= 4100);
    }

    #[test]
    fn truncate_body_mixed_utf8() {
        // ASCII text that fits within limit
        let body = b"Hello World 2026";
        let result = truncate_body(body);
        assert_eq!(result, "Hello World 2026");
    }

    // ---- upsert_header additional tests ----

    #[test]
    fn upsert_header_empty_value() {
        let mut headers: HeaderList = Vec::new();
        upsert_header(&mut headers, "X-Empty", "");
        assert_eq!(header_value(&headers, "X-Empty"), Some(""));
    }

    #[test]
    fn upsert_header_empty_name() {
        let mut headers: HeaderList = Vec::new();
        upsert_header(&mut headers, "", "value");
        assert_eq!(header_value(&headers, ""), Some("value"));
    }

    #[test]
    fn upsert_header_preserves_insertion_order() {
        let mut headers: HeaderList = Vec::new();
        upsert_header(&mut headers, "A", "1");
        upsert_header(&mut headers, "B", "2");
        upsert_header(&mut headers, "C", "3");
        assert_eq!(headers[0].0, "A");
        assert_eq!(headers[1].0, "B");
        assert_eq!(headers[2].0, "C");
    }

    // ---- header_value additional tests ----

    #[test]
    fn header_value_multiple_headers_returns_first_match() {
        let headers = vec![
            ("X-Test".to_string(), "first".to_string()),
            ("X-Test".to_string(), "second".to_string()),
        ];
        // find returns first match
        assert_eq!(header_value(&headers, "X-Test"), Some("first"));
    }

    #[test]
    fn header_value_partial_name_no_match() {
        let headers = vec![("Content-Type".to_string(), "text/plain".to_string())];
        assert_eq!(header_value(&headers, "Content"), None);
    }

    // ---- parse_retry_after additional tests ----

    #[test]
    fn parse_retry_after_negative_value() {
        let headers = vec![(RETRY_AFTER_HEADER.to_string(), "-1".to_string())];
        assert_eq!(parse_retry_after(&headers), None);
    }

    #[test]
    fn parse_retry_after_float_value() {
        let headers = vec![(RETRY_AFTER_HEADER.to_string(), "1.5".to_string())];
        assert_eq!(parse_retry_after(&headers), None);
    }

    #[test]
    fn parse_retry_after_max_u64() {
        let headers = vec![(RETRY_AFTER_HEADER.to_string(), u64::MAX.to_string())];
        assert_eq!(
            parse_retry_after(&headers),
            Some(Duration::from_secs(u64::MAX))
        );
    }

    #[test]
    fn parse_retry_after_case_insensitive_lookup() {
        let headers = vec![("retry-after".to_string(), "10".to_string())];
        assert_eq!(parse_retry_after(&headers), Some(Duration::from_secs(10)));
    }

    // ---- SchemaValidationMode additional tests ----

    #[test]
    fn schema_validation_mode_all_variants() {
        let off = SchemaValidationMode::Off;
        let resp = SchemaValidationMode::ResponseOnly;
        let both = SchemaValidationMode::VariablesAndResponse;
        assert_ne!(off, resp);
        assert_ne!(resp, both);
        assert_ne!(off, both);
    }

    #[test]
    fn schema_validation_mode_debug_all() {
        assert!(format!("{:?}", SchemaValidationMode::Off).contains("Off"));
        assert!(format!("{:?}", SchemaValidationMode::ResponseOnly).contains("ResponseOnly"));
    }

    // ---- GraphqlClientMetrics edge cases ----

    #[test]
    fn metrics_concurrent_increments() {
        let metrics = GraphqlClientMetrics::default();
        for _ in 0..100 {
            metrics.requests_total.fetch_add(1, Ordering::Relaxed);
        }
        assert_eq!(metrics.snapshot().requests_total, 100);
    }

    #[test]
    fn metrics_debug_format() {
        let metrics = GraphqlClientMetrics::default();
        metrics.requests_total.fetch_add(42, Ordering::Relaxed);
        let dbg = format!("{metrics:?}");
        assert!(dbg.contains("GraphqlClientMetrics"));
    }

    #[test]
    fn metrics_snapshot_ne() {
        let a = GraphqlClientMetricsSnapshot {
            requests_total: 1,
            requests_success: 1,
            requests_error: 0,
            requests_retried: 0,
        };
        let b = GraphqlClientMetricsSnapshot {
            requests_total: 2,
            requests_success: 1,
            requests_error: 0,
            requests_retried: 0,
        };
        assert_ne!(a, b);
    }

    // ---- GraphqlClientConfig additional tests ----

    #[test]
    fn config_default_has_content_type() {
        let config = GraphqlClientConfig::default();
        let ct = header_value(&config.headers, "Content-Type");
        assert_eq!(ct, Some("application/json"));
    }

    #[test]
    fn config_custom_service_name() {
        let config = GraphqlClientConfig {
            service_name: "my-service".to_string(),
            ..GraphqlClientConfig::default()
        };
        assert_eq!(config.service_name, "my-service");
    }

    // ---- GraphqlClientBuilder additional tests ----

    #[test]
    fn builder_with_header_adds_multiple() {
        let builder = GraphqlClientBuilder::new("https://api.test.com/graphql")
            .with_header("X-One", "1")
            .with_header("X-Two", "2")
            .with_header("X-Three", "3");
        assert_eq!(header_value(&builder.config.headers, "X-One"), Some("1"));
        assert_eq!(header_value(&builder.config.headers, "X-Two"), Some("2"));
        assert_eq!(header_value(&builder.config.headers, "X-Three"), Some("3"));
    }

    #[test]
    fn builder_with_dedup_false() {
        let builder =
            GraphqlClientBuilder::new("https://api.test.com/graphql").with_dedup_in_flight(false);
        assert!(!builder.config.dedup_in_flight);
    }

    #[test]
    fn builder_with_zero_timeout() {
        let builder =
            GraphqlClientBuilder::new("https://api.test.com/graphql").with_timeout(Duration::ZERO);
        assert_eq!(builder.config.timeout, Duration::ZERO);
    }

    // ---- GraphqlClient additional tests ----

    #[test]
    fn client_new_with_path_endpoint() {
        let client = GraphqlClient::new("https://api.example.com/v2/graphql");
        assert_eq!(client.endpoint, "https://api.example.com/v2/graphql");
    }

    #[test]
    fn client_clone_independent_endpoints() {
        let client = GraphqlClient::new("https://api.test.com/graphql");
        let cloned = client.clone();
        // Endpoints are equal after clone
        assert_eq!(client.endpoint, cloned.endpoint);
    }

    #[test]
    fn client_with_config_dedup_disabled() {
        let config = GraphqlClientConfig {
            dedup_in_flight: false,
            ..GraphqlClientConfig::default()
        };
        let client = GraphqlClient::with_config("https://api.test.com/graphql", config).unwrap();
        assert!(client.dedup_state.is_none());
    }

    #[test]
    fn client_from_builder_full_config() {
        let client = GraphqlClientBuilder::new("https://api.test.com/graphql")
            .with_service_name("github")
            .with_bearer_token("ghp_test123")
            .with_timeout(Duration::from_secs(60))
            .with_dedup_in_flight(true)
            .with_validation_mode(SchemaValidationMode::VariablesAndResponse)
            .build()
            .unwrap();
        assert_eq!(client.endpoint, "https://api.test.com/graphql");
        assert_eq!(client.config.service_name, "github");
        assert_eq!(client.config.timeout, Duration::from_secs(60));
        assert!(client.dedup_state.is_some());
        assert_eq!(
            client.config.validation,
            SchemaValidationMode::VariablesAndResponse
        );
    }

    #[test]
    fn client_metrics_snapshot_copy() {
        let client = GraphqlClient::new("https://api.test.com/graphql");
        let snap1 = client.metrics();
        let snap2 = snap1;
        assert_eq!(snap1, snap2);
    }

    // ---- map_request_async_error tests ----

    #[test]
    fn map_timeout_error_to_http_timeout() {
        let err = map_request_async_error(
            AsyncError::Timeout { timeout_ms: 30000 },
            Duration::from_secs(30),
        );
        match err {
            GraphqlClientError::Http(info) => {
                assert!(info.is_timeout);
                assert!(info.message.contains("30000"));
            }
            other => panic!("expected Http, got {other:?}"),
        }
    }

    #[test]
    fn map_cancelled_error_to_http_cancelled() {
        let err = map_request_async_error(AsyncError::Cancelled, Duration::from_secs(10));
        match err {
            GraphqlClientError::Http(info) => {
                assert!(!info.is_timeout);
                assert_eq!(info.message, "request cancelled");
            }
            other => panic!("expected Http, got {other:?}"),
        }
    }

    #[test]
    fn map_protocol_io_error_to_protocol() {
        let err = map_request_async_error(
            AsyncError::ProtocolIo {
                message: "broken pipe".into(),
            },
            Duration::from_secs(10),
        );
        match err {
            GraphqlClientError::Protocol { message } => {
                assert_eq!(message, "broken pipe");
            }
            other => panic!("expected Protocol, got {other:?}"),
        }
    }

    #[test]
    fn map_join_error_to_protocol() {
        let err = map_request_async_error(
            AsyncError::Join {
                message: "task panicked".into(),
            },
            Duration::from_secs(10),
        );
        match err {
            GraphqlClientError::Protocol { message } => {
                assert_eq!(message, "task panicked");
            }
            other => panic!("expected Protocol, got {other:?}"),
        }
    }

    #[test]
    fn map_runtime_error_to_protocol() {
        let err = map_request_async_error(
            AsyncError::Runtime {
                message: "runtime shutdown".into(),
            },
            Duration::from_secs(10),
        );
        match err {
            GraphqlClientError::Protocol { message } => {
                assert_eq!(message, "runtime shutdown");
            }
            other => panic!("expected Protocol, got {other:?}"),
        }
    }

    #[test]
    fn map_channel_closed_to_protocol() {
        let err = map_request_async_error(AsyncError::ChannelClosed, Duration::from_secs(10));
        match err {
            GraphqlClientError::Protocol { message } => {
                assert!(message.contains("channel closed"));
            }
            other => panic!("expected Protocol, got {other:?}"),
        }
    }

    #[test]
    fn map_channel_full_to_protocol() {
        let err = map_request_async_error(AsyncError::ChannelFull, Duration::from_secs(10));
        match err {
            GraphqlClientError::Protocol { message } => {
                assert!(message.contains("channel full"));
            }
            other => panic!("expected Protocol, got {other:?}"),
        }
    }

    // ---- truncate_body additional edge cases ----

    #[test]
    fn truncate_body_exactly_max_minus_one() {
        let body = vec![b'z'; 4095];
        let result = truncate_body(&body);
        assert_eq!(result.len(), 4095);
        assert!(!result.ends_with('…'));
    }

    #[test]
    fn truncate_body_all_newlines() {
        let body = vec![b'\n'; 5000];
        let result = truncate_body(&body);
        assert!(result.ends_with('…'));
    }

    // ---- GraphqlClientConfig edge cases ----

    #[test]
    fn config_default_retry_policy_matches() {
        use crate::retry::RetryStrategy;
        let config = GraphqlClientConfig::default();
        assert_eq!(config.retry.max_attempts, 3);
        assert_eq!(config.retry.strategy, RetryStrategy::IdempotentOnly);
    }

    // ---- GraphqlClientBuilder: endpoint edge cases ----

    #[test]
    fn builder_with_empty_endpoint() {
        let builder = GraphqlClientBuilder::new("");
        assert!(builder.endpoint.is_empty());
    }

    #[test]
    fn builder_with_unicode_endpoint() {
        let builder = GraphqlClientBuilder::new("https://api.example.com/graphql/abfrage");
        assert!(builder.endpoint.contains("abfrage"));
    }

    // ---- metrics inequality and default behavior ----

    #[test]
    fn metrics_snapshot_all_max_values() {
        let snap = GraphqlClientMetricsSnapshot {
            requests_total: u64::MAX,
            requests_success: u64::MAX,
            requests_error: u64::MAX,
            requests_retried: u64::MAX,
        };
        let copy = snap;
        assert_eq!(snap, copy);
    }

    #[test]
    fn metrics_individual_field_increments() {
        let metrics = GraphqlClientMetrics::default();
        metrics.requests_success.fetch_add(10, Ordering::Relaxed);
        metrics.requests_error.fetch_add(5, Ordering::Relaxed);
        let snap = metrics.snapshot();
        assert_eq!(snap.requests_total, 0);
        assert_eq!(snap.requests_success, 10);
        assert_eq!(snap.requests_error, 5);
        assert_eq!(snap.requests_retried, 0);
    }

    // ---- DedupGuard ----

    #[fcp_async_core::runtime::test]
    async fn dedup_guard_removes_entry_on_drop() {
        let state = DedupState::new();

        // Pre-seed the map with a Shared future that's already resolved —
        // the guard's job is only to remove the key, not to drive the
        // future.
        let fut = async { Ok(Vec::<u8>::new()) }.boxed().shared();
        let key = b"{\"query\":\"{ seeded }\"}".to_vec();
        state.inner.lock().await.insert(key.clone(), fut);
        assert_eq!(state.inner.lock().await.len(), 1);

        {
            let _guard = DedupGuard {
                state: state.clone(),
                key: key.clone(),
            };
            // Drop happens at end of scope.
        }

        // Give the spawn fallback a chance to run if try_lock contended.
        // In this test there's no concurrent lock holder, so try_lock
        // succeeds and removal is synchronous.
        assert!(
            state.inner.lock().await.is_empty(),
            "DedupGuard::drop must remove the map entry"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn dedup_guard_tolerates_missing_key() {
        // Guard for a key that was already removed should be a no-op,
        // not a panic.
        let state = DedupState::new();
        {
            let _guard = DedupGuard {
                state: state.clone(),
                key: b"never-inserted".to_vec(),
            };
        }
        assert!(state.inner.lock().await.is_empty());
    }

    // ---- br-flywheel_connectors-upp69: collision-free dedup keys ----

    #[fcp_async_core::runtime::test]
    async fn dedup_map_distinguishes_bodies_that_would_share_siphash_output() {
        // Regression: prior behavior keyed on `u64` DefaultHasher output,
        // which merges distinct bodies on the (hypothetical, but
        // adversarially-attainable) collision. With byte-keyed dedup,
        // any two distinct byte sequences map to distinct entries
        // *unconditionally*. Prove it with the strongest possible
        // pair: two bodies that differ in exactly one byte.
        let state = DedupState::new();

        let body_a = b"{\"query\":\"{ a }\"}".to_vec();
        let mut body_b = body_a.clone();
        // Flip the only letter of content.
        let idx = body_b
            .iter()
            .position(|&c| c == b'a')
            .expect("body_a has 'a'");
        body_b[idx] = b'b';

        let fut_a = async { Ok(b"RESPONSE-A".to_vec()) }.boxed().shared();
        let fut_b = async { Ok(b"RESPONSE-B".to_vec()) }.boxed().shared();

        {
            let mut inner = state.inner.lock().await;
            inner.insert(body_a.clone(), fut_a);
            inner.insert(body_b.clone(), fut_b);
            assert_eq!(
                inner.len(),
                2,
                "distinct bodies must occupy distinct map entries"
            );
        }

        let got_a = state
            .inner
            .lock()
            .await
            .get(&body_a)
            .cloned()
            .expect("a present")
            .await
            .expect("a resolved");
        let got_b = state
            .inner
            .lock()
            .await
            .get(&body_b)
            .cloned()
            .expect("b present")
            .await
            .expect("b resolved");

        assert_eq!(got_a, b"RESPONSE-A");
        assert_eq!(got_b, b"RESPONSE-B");
    }
}
