//! Integration tests: fcp-host discovery/introspection against real subprocess connectors.
//!
//! Bead: bd-219o

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::net::TcpListener as StdTcpListener;
#[cfg(unix)]
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex as StdMutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use fcp_async_core::sync::Mutex;
use fcp_core::{
    CapabilityToken, ConnectorHealth, ConnectorId, CorrelationId, HandshakeRequest, HealthSnapshot,
    Introspection, InvokeRequest, InvokeResponse, InvokeStatus, LifecycleState, LifecycleStatus,
    OperationId, RequestId, RollbackRules, RolloutPolicy, SelfCheckReport, SuccessThresholds,
    ZoneId,
};
use fcp_e2e::{AssertionsSummary, ConnectorProcessRunner, E2eLogEntry, E2eLogger};
use fcp_host::{
    BatchInvokeResponse, BatchStatus, CancelReason, CancellationOutcome, CancellationRequest,
    CancellationResponse, CleanupBehavior, ConnectorArchetype, ConnectorRegistry, ConnectorSummary,
    DiscoveryEndpoint, DiscoveryResponse, HostHealthResponse, HostHealthStatus,
    IntrospectionResponse, OperationResultStatus, PolicyEngine, PreflightRequest,
    PreflightResponse, RolloutDecision, RolloutOutcome,
};
use fcp_testkit::LogCapture;
use reqwest::header::{CACHE_CONTROL, ETAG, HeaderMap, HeaderValue, IF_NONE_MATCH, LAST_MODIFIED};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

#[derive(Debug, Deserialize)]
struct PinStateResponse {
    connector_id: String,
    pinned: bool,
    version: Option<semver::Version>,
}

#[derive(Debug, Deserialize)]
struct RolloutStatusResponse {
    #[serde(flatten)]
    status: LifecycleStatus,
    pinned: bool,
    pinned_version: Option<semver::Version>,
    canary_percent: u8,
}

#[derive(Debug, Deserialize)]
struct ManualRollbackResponse {
    connector_id: String,
    state: LifecycleState,
    from_version: semver::Version,
    to_version: semver::Version,
    message: String,
}

struct AllowAllPolicy;

#[async_trait::async_trait]
impl PolicyEngine for AllowAllPolicy {
    async fn evaluate_preflight(&self, _request: &PreflightRequest) -> PreflightResponse {
        PreflightResponse::allowed()
    }
}

struct SubprocessConnector {
    summary: ConnectorSummary,
    runner: Mutex<ConnectorProcessRunner>,
}

impl SubprocessConnector {
    async fn spawn(id: ConnectorId, name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let binary = env!("CARGO_BIN_EXE_fcp-test-connector");
        let env = [("FCP_TEST_CONNECTOR_ID", id.as_str())];
        let runner = ConnectorProcessRunner::spawn(binary, &[], &env).await?;

        let summary = ConnectorSummary {
            id,
            name: name.to_string(),
            description: Some("Subprocess test connector".to_string()),
            version: semver::Version::new(1, 0, 0),
            categories: vec!["test".to_string()],
            tool_count: 1,
            max_safety_tier: fcp_core::SafetyTier::Safe,
            enabled: true,
            health: ConnectorHealth::healthy(),
            last_health_check: None,
        };

        Ok(Self {
            summary,
            runner: Mutex::new(runner),
        })
    }

    async fn rpc(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> std::io::Result<serde_json::Value> {
        let mut runner = self.runner.lock().await;
        let request = json!({
            "jsonrpc": "2.0",
            "id": RequestId::random().0,
            "method": method,
            "params": params,
        });
        let response = runner.request(&request).await?;
        if let Some(error) = response.get("error") {
            return Err(std::io::Error::other(format!("connector error: {error}")));
        }
        Ok(response.get("result").cloned().unwrap_or(json!({})))
    }

    async fn handshake(&self) -> std::io::Result<()> {
        let request = HandshakeRequest {
            protocol_version: "2.0".to_string(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: [0_u8; 32],
            nonce: [42_u8; 32],
            capabilities_requested: Vec::new(),
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        };
        let params = serde_json::to_value(request)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
        let _ = self.rpc("handshake", params).await?;
        Ok(())
    }

    async fn introspect(&self) -> std::io::Result<Introspection> {
        let result = self.rpc("introspect", json!({})).await?;
        serde_json::from_value(result)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
    }

    async fn health(&self) -> std::io::Result<HealthSnapshot> {
        let result = self.rpc("health", json!({})).await?;
        serde_json::from_value(result)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
    }

    async fn self_check(&self) -> std::io::Result<SelfCheckReport> {
        let result = self.rpc("self_check", json!({})).await?;
        serde_json::from_value(result)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
    }

    async fn invoke(&self, request: InvokeRequest) -> std::io::Result<InvokeResponse> {
        let params = serde_json::to_value(request)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
        let result = self.rpc("invoke", params).await?;
        serde_json::from_value(result)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
    }

    async fn terminate(&self) -> std::io::Result<()> {
        let mut runner = self.runner.lock().await;
        runner.terminate()
    }

    async fn summary_with_health(&self) -> ConnectorSummary {
        let mut summary = self.summary.clone();
        match self.health().await {
            Ok(snapshot) => {
                summary.health = ConnectorHealth::from(&snapshot.status);
                summary.last_health_check = Some(chrono::Utc::now());
            }
            Err(err) => {
                summary.health =
                    ConnectorHealth::unavailable(format!("health check failed: {err}"));
                summary.last_health_check = Some(chrono::Utc::now());
            }
        }
        summary
    }
}

struct SubprocessRegistry {
    connectors: HashMap<ConnectorId, Arc<SubprocessConnector>>,
    version: u64,
}

impl SubprocessRegistry {
    fn new(connectors: Vec<SubprocessConnector>) -> Self {
        let mut map = HashMap::new();
        for connector in connectors {
            map.insert(connector.summary.id.clone(), Arc::new(connector));
        }
        Self {
            connectors: map,
            version: 1,
        }
    }

    async fn invoke(
        &self,
        id: &ConnectorId,
        request: InvokeRequest,
    ) -> std::io::Result<InvokeResponse> {
        let connector = self.connectors.get(id).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "connector missing")
        })?;
        connector.invoke(request).await
    }

    async fn terminate_all(&self) -> std::io::Result<()> {
        for connector in self.connectors.values() {
            let _ = connector.terminate().await;
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl ConnectorRegistry for SubprocessRegistry {
    async fn list(&self) -> Vec<ConnectorSummary> {
        let mut results = Vec::new();
        for connector in self.connectors.values() {
            results.push(connector.summary_with_health().await);
        }
        results
    }

    async fn get(&self, id: &ConnectorId) -> Option<ConnectorSummary> {
        self.connectors
            .get(id)
            .map(|connector| connector.summary.clone())
    }

    async fn get_introspection(&self, id: &ConnectorId) -> Option<Introspection> {
        let connector = self.connectors.get(id)?;
        connector.introspect().await.ok()
    }

    async fn get_archetype(&self, id: &ConnectorId) -> Option<ConnectorArchetype> {
        self.connectors.get(id)?;
        Some(ConnectorArchetype::RequestResponse)
    }

    async fn get_rate_limits(&self, id: &ConnectorId) -> Option<fcp_core::RateLimitDeclarations> {
        self.connectors.get(id)?;
        Some(fcp_core::RateLimitDeclarations::default())
    }

    async fn self_check(&self, id: &ConnectorId) -> Option<SelfCheckReport> {
        let connector = self.connectors.get(id)?;
        connector.self_check().await.ok()
    }

    fn version(&self) -> u64 {
        self.version
    }
}

fn build_invoke_request(connector_id: ConnectorId) -> (InvokeRequest, CorrelationId) {
    let correlation_id = CorrelationId::new();
    let request = InvokeRequest {
        r#type: "invoke".to_string(),
        id: RequestId::random(),
        connector_id,
        operation: OperationId::from_static("test.echo"),
        zone_id: ZoneId::work(),
        input: json!({ "message": "hello" }),
        capability_token: CapabilityToken::test_token(),
        holder_proof: None,
        context: None,
        idempotency_key: None,
        lease_seq: None,
        deadline_ms: None,
        correlation_id: Some(correlation_id.clone()),
        provenance: None,
        approval_tokens: Vec::new(),
    };
    (request, correlation_id)
}

fn batch_operation_json(
    id: &str,
    request: InvokeRequest,
    depends_on: &[&str],
) -> serde_json::Value {
    json!({
        "id": id,
        "request": request,
        "depends_on": depends_on,
    })
}

#[fcp_async_core::runtime::test]
async fn host_discovery_with_subprocess_connectors() -> Result<(), Box<dyn std::error::Error>> {
    let connector_a_id = ConnectorId::from_static("fcp.test.echo:utility:1.0.0");
    let connector_b_id = ConnectorId::from_static("fcp.test.ping:utility:1.0.0");

    let connector_a = SubprocessConnector::spawn(connector_a_id.clone(), "Test Echo").await?;
    let connector_b = SubprocessConnector::spawn(connector_b_id.clone(), "Test Ping").await?;

    connector_a.handshake().await?;
    connector_b.handshake().await?;

    let registry = Arc::new(SubprocessRegistry::new(vec![connector_a, connector_b]));
    let endpoint = DiscoveryEndpoint::new(Arc::clone(&registry), Arc::new(AllowAllPolicy));

    let response = endpoint.discover(None).await;
    assert_eq!(response.connectors.len(), 2);
    assert!(response.connectors.iter().any(|c| c.id == connector_a_id));
    assert!(response.connectors.iter().any(|c| c.id == connector_b_id));

    let mut logs = Vec::new();
    logs.push(json!({
        "step": "discover",
        "correlation_id": CorrelationId::new().to_string(),
        "connector_count": response.connectors.len(),
    }));

    let introspection_a = endpoint.introspect(&connector_a_id).await?;
    assert!(
        introspection_a
            .introspection
            .operations
            .iter()
            .any(|op| op.id == OperationId::from_static("test.echo"))
    );
    logs.push(json!({
        "step": "introspect",
        "correlation_id": CorrelationId::new().to_string(),
        "connector_id": connector_a_id.as_str(),
    }));

    let introspection_b = endpoint.introspect(&connector_b_id).await?;
    assert!(
        introspection_b
            .introspection
            .operations
            .iter()
            .any(|op| op.id == OperationId::from_static("test.echo"))
    );
    logs.push(json!({
        "step": "introspect",
        "correlation_id": CorrelationId::new().to_string(),
        "connector_id": connector_b_id.as_str(),
    }));

    let (invoke_request, correlation_id) = build_invoke_request(connector_a_id.clone());
    let invoke_response = registry.invoke(&connector_a_id, invoke_request).await?;
    assert_eq!(invoke_response.status, InvokeStatus::Ok);
    assert!(invoke_response.receipt_id.is_some());
    logs.push(json!({
        "step": "invoke",
        "correlation_id": correlation_id.to_string(),
        "connector_id": connector_a_id.as_str(),
        "receipt_id": invoke_response
            .receipt_id
            .as_ref()
            .map(|id| id.to_string()),
    }));

    let self_check = endpoint.self_check(&connector_a_id).await?;
    assert_eq!(self_check.report.status, fcp_core::SelfCheckStatus::Ok);
    logs.push(json!({
        "step": "self_check",
        "correlation_id": CorrelationId::new().to_string(),
        "connector_id": connector_a_id.as_str(),
        "status": format!("{:?}", self_check.report.status),
    }));

    for entry in &logs {
        assert!(entry.get("correlation_id").is_some());
    }

    registry.terminate_all().await?;

    Ok(())
}

type StderrLogs = Arc<StdMutex<Vec<String>>>;

fn test_cx() -> asupersync::Cx {
    asupersync::Cx::current().unwrap_or_else(asupersync::Cx::for_testing)
}

fn build_http_client(builder: reqwest::ClientBuilder) -> Result<reqwest::Client, reqwest::Error> {
    asupersync_tokio_compat::runtime::with_tokio_context_sync(|| builder.build())
}

async fn http_get_status(
    client: reqwest::Client,
    url: String,
) -> Result<reqwest::StatusCode, Box<dyn std::error::Error>> {
    let cx = test_cx();
    let status = asupersync_tokio_compat::runtime::with_tokio_context(&cx, move || async move {
        client
            .get(url)
            .send()
            .await
            .map(|response| response.status())
    })
    .await
    .ok_or_else(|| std::io::Error::other("tokio-compat GET status request cancelled"))??;
    Ok(status)
}

async fn http_get_json<T>(
    client: reqwest::Client,
    url: String,
) -> Result<T, Box<dyn std::error::Error>>
where
    T: DeserializeOwned + Send + 'static,
{
    Ok(http_get_json_response(client, url, None).await?.body)
}

async fn http_post_json<B, T>(
    client: reqwest::Client,
    url: String,
    body: B,
) -> Result<T, Box<dyn std::error::Error>>
where
    B: serde::Serialize + Send + 'static,
    T: DeserializeOwned + Send + 'static,
{
    Ok(http_post_json_response(client, url, body, None).await?.body)
}

async fn http_put_json<B, T>(
    client: reqwest::Client,
    url: String,
    body: B,
) -> Result<T, Box<dyn std::error::Error>>
where
    B: serde::Serialize + Send + 'static,
    T: DeserializeOwned + Send + 'static,
{
    let cx = test_cx();
    let response = asupersync_tokio_compat::runtime::with_tokio_context(&cx, move || async move {
        let response = client
            .put(url)
            .json(&body)
            .send()
            .await?
            .error_for_status()?;
        let body = response.json::<T>().await?;
        Ok::<_, reqwest::Error>(body)
    })
    .await
    .ok_or_else(|| std::io::Error::other("tokio-compat PUT JSON request cancelled"))??;
    Ok(response)
}

async fn http_delete_json<T>(
    client: reqwest::Client,
    url: String,
) -> Result<T, Box<dyn std::error::Error>>
where
    T: DeserializeOwned + Send + 'static,
{
    let cx = test_cx();
    let response = asupersync_tokio_compat::runtime::with_tokio_context(&cx, move || async move {
        let response = client.delete(url).send().await?.error_for_status()?;
        let body = response.json::<T>().await?;
        Ok::<_, reqwest::Error>(body)
    })
    .await
    .ok_or_else(|| std::io::Error::other("tokio-compat DELETE JSON request cancelled"))??;
    Ok(response)
}

struct HttpJsonResponse<T> {
    status: reqwest::StatusCode,
    headers: HeaderMap,
    body: T,
}

async fn http_get_json_response<T>(
    client: reqwest::Client,
    url: String,
    headers: Option<HeaderMap>,
) -> Result<HttpJsonResponse<T>, Box<dyn std::error::Error>>
where
    T: DeserializeOwned + Send + 'static,
{
    let cx = test_cx();
    let response = asupersync_tokio_compat::runtime::with_tokio_context(&cx, move || async move {
        let mut request = client.get(url);
        if let Some(headers) = headers {
            request = request.headers(headers);
        }
        let response = request.send().await?.error_for_status()?;
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.json::<T>().await?;
        Ok::<_, reqwest::Error>(HttpJsonResponse {
            status,
            headers,
            body,
        })
    })
    .await
    .ok_or_else(|| std::io::Error::other("tokio-compat GET JSON request cancelled"))??;
    Ok(response)
}

async fn http_post_json_response<B, T>(
    client: reqwest::Client,
    url: String,
    body: B,
    headers: Option<HeaderMap>,
) -> Result<HttpJsonResponse<T>, Box<dyn std::error::Error>>
where
    B: serde::Serialize + Send + 'static,
    T: DeserializeOwned + Send + 'static,
{
    let cx = test_cx();
    let response = asupersync_tokio_compat::runtime::with_tokio_context(&cx, move || async move {
        let mut request = client.post(url).json(&body);
        if let Some(headers) = headers {
            request = request.headers(headers);
        }
        let response = request.send().await?.error_for_status()?;
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.json::<T>().await?;
        Ok::<_, reqwest::Error>(HttpJsonResponse {
            status,
            headers,
            body,
        })
    })
    .await
    .ok_or_else(|| std::io::Error::other("tokio-compat POST JSON request cancelled"))??;
    Ok(response)
}

fn assert_cache_headers(
    headers: &HeaderMap,
    cache: &fcp_host::CacheMetadata,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        headers.get(ETAG).and_then(|value| value.to_str().ok()),
        Some(cache.etag.as_str())
    );

    let cache_control = headers
        .get(CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
        .expect("cache-control header should be present");
    let mut expected_cache_control = format!("max-age={}", cache.max_age_seconds);
    if let Some(stale) = cache.stale_while_revalidate_seconds {
        expected_cache_control.push_str(&format!(", stale-while-revalidate={stale}"));
    }
    assert_eq!(cache_control, expected_cache_control);

    let last_modified = headers
        .get(LAST_MODIFIED)
        .and_then(|value| value.to_str().ok())
        .expect("last-modified header should be present");
    let parsed_last_modified = chrono::DateTime::parse_from_rfc2822(last_modified)?;
    assert_eq!(
        parsed_last_modified.timestamp(),
        cache.last_modified.timestamp()
    );

    Ok(())
}

struct HttpHostProcess {
    child: Child,
    client: reqwest::Client,
    base_url: String,
    #[allow(dead_code)]
    stderr_logs: StderrLogs,
    stderr_thread: Option<JoinHandle<()>>,
}

async fn wait_for_host_readiness(
    child: &mut Child,
    client: &reqwest::Client,
    base_url: &str,
    stderr_logs: &StderrLogs,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut last_error = None;

    for _ in 0..40 {
        if let Some(status) = child.try_wait()? {
            let raw_stderr = stderr_logs
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            return Err(
                format!("fcp-host exited early with {status}; stderr: {raw_stderr:?}").into(),
            );
        }

        match fcp_async_core::time::timeout(
            Duration::from_millis(250),
            http_get_status(client.clone(), format!("{base_url}/rpc/health")),
        )
        .await
        {
            Ok(Ok(status)) if status.is_success() => return Ok(()),
            Ok(Ok(status)) => {
                last_error = Some(format!("health returned {status}"));
                fcp_async_core::time::sleep(Duration::from_millis(50)).await;
            }
            Ok(Err(err)) => {
                last_error = Some(err.to_string());
                fcp_async_core::time::sleep(Duration::from_millis(50)).await;
            }
            Err(_) => {
                last_error = Some("health request timed out".to_string());
                fcp_async_core::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }

    let _ = child.kill();
    let _ = child.wait();
    let raw_stderr = stderr_logs
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    Err(format!(
        "timed out waiting for fcp-host readiness; last_error: {}; stderr: {raw_stderr:?}",
        last_error.unwrap_or_else(|| "none".to_string())
    )
    .into())
}

impl HttpHostProcess {
    async fn spawn(
        connector_configs: Vec<serde_json::Value>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let bind_listener = StdTcpListener::bind("127.0.0.1:0")?;
        let bind_addr = bind_listener.local_addr()?;
        drop(bind_listener);

        let base_url = format!("http://{bind_addr}");
        let mut child = Command::new(env!("CARGO_BIN_EXE_fcp-host"))
            .env("FCP_HOST_BIND", bind_addr.to_string())
            .env(
                "FCP_HOST_CONNECTORS",
                serde_json::to_string(&connector_configs)?,
            )
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        let (stderr_logs, stderr_thread) = spawn_stderr_capture(&mut child)?;

        let client = build_http_client(reqwest::Client::builder().timeout(Duration::from_secs(2)))?;
        wait_for_host_readiness(&mut child, &client, &base_url, &stderr_logs).await?;

        Ok(Self {
            child,
            client,
            base_url,
            stderr_logs,
            stderr_thread: Some(stderr_thread),
        })
    }
}

impl Drop for HttpHostProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(stderr_thread) = self.stderr_thread.take() {
            let _ = stderr_thread.join();
        }
    }
}

#[cfg(unix)]
struct UnixHostProcess {
    child: Child,
    client: reqwest::Client,
    base_url: String,
    #[allow(dead_code)]
    stderr_logs: StderrLogs,
    stderr_thread: Option<JoinHandle<()>>,
}

#[cfg(unix)]
impl UnixHostProcess {
    async fn spawn(
        connector_configs: Vec<serde_json::Value>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let socket_path = unique_unix_socket_path()?;
        let base_url = "http://localhost".to_string();
        let mut child = Command::new(env!("CARGO_BIN_EXE_fcp-host"))
            .env("FCP_HOST_BIND", format!("unix://{}", socket_path.display()))
            .env(
                "FCP_HOST_CONNECTORS",
                serde_json::to_string(&connector_configs)?,
            )
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        let (stderr_logs, stderr_thread) = spawn_stderr_capture(&mut child)?;

        let client = build_http_client(
            reqwest::Client::builder()
                .timeout(Duration::from_secs(2))
                .unix_socket(socket_path),
        )?;
        wait_for_host_readiness(&mut child, &client, &base_url, &stderr_logs).await?;

        Ok(Self {
            child,
            client,
            base_url,
            stderr_logs,
            stderr_thread: Some(stderr_thread),
        })
    }
}

#[cfg(unix)]
impl Drop for UnixHostProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(stderr_thread) = self.stderr_thread.take() {
            let _ = stderr_thread.join();
        }
    }
}

#[cfg(unix)]
fn unique_unix_socket_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
    for _ in 0..16 {
        let path = PathBuf::from("/tmp").join(format!("fcp-host-{}.sock", CorrelationId::new()));
        if !path.exists() {
            return Ok(path);
        }
    }

    Err("failed to allocate unique unix socket path".into())
}

fn spawn_stderr_capture(
    child: &mut Child,
) -> Result<(StderrLogs, JoinHandle<()>), Box<dyn std::error::Error>> {
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| std::io::Error::other("fcp-host stderr pipe unavailable"))?;
    let logs = Arc::new(StdMutex::new(Vec::new()));
    let logs_for_thread = Arc::clone(&logs);
    let handle = std::thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines() {
            match line {
                Ok(line) => logs_for_thread
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(line),
                Err(_) => break,
            }
        }
    });
    Ok((logs, handle))
}

async fn wait_for_log_events(
    stderr_logs: &Arc<StdMutex<Vec<String>>>,
    events: &[&str],
) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let raw_lines = stderr_logs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let parsed_logs: Vec<Value> = raw_lines
            .iter()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .collect();
        let saw_all_events = events.iter().all(|event| {
            parsed_logs
                .iter()
                .any(|entry| entry.get("event").and_then(Value::as_str) == Some(*event))
        });
        if saw_all_events {
            return Ok(parsed_logs);
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for log events {events:?}; raw stderr lines: {raw_lines:?}"
            )
            .into());
        }
        fcp_async_core::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn assert_discovery_routes(
    client: &reqwest::Client,
    base_url: &str,
    connector_a_id: &ConnectorId,
    connector_b_id: &ConnectorId,
) -> Result<(), Box<dyn std::error::Error>> {
    let url = |path: &str| format!("{base_url}{path}");

    let health: HostHealthResponse = http_get_json(client.clone(), url("/rpc/health")).await?;
    assert_eq!(health.status, HostHealthStatus::Healthy);
    assert_eq!(health.connectors.len(), 2);
    assert!(health.connectors.contains_key(connector_a_id));
    assert!(health.connectors.contains_key(connector_b_id));

    let discover_all = http_post_json_response::<_, DiscoveryResponse>(
        client.clone(),
        url("/rpc/discover"),
        json!({}),
        None,
    )
    .await?;
    assert_eq!(discover_all.status, reqwest::StatusCode::OK);
    let discover_all_headers = discover_all.headers.clone();
    let discover_all = discover_all.body;
    assert_eq!(discover_all.connectors.len(), 2);
    let discover_all_cache = discover_all
        .cache
        .as_ref()
        .expect("discover response should expose cache metadata");
    assert!(!discover_all_cache.etag.is_empty());
    assert!(discover_all.meta.is_none());
    assert_cache_headers(&discover_all_headers, discover_all_cache)?;
    assert!(
        discover_all
            .connectors
            .iter()
            .all(|connector| connector.tool_count == 1)
    );
    assert!(
        discover_all
            .connectors
            .iter()
            .all(|connector| { matches!(connector.max_safety_tier, fcp_core::SafetyTier::Safe) })
    );
    assert!(
        discover_all
            .connectors
            .iter()
            .all(|connector| connector.health.is_healthy())
    );

    let discover_filtered = http_post_json_response::<_, DiscoveryResponse>(
        client.clone(),
        url("/rpc/discover"),
        json!({ "category": "primary" }),
        None,
    )
    .await?;
    assert_eq!(discover_filtered.status, reqwest::StatusCode::OK);
    let discover_filtered_headers = discover_filtered.headers.clone();
    let discover_filtered = discover_filtered.body;
    assert_eq!(discover_filtered.connectors.len(), 1);
    let discover_filtered_cache = discover_filtered
        .cache
        .as_ref()
        .expect("filtered discover response should expose cache metadata");
    assert_ne!(discover_all_cache.etag, discover_filtered_cache.etag);
    assert_cache_headers(&discover_filtered_headers, discover_filtered_cache)?;
    assert_eq!(discover_filtered.connectors[0].id, *connector_a_id);
    assert_eq!(discover_filtered.connectors[0].tool_count, 1);
    assert!(matches!(
        discover_filtered.connectors[0].max_safety_tier,
        fcp_core::SafetyTier::Safe
    ));
    assert!(discover_filtered.connectors[0].health.is_healthy());

    let mut discover_not_modified_headers = HeaderMap::new();
    discover_not_modified_headers.insert(
        IF_NONE_MATCH,
        HeaderValue::from_str(&discover_all_cache.etag)?,
    );
    let discover_not_modified = http_post_json_response::<_, DiscoveryResponse>(
        client.clone(),
        url("/rpc/discover"),
        json!({}),
        Some(discover_not_modified_headers),
    )
    .await?;
    assert_eq!(discover_not_modified.status, reqwest::StatusCode::OK);
    let discover_not_modified_response_headers = discover_not_modified.headers.clone();
    let discover_not_modified = discover_not_modified.body;
    assert!(discover_not_modified.connectors.is_empty());
    assert_eq!(
        discover_not_modified.meta.as_ref().map(|meta| meta.status),
        Some(304)
    );
    assert_eq!(
        discover_not_modified
            .cache
            .as_ref()
            .map(|cache| cache.etag.as_str()),
        Some(discover_all_cache.etag.as_str())
    );
    assert_cache_headers(
        &discover_not_modified_response_headers,
        discover_not_modified
            .cache
            .as_ref()
            .expect("not-modified discover should still expose cache metadata"),
    )?;

    let introspection = http_get_json_response::<IntrospectionResponse>(
        client.clone(),
        url(&format!("/rpc/introspect/{}", connector_a_id.as_str())),
        None,
    )
    .await?;
    assert_eq!(introspection.status, reqwest::StatusCode::OK);
    let introspection_headers = introspection.headers.clone();
    let introspection = introspection.body;
    assert_eq!(introspection.connector.id, *connector_a_id);
    assert_eq!(introspection.connector.tool_count, 1);
    assert!(matches!(
        introspection.connector.max_safety_tier,
        fcp_core::SafetyTier::Safe
    ));
    assert!(introspection.connector.health.is_healthy());
    assert_eq!(introspection.tools.len(), 1);
    assert_eq!(introspection.tools[0].name, "test.echo");
    assert_cache_headers(
        &introspection_headers,
        introspection
            .cache
            .as_ref()
            .expect("introspection should expose cache metadata"),
    )?;

    let introspection_cache = introspection
        .cache
        .as_ref()
        .expect("introspection cache metadata");
    let mut introspect_not_modified_headers = HeaderMap::new();
    introspect_not_modified_headers.insert(
        IF_NONE_MATCH,
        HeaderValue::from_str(&introspection_cache.etag)?,
    );
    let introspect_not_modified = http_get_json_response::<IntrospectionResponse>(
        client.clone(),
        url(&format!("/rpc/introspect/{}", connector_a_id.as_str())),
        Some(introspect_not_modified_headers),
    )
    .await?;
    assert_eq!(introspect_not_modified.status, reqwest::StatusCode::OK);
    let introspect_not_modified_headers = introspect_not_modified.headers.clone();
    let introspect_not_modified = introspect_not_modified.body;
    assert_eq!(
        introspect_not_modified
            .meta
            .as_ref()
            .map(|meta| meta.status),
        Some(304)
    );
    assert!(introspect_not_modified.tools.is_empty());
    assert_cache_headers(
        &introspect_not_modified_headers,
        introspect_not_modified
            .cache
            .as_ref()
            .expect("not-modified introspection should expose cache metadata"),
    )?;

    let preflight: PreflightResponse = http_post_json(
        client.clone(),
        url("/rpc/preflight"),
        PreflightRequest {
            connector_id: connector_a_id.clone(),
            operation: "test.echo".to_string(),
            params: Some(json!({ "message": "hello" })),
            principal: Some("agent:test".to_string()),
            zone_id: Some(ZoneId::work()),
        },
    )
    .await?;
    assert!(preflight.allowed);
    assert!(preflight.reason.is_none());

    let (invoke_request, correlation_id) = build_invoke_request(connector_a_id.clone());
    let invoke_response: InvokeResponse =
        http_post_json(client.clone(), url("/rpc/invoke"), invoke_request).await?;
    assert_eq!(invoke_response.status, InvokeStatus::Ok);
    assert!(invoke_response.receipt_id.is_some());
    assert_eq!(
        invoke_response
            .result
            .as_ref()
            .and_then(|result| result.get("echo"))
            .and_then(|echo| echo.get("message"))
            .and_then(Value::as_str),
        Some("hello")
    );
    assert!(
        correlation_id.to_string().len() > 10,
        "correlation id should be propagated from the request helper"
    );

    let doctor: serde_json::Value = http_post_json(
        client.clone(),
        url("/doctor"),
        json!({
            "zone_id": "z:work",
            "connectors": [connector_b_id.as_str()],
            "self_check": true,
        }),
    )
    .await?;
    assert_eq!(doctor["overall_status"], "OK");
    assert_eq!(
        doctor["connector_self_checks"]
            .as_array()
            .map_or(0, Vec::len),
        1
    );

    Ok(())
}

fn test_connector_config(
    connector_id: &ConnectorId,
    name: &str,
    categories: &[&str],
) -> serde_json::Value {
    json!({
        "id": connector_id.as_str(),
        "binary": env!("CARGO_BIN_EXE_fcp-test-connector"),
        "name": name,
        "description": "Binary-level host integration test connector",
        "config": {},
        "categories": categories,
        "env": {
            "FCP_TEST_CONNECTOR_ID": connector_id.as_str(),
        },
    })
}

fn test_rollout_policy() -> RolloutPolicy {
    RolloutPolicy::builder()
        .canary_percent(10)
        .min_canary_duration_secs(1)
        .success_thresholds(SuccessThresholds::new(9000, 1000, 3, 60))
        .rollback_rules(RollbackRules::new(5000, 3, 3, 60, true))
        .build()
}

fn test_rollout_rollback_policy() -> RolloutPolicy {
    RolloutPolicy::builder()
        .canary_percent(10)
        .min_canary_duration_secs(0)
        .success_thresholds(SuccessThresholds::new(10_000, 0, 1, 60))
        .rollback_rules(RollbackRules::new(0, 1, 1, 60, true))
        .build()
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn fcp_host_binary_exposes_discovery_routes() -> Result<(), Box<dyn std::error::Error>> {
    let connector_a_id = ConnectorId::from_static("fcp.test.http-echo:utility:1.0.0");
    let connector_b_id = ConnectorId::from_static("fcp.test.http-ping:utility:1.0.0");

    let host = HttpHostProcess::spawn(vec![
        test_connector_config(&connector_a_id, "HTTP Echo", &["test", "primary"]),
        test_connector_config(&connector_b_id, "HTTP Ping", &["test", "secondary"]),
    ])
    .await?;

    assert_discovery_routes(
        &host.client,
        &host.base_url,
        &connector_a_id,
        &connector_b_id,
    )
    .await?;

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn fcp_host_binary_batch_route_executes_multiple_invokes()
-> Result<(), Box<dyn std::error::Error>> {
    let connector_id = ConnectorId::from_static("fcp.test.batch-http:utility:1.0.0");
    let host = HttpHostProcess::spawn(vec![test_connector_config(
        &connector_id,
        "Batch Echo",
        &["test", "batch"],
    )])
    .await?;
    let url = |path: &str| format!("{}{path}", host.base_url);

    let (mut first_request, _) = build_invoke_request(connector_id.clone());
    first_request.input = json!({ "message": "first" });
    let (mut second_request, _) = build_invoke_request(connector_id.clone());
    second_request.input = json!({ "message": "second" });

    let response: BatchInvokeResponse = http_post_json(
        host.client.clone(),
        url("/rpc/batch"),
        json!({
            "operations": [
                batch_operation_json("op1", first_request, &[]),
                batch_operation_json("op2", second_request, &[]),
            ],
            "options": {
                "max_parallelism": 2,
                "stop_on_first_error": false,
                "timeout_ms": 30_000,
            }
        }),
    )
    .await?;

    assert_eq!(response.status, BatchStatus::Success);
    assert_eq!(response.completed, 2);
    assert_eq!(response.failed, 0);
    assert_eq!(response.skipped, 0);
    assert_eq!(response.results.len(), 2);
    assert_eq!(response.results[0].id, "op1");
    assert_eq!(response.results[1].id, "op2");
    assert_eq!(response.results[0].status, OperationResultStatus::Success);
    assert_eq!(response.results[1].status, OperationResultStatus::Success);
    assert_eq!(
        response.results[0]
            .output
            .as_ref()
            .and_then(|output| output.get("result"))
            .and_then(|result| result.get("echo"))
            .and_then(|echo| echo.get("message"))
            .and_then(Value::as_str),
        Some("first")
    );
    assert_eq!(
        response.results[1]
            .output
            .as_ref()
            .and_then(|output| output.get("result"))
            .and_then(|result| result.get("echo"))
            .and_then(|echo| echo.get("message"))
            .and_then(Value::as_str),
        Some("second")
    );

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn fcp_host_binary_batch_route_skips_dependents_after_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let connector_id = ConnectorId::from_static("fcp.test.batch-failure:utility:1.0.0");
    let host = HttpHostProcess::spawn(vec![test_connector_config(
        &connector_id,
        "Batch Failure Echo",
        &["test", "batch"],
    )])
    .await?;
    let url = |path: &str| format!("{}{path}", host.base_url);

    let unknown_connector_id = ConnectorId::from_static("fcp.test.missing:utility:1.0.0");
    let (mut failing_request, _) = build_invoke_request(unknown_connector_id);
    failing_request.input = json!({ "message": "missing" });
    let (mut dependent_request, _) = build_invoke_request(connector_id.clone());
    dependent_request.input = json!({ "message": "dependent" });
    let (mut independent_request, _) = build_invoke_request(connector_id.clone());
    independent_request.input = json!({ "message": "independent" });

    let response: BatchInvokeResponse = http_post_json(
        host.client.clone(),
        url("/rpc/batch"),
        json!({
            "operations": [
                batch_operation_json("op1", failing_request, &[]),
                batch_operation_json("op2", dependent_request, &["op1"]),
                batch_operation_json("op3", independent_request, &[]),
            ],
            "options": {
                "max_parallelism": 3,
                "stop_on_first_error": false,
                "timeout_ms": 30_000,
            }
        }),
    )
    .await?;

    assert_eq!(response.status, BatchStatus::PartialSuccess);
    assert_eq!(response.completed, 1);
    assert_eq!(response.failed, 1);
    assert_eq!(response.skipped, 1);
    assert_eq!(response.results.len(), 3);
    assert_eq!(response.results[0].status, OperationResultStatus::Error);
    assert_eq!(response.results[1].status, OperationResultStatus::Skipped);
    assert_eq!(response.results[2].status, OperationResultStatus::Success);
    assert_eq!(
        response.results[0]
            .error
            .as_ref()
            .map(|error| error.code.as_str()),
        Some("CONNECTOR_NOT_FOUND")
    );
    assert_eq!(
        response.results[1]
            .error
            .as_ref()
            .map(|error| error.code.as_str()),
        Some("DEP_FAILED")
    );
    assert_eq!(
        response.results[2]
            .output
            .as_ref()
            .and_then(|output| output.get("result"))
            .and_then(|result| result.get("echo"))
            .and_then(|echo| echo.get("message"))
            .and_then(Value::as_str),
        Some("independent")
    );

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn fcp_host_binary_cancel_route_cancels_in_flight_invoke()
-> Result<(), Box<dyn std::error::Error>> {
    let connector_id = ConnectorId::from_static("fcp.test.cancel-http:utility:1.0.0");
    let host = HttpHostProcess::spawn(vec![test_connector_config(
        &connector_id,
        "Cancel Echo",
        &["test", "cancel"],
    )])
    .await?;
    let url = |path: &str| format!("{}{path}", host.base_url);

    let (mut invoke_request, _) = build_invoke_request(connector_id.clone());
    invoke_request.input = json!({
        "message": "slow",
        "delay_ms": 300_u64,
    });
    let operation_id = invoke_request.id.to_string();

    let invoke_task = fcp_async_core::task::spawn({
        let client = host.client.clone();
        let invoke_url = url("/rpc/invoke");
        async move {
            http_post_json::<_, InvokeResponse>(client, invoke_url, invoke_request)
                .await
                .map_err(|err| err.to_string())
        }
    });

    let logs = wait_for_log_events(&host.stderr_logs, &["invoke_request"]).await?;
    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("invoke_request")
            && entry.get("connector_id").and_then(Value::as_str) == Some(connector_id.as_str())
            && entry.get("operation_id").and_then(Value::as_str) == Some(operation_id.as_str())
    }));

    fcp_async_core::time::sleep(Duration::from_millis(50)).await;

    let cancel_response: CancellationResponse = http_post_json(
        host.client.clone(),
        url("/rpc/operations/cancel"),
        CancellationRequest {
            operation_id: operation_id.clone(),
            reason: CancelReason::UserRequested,
            cleanup: CleanupBehavior::BestEffort,
            return_partial: true,
        },
    )
    .await?;

    assert_eq!(cancel_response.operation_id, operation_id);
    assert_eq!(cancel_response.outcome, CancellationOutcome::Cancelled);
    assert!(cancel_response.partial_result.is_none());
    assert!(cancel_response.checkpoint.is_none());
    assert!(cancel_response.cleanup_result.is_some());

    let invoke_response = invoke_task
        .await
        .map_err(std::io::Error::other)?
        .map_err(std::io::Error::other)?;
    assert_eq!(invoke_response.status, InvokeStatus::Ok);

    let logs = wait_for_log_events(
        &host.stderr_logs,
        &[
            "invoke_request",
            "cancel_request",
            "cancel_response",
            "invoke_response",
        ],
    )
    .await?;
    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("cancel_request")
            && entry.get("operation_id").and_then(Value::as_str) == Some(operation_id.as_str())
    }));
    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("cancel_response")
            && entry.get("operation_id").and_then(Value::as_str) == Some(operation_id.as_str())
            && entry.get("outcome").and_then(Value::as_str) == Some("Cancelled")
    }));
    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("invoke_response")
            && entry.get("operation_id").and_then(Value::as_str) == Some(operation_id.as_str())
            && entry.get("status").and_then(Value::as_str) == Some("Ok")
    }));

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn fcp_host_binary_cancel_route_returns_too_late_for_completed_invoke()
-> Result<(), Box<dyn std::error::Error>> {
    let connector_id = ConnectorId::from_static("fcp.test.cancel-too-late:utility:1.0.0");
    let host = HttpHostProcess::spawn(vec![test_connector_config(
        &connector_id,
        "Cancel Too Late Echo",
        &["test", "cancel"],
    )])
    .await?;
    let url = |path: &str| format!("{}{path}", host.base_url);

    let (invoke_request, _) = build_invoke_request(connector_id.clone());
    let operation_id = invoke_request.id.to_string();

    let invoke_response: InvokeResponse =
        http_post_json(host.client.clone(), url("/rpc/invoke"), invoke_request).await?;
    assert_eq!(invoke_response.status, InvokeStatus::Ok);

    let cancel_response: CancellationResponse = http_post_json(
        host.client.clone(),
        url("/rpc/cancel"),
        CancellationRequest {
            operation_id: operation_id.clone(),
            reason: CancelReason::UserRequested,
            cleanup: CleanupBehavior::BestEffort,
            return_partial: false,
        },
    )
    .await?;

    assert_eq!(cancel_response.operation_id, operation_id);
    assert_eq!(cancel_response.outcome, CancellationOutcome::TooLate);
    assert!(cancel_response.partial_result.is_none());
    assert!(cancel_response.checkpoint.is_none());
    assert!(cancel_response.cleanup_result.is_none());

    let logs = wait_for_log_events(
        &host.stderr_logs,
        &[
            "invoke_request",
            "invoke_response",
            "cancel_request",
            "cancel_response",
        ],
    )
    .await?;
    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("cancel_response")
            && entry.get("operation_id").and_then(Value::as_str) == Some(operation_id.as_str())
            && entry.get("outcome").and_then(Value::as_str) == Some("TooLate")
    }));

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn fcp_host_binary_rollout_routes_schedule_and_promote_canary()
-> Result<(), Box<dyn std::error::Error>> {
    let connector_id = ConnectorId::from_static("fcp.test.rollout-http:utility:1.0.0");
    let host = HttpHostProcess::spawn(vec![test_connector_config(
        &connector_id,
        "Rollout Echo",
        &["test", "rollout"],
    )])
    .await?;
    let url = |path: &str| format!("{}{path}", host.base_url);

    let policy = test_rollout_policy();
    let previous_version = semver::Version::new(1, 0, 0);
    let canary_version = semver::Version::new(1, 0, 1);
    let schedule_observed_at = chrono::Utc::now() - chrono::Duration::seconds(5);

    let scheduled: RolloutOutcome = http_post_json(
        host.client.clone(),
        url("/rpc/rollout/schedule"),
        json!({
            "connector_id": connector_id.as_str(),
            "version": canary_version.clone(),
            "previous_version": previous_version.clone(),
            "policy": policy.clone(),
            "observed_at": schedule_observed_at,
        }),
    )
    .await?;
    assert_eq!(scheduled.decision, RolloutDecision::Scheduled);
    assert_eq!(scheduled.record.state, LifecycleState::Canary);
    assert_eq!(scheduled.record.version, canary_version);
    assert_eq!(
        scheduled.record.previous_version,
        Some(previous_version.clone())
    );
    assert_eq!(scheduled.audit_event.reason_code, "canary_scheduled");

    let status: LifecycleStatus = http_get_json(
        host.client.clone(),
        url(&format!("/rpc/rollout/{}", connector_id.as_str())),
    )
    .await?;
    assert_eq!(status.state, LifecycleState::Canary);
    assert_eq!(status.version, canary_version);
    assert_eq!(
        status.rollback_target_version,
        Some(previous_version.clone())
    );

    let first: RolloutOutcome = http_post_json(
        host.client.clone(),
        url("/rpc/rollout/evaluate"),
        json!({
            "connector_id": connector_id.as_str(),
            "invocation_succeeded": true,
            "latency_ms": 20,
            "uptime_secs": 120,
            "pinned": false,
            "crashed": false,
            "policy": policy.clone(),
            "observed_at": chrono::Utc::now(),
        }),
    )
    .await?;
    assert_eq!(first.decision, RolloutDecision::Hold);
    assert_eq!(first.record.state, LifecycleState::Canary);
    assert_eq!(first.audit_event.reason_code, "insufficient_samples");

    let second: RolloutOutcome = http_post_json(
        host.client.clone(),
        url("/rpc/rollout/evaluate"),
        json!({
            "connector_id": connector_id.as_str(),
            "invocation_succeeded": true,
            "latency_ms": 25,
            "uptime_secs": 120,
            "pinned": false,
            "crashed": false,
            "policy": policy.clone(),
            "observed_at": chrono::Utc::now(),
        }),
    )
    .await?;
    assert_eq!(second.decision, RolloutDecision::Hold);
    assert_eq!(second.record.state, LifecycleState::Canary);
    assert_eq!(second.audit_event.reason_code, "insufficient_samples");

    let promoted: RolloutOutcome = http_post_json(
        host.client.clone(),
        url("/rpc/rollout/evaluate"),
        json!({
            "connector_id": connector_id.as_str(),
            "invocation_succeeded": true,
            "latency_ms": 30,
            "uptime_secs": 120,
            "pinned": false,
            "crashed": false,
            "policy": policy,
            "observed_at": chrono::Utc::now(),
        }),
    )
    .await?;
    assert_eq!(promoted.decision, RolloutDecision::Promote);
    assert_eq!(promoted.record.state, LifecycleState::Production);
    assert_eq!(promoted.audit_event.reason_code, "promotion_thresholds_met");

    let final_status: LifecycleStatus = http_get_json(
        host.client.clone(),
        url(&format!("/rpc/rollout/{}", connector_id.as_str())),
    )
    .await?;
    assert_eq!(final_status.state, LifecycleState::Production);
    assert_eq!(final_status.version, canary_version);
    assert!(!final_status.auto_promote_pending);
    assert_eq!(final_status.rollback_target_version, Some(previous_version));

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn fcp_host_binary_rollout_pin_route_pins_baseline_version()
-> Result<(), Box<dyn std::error::Error>> {
    let connector_id = ConnectorId::from_static("fcp.test.rollout-pin-baseline:utility:1.0.0");
    let host = HttpHostProcess::spawn(vec![test_connector_config(
        &connector_id,
        "Rollout Pin Baseline",
        &["test", "rollout"],
    )])
    .await?;
    let url = |path: &str| format!("{}{path}", host.base_url);

    let baseline_version = semver::Version::new(1, 0, 0);

    let pinned: PinStateResponse = http_put_json(
        host.client.clone(),
        url(&format!("/rpc/rollout/pin/{}", connector_id.as_str())),
        json!({ "version": baseline_version.clone() }),
    )
    .await?;
    assert_eq!(pinned.connector_id, connector_id.as_str());
    assert!(pinned.pinned);
    assert_eq!(pinned.version, Some(baseline_version.clone()));

    let pin_status: PinStateResponse = http_get_json(
        host.client.clone(),
        url(&format!("/rpc/rollout/pin/{}", connector_id.as_str())),
    )
    .await?;
    assert!(pin_status.pinned);
    assert_eq!(pin_status.version, Some(baseline_version));

    let logs = wait_for_log_events(
        &host.stderr_logs,
        &[
            "rollout_pin_request",
            "rollout_pin_response",
            "rollout_pin_status_request",
            "rollout_pin_status_response",
        ],
    )
    .await?;

    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("rollout_pin_response")
            && entry.get("connector_id").and_then(Value::as_str) == Some(connector_id.as_str())
            && entry.get("pinned").and_then(Value::as_bool) == Some(true)
    }));
    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("rollout_pin_status_response")
            && entry.get("connector_id").and_then(Value::as_str) == Some(connector_id.as_str())
            && entry.get("pinned").and_then(Value::as_bool) == Some(true)
    }));

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn fcp_host_binary_rollout_routes_rollback_and_emit_transition_logs()
-> Result<(), Box<dyn std::error::Error>> {
    let connector_id = ConnectorId::from_static("fcp.test.rollout-rollback:utility:1.0.0");
    let host = HttpHostProcess::spawn(vec![test_connector_config(
        &connector_id,
        "Rollout Rollback",
        &["test", "rollout"],
    )])
    .await?;
    let url = |path: &str| format!("{}{path}", host.base_url);

    let policy = test_rollout_rollback_policy();
    let previous_version = semver::Version::new(1, 0, 0);
    let canary_version = semver::Version::new(1, 0, 1);

    let pinned_baseline: PinStateResponse = http_put_json(
        host.client.clone(),
        url(&format!("/rpc/rollout/pin/{}", connector_id.as_str())),
        json!({ "version": previous_version.clone() }),
    )
    .await?;
    assert_eq!(pinned_baseline.connector_id, connector_id.as_str());
    assert!(pinned_baseline.pinned);
    assert_eq!(pinned_baseline.version, Some(previous_version.clone()));

    let pin_status_before_rollout: PinStateResponse = http_get_json(
        host.client.clone(),
        url(&format!("/rpc/rollout/pin/{}", connector_id.as_str())),
    )
    .await?;
    assert!(pin_status_before_rollout.pinned);
    assert_eq!(
        pin_status_before_rollout.version,
        Some(previous_version.clone())
    );

    let scheduled: RolloutOutcome = http_post_json(
        host.client.clone(),
        url("/rpc/rollout/schedule"),
        json!({
            "connector_id": connector_id.as_str(),
            "version": canary_version.clone(),
            "previous_version": previous_version.clone(),
            "policy": policy.clone(),
            "observed_at": chrono::Utc::now() - chrono::Duration::seconds(5),
        }),
    )
    .await?;
    assert_eq!(scheduled.decision, RolloutDecision::Scheduled);
    assert_eq!(scheduled.record.state, LifecycleState::Canary);
    assert_eq!(scheduled.audit_event.reason_code, "canary_scheduled");

    let rolled_back: RolloutOutcome = http_post_json(
        host.client.clone(),
        url("/rpc/rollout/evaluate"),
        json!({
            "connector_id": connector_id.as_str(),
            "invocation_succeeded": false,
            "latency_ms": 15,
            "uptime_secs": 120,
            "pinned": false,
            "crashed": false,
            "policy": policy,
            "observed_at": chrono::Utc::now(),
        }),
    )
    .await?;
    assert_eq!(rolled_back.decision, RolloutDecision::Rollback);
    assert_eq!(rolled_back.record.state, LifecycleState::RolledBack);
    assert_eq!(
        rolled_back.audit_event.reason_code,
        "consecutive_failures_exceeded"
    );
    assert!(
        rolled_back
            .audit_event
            .evidence_digest
            .starts_with("blake3-256:")
    );

    let final_status: LifecycleStatus = http_get_json(
        host.client.clone(),
        url(&format!("/rpc/rollout/{}", connector_id.as_str())),
    )
    .await?;
    assert_eq!(final_status.state, LifecycleState::RolledBack);
    assert_eq!(final_status.version, canary_version);
    assert_eq!(
        final_status.rollback_target_version,
        Some(previous_version.clone())
    );
    assert!(!final_status.auto_rollback_pending);

    let restored_pin_status: PinStateResponse = http_get_json(
        host.client.clone(),
        url(&format!("/rpc/rollout/pin/{}", connector_id.as_str())),
    )
    .await?;
    assert!(restored_pin_status.pinned);
    assert_eq!(restored_pin_status.version, Some(previous_version));

    let logs = wait_for_log_events(
        &host.stderr_logs,
        &[
            "rollout_pin_request",
            "rollout_pin_response",
            "rollout_pin_status_request",
            "rollout_pin_status_response",
            "rollout_schedule_request",
            "rollout_schedule_response",
            "rollout_evaluate_request",
            "rollout_evaluate_response",
            "rollout_status_request",
            "rollout_status_response",
        ],
    )
    .await?;

    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("rollout_pin_response")
            && entry.get("connector_id").and_then(Value::as_str) == Some(connector_id.as_str())
            && entry.get("pinned").and_then(Value::as_bool) == Some(true)
    }));
    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("rollout_pin_status_response")
            && entry.get("connector_id").and_then(Value::as_str) == Some(connector_id.as_str())
            && entry.get("pinned").and_then(Value::as_bool) == Some(true)
    }));
    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("rollout_schedule_response")
            && entry.get("connector_id").and_then(Value::as_str) == Some(connector_id.as_str())
            && entry.get("reason_code").and_then(Value::as_str) == Some("canary_scheduled")
            && entry.get("duration_ms").and_then(Value::as_u64).is_some()
    }));
    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("rollout_evaluate_response")
            && entry.get("connector_id").and_then(Value::as_str) == Some(connector_id.as_str())
            && entry.get("reason_code").and_then(Value::as_str)
                == Some("consecutive_failures_exceeded")
            && entry.get("duration_ms").and_then(Value::as_u64).is_some()
    }));
    assert!(logs.iter().any(|entry| {
        entry.get("message").and_then(Value::as_str) == Some("rollout decision")
            && entry.get("connector_id").and_then(Value::as_str) == Some(connector_id.as_str())
            && entry.get("decision").and_then(Value::as_str) == Some("scheduled")
            && entry.get("state_before").and_then(Value::as_str) == Some("pending")
            && entry.get("state_after").and_then(Value::as_str) == Some("canary")
    }));
    assert!(logs.iter().any(|entry| {
        entry.get("message").and_then(Value::as_str) == Some("rollout decision")
            && entry.get("connector_id").and_then(Value::as_str) == Some(connector_id.as_str())
            && entry.get("decision").and_then(Value::as_str) == Some("rollback")
            && entry.get("state_before").and_then(Value::as_str) == Some("canary")
            && entry.get("state_after").and_then(Value::as_str) == Some("rolled_back")
            && entry
                .get("evidence_digest")
                .and_then(Value::as_str)
                .is_some_and(|digest| digest.starts_with("blake3-256:"))
    }));

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn fcp_host_binary_pin_status_and_manual_rollback_routes_emit_logs()
-> Result<(), Box<dyn std::error::Error>> {
    let connector_id = ConnectorId::from_static("fcp.test.rollout-pin:utility:1.0.0");
    let host = HttpHostProcess::spawn(vec![test_connector_config(
        &connector_id,
        "Rollout Pin",
        &["test", "rollout"],
    )])
    .await?;
    let url = |path: &str| format!("{}{path}", host.base_url);

    let previous_version = semver::Version::new(1, 0, 0);
    let canary_version = semver::Version::new(1, 0, 1);
    let policy = test_rollout_policy();

    let pinned: PinStateResponse = http_put_json(
        host.client.clone(),
        url(&format!("/rpc/rollout/pin/{}", connector_id.as_str())),
        json!({ "version": canary_version.clone() }),
    )
    .await?;
    assert_eq!(pinned.connector_id, connector_id.as_str());
    assert!(pinned.pinned);
    assert_eq!(pinned.version, Some(canary_version.clone()));

    let pin_status: PinStateResponse = http_get_json(
        host.client.clone(),
        url(&format!("/rpc/rollout/pin/{}", connector_id.as_str())),
    )
    .await?;
    assert!(pin_status.pinned);
    assert_eq!(pin_status.version, Some(canary_version.clone()));

    let _scheduled: RolloutOutcome = http_post_json(
        host.client.clone(),
        url("/rpc/rollout/schedule"),
        json!({
            "connector_id": connector_id.as_str(),
            "version": canary_version.clone(),
            "previous_version": previous_version.clone(),
            "policy": policy.clone(),
            "observed_at": chrono::Utc::now() - chrono::Duration::seconds(5),
        }),
    )
    .await?;

    let status: RolloutStatusResponse = http_get_json(
        host.client.clone(),
        url(&format!("/rpc/rollout/{}", connector_id.as_str())),
    )
    .await?;
    assert_eq!(status.status.state, LifecycleState::Canary);
    assert!(status.pinned);
    assert_eq!(status.pinned_version, Some(canary_version.clone()));
    assert_eq!(status.canary_percent, policy.canary_percent);

    let rollback: ManualRollbackResponse = http_post_json(
        host.client.clone(),
        url("/rpc/rollout/rollback"),
        json!({
            "connector_id": connector_id.as_str(),
            "to_version": previous_version.clone(),
        }),
    )
    .await?;
    assert_eq!(rollback.connector_id, connector_id.as_str());
    assert_eq!(rollback.state, LifecycleState::RolledBack);
    assert_eq!(rollback.from_version, canary_version.clone());
    assert_eq!(rollback.to_version, previous_version.clone());
    assert!(rollback.message.contains("rolled back"));

    let repinned: PinStateResponse = http_get_json(
        host.client.clone(),
        url(&format!("/rpc/rollout/pin/{}", connector_id.as_str())),
    )
    .await?;
    assert!(repinned.pinned);
    assert_eq!(repinned.version, Some(previous_version.clone()));

    let unpinned: PinStateResponse = http_delete_json(
        host.client.clone(),
        url(&format!("/rpc/rollout/pin/{}", connector_id.as_str())),
    )
    .await?;
    assert!(!unpinned.pinned);
    assert_eq!(unpinned.version, None);

    let logs = wait_for_log_events(
        &host.stderr_logs,
        &[
            "rollout_pin_request",
            "rollout_pin_response",
            "rollout_pin_status_request",
            "rollout_pin_status_response",
            "rollout_manual_rollback_request",
            "rollout_manual_rollback_response",
            "rollout_unpin_request",
            "rollout_unpin_response",
        ],
    )
    .await?;

    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("rollout_pin_response")
            && entry.get("connector_id").and_then(Value::as_str) == Some(connector_id.as_str())
            && entry.get("pinned").and_then(Value::as_bool) == Some(true)
    }));
    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("rollout_manual_rollback_response")
            && entry.get("connector_id").and_then(Value::as_str) == Some(connector_id.as_str())
            && entry.get("from_version").and_then(Value::as_str) == Some("1.0.1")
            && entry.get("to_version").and_then(Value::as_str) == Some("1.0.0")
            && entry.get("state").and_then(Value::as_str) == Some("rolled_back")
    }));
    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("rollout_unpin_response")
            && entry.get("connector_id").and_then(Value::as_str) == Some(connector_id.as_str())
    }));

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn fcp_host_binary_emits_structured_endpoint_logs() -> Result<(), Box<dyn std::error::Error>>
{
    let connector_a_id = ConnectorId::from_static("fcp.test.log-echo:utility:1.0.0");
    let connector_b_id = ConnectorId::from_static("fcp.test.log-ping:utility:1.0.0");

    let host = HttpHostProcess::spawn(vec![
        test_connector_config(&connector_a_id, "Log Echo", &["test", "primary"]),
        test_connector_config(&connector_b_id, "Log Ping", &["test", "secondary"]),
    ])
    .await?;

    assert_discovery_routes(
        &host.client,
        &host.base_url,
        &connector_a_id,
        &connector_b_id,
    )
    .await?;

    let logs = wait_for_log_events(
        &host.stderr_logs,
        &[
            "discover_request",
            "discover_response",
            "introspect_request",
            "introspect_response",
            "invoke_request",
            "invoke_response",
            "preflight_check",
            "doctor_request",
            "doctor_response",
            "health_response",
        ],
    )
    .await?;

    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("discover_response")
            && entry.get("connector_count").and_then(Value::as_u64) == Some(2)
            && entry.get("registry_version").and_then(Value::as_u64) == Some(1)
            && entry.get("cache_hit").and_then(Value::as_bool) == Some(false)
    }));
    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("discover_response")
            && entry.get("connector_count").and_then(Value::as_u64) == Some(1)
            && entry.get("registry_version").and_then(Value::as_u64) == Some(1)
            && entry.get("cache_hit").and_then(Value::as_bool) == Some(true)
    }));
    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("introspect_response")
            && entry.get("connector_id").and_then(Value::as_str) == Some(connector_a_id.as_str())
            && entry.get("tool_count").and_then(Value::as_u64) == Some(1)
    }));
    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("preflight_check")
            && entry.get("connector_id").and_then(Value::as_str) == Some(connector_a_id.as_str())
            && entry.get("operation").and_then(Value::as_str) == Some("test.echo")
            && entry.get("allowed").and_then(Value::as_bool) == Some(true)
    }));
    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("invoke_request")
            && entry.get("connector_id").and_then(Value::as_str) == Some(connector_a_id.as_str())
            && entry.get("operation").and_then(Value::as_str) == Some("test.echo")
    }));
    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("invoke_response")
            && entry.get("connector_id").and_then(Value::as_str) == Some(connector_a_id.as_str())
            && entry.get("operation").and_then(Value::as_str) == Some("test.echo")
            && entry.get("status").and_then(Value::as_str) == Some("Ok")
    }));
    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("doctor_response")
            && entry.get("overall_status").and_then(Value::as_str) == Some("Ok")
    }));
    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("health_response")
            && entry.get("connector_count").and_then(Value::as_u64) == Some(2)
    }));

    Ok(())
}

#[cfg(unix)]
#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn fcp_host_binary_exposes_discovery_routes_over_unix_socket()
-> Result<(), Box<dyn std::error::Error>> {
    let connector_a_id = ConnectorId::from_static("fcp.test.unix-echo:utility:1.0.0");
    let connector_b_id = ConnectorId::from_static("fcp.test.unix-ping:utility:1.0.0");

    let host = UnixHostProcess::spawn(vec![
        test_connector_config(&connector_a_id, "Unix Echo", &["test", "primary"]),
        test_connector_config(&connector_b_id, "Unix Ping", &["test", "secondary"]),
    ])
    .await?;

    assert_discovery_routes(
        &host.client,
        &host.base_url,
        &connector_a_id,
        &connector_b_id,
    )
    .await?;

    Ok(())
}

#[test]
fn host_log_schema_example() {
    let mut logger = E2eLogger::new();
    let correlation_id = CorrelationId::new().to_string();

    logger.push(E2eLogEntry::new(
        "info",
        "host_connector_integration",
        "fcp-host",
        "execute",
        &correlation_id,
        "pass",
        5,
        AssertionsSummary::new(1, 0),
        json!({ "connector_count": 2 }),
    ));

    let payload = logger.to_json_lines();
    let capture = LogCapture::new();
    capture.push_line(&payload);
    capture.assert_valid();
}
