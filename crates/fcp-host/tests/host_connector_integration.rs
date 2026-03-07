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
    Introspection, InvokeRequest, InvokeResponse, InvokeStatus, OperationId, RequestId,
    SelfCheckReport, ZoneId,
};
use fcp_e2e::{AssertionsSummary, ConnectorProcessRunner, E2eLogEntry, E2eLogger};
use fcp_host::{
    ConnectorArchetype, ConnectorRegistry, ConnectorSummary, DiscoveryEndpoint, DiscoveryResponse,
    HostHealthResponse, HostHealthStatus, IntrospectionResponse, PolicyEngine, PreflightRequest,
    PreflightResponse,
};
use fcp_testkit::LogCapture;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

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
    let cx = test_cx();
    let value = asupersync_tokio_compat::runtime::with_tokio_context(&cx, move || async move {
        client
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .json::<T>()
            .await
    })
    .await
    .ok_or_else(|| std::io::Error::other("tokio-compat GET JSON request cancelled"))??;
    Ok(value)
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
    let cx = test_cx();
    let value = asupersync_tokio_compat::runtime::with_tokio_context(&cx, move || async move {
        client
            .post(url)
            .json(&body)
            .send()
            .await?
            .error_for_status()?
            .json::<T>()
            .await
    })
    .await
    .ok_or_else(|| std::io::Error::other("tokio-compat POST JSON request cancelled"))??;
    Ok(value)
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

    let discover_all: DiscoveryResponse =
        http_post_json(client.clone(), url("/rpc/discover"), json!({})).await?;
    assert_eq!(discover_all.connectors.len(), 2);
    let discover_all_cache = discover_all
        .cache
        .as_ref()
        .expect("discover response should expose cache metadata");
    assert!(!discover_all_cache.etag.is_empty());
    assert!(discover_all.meta.is_none());
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

    let discover_filtered: DiscoveryResponse = http_post_json(
        client.clone(),
        url("/rpc/discover"),
        json!({ "category": "primary" }),
    )
    .await?;
    assert_eq!(discover_filtered.connectors.len(), 1);
    let discover_filtered_cache = discover_filtered
        .cache
        .as_ref()
        .expect("filtered discover response should expose cache metadata");
    assert_ne!(discover_all_cache.etag, discover_filtered_cache.etag);
    assert_eq!(discover_filtered.connectors[0].id, *connector_a_id);
    assert_eq!(discover_filtered.connectors[0].tool_count, 1);
    assert!(matches!(
        discover_filtered.connectors[0].max_safety_tier,
        fcp_core::SafetyTier::Safe
    ));
    assert!(discover_filtered.connectors[0].health.is_healthy());

    let discover_not_modified: DiscoveryResponse = http_post_json(
        client.clone(),
        url("/rpc/discover"),
        json!({
            "_cache": { "if_none_match": discover_all_cache.etag }
        }),
    )
    .await?;
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

    let introspection: IntrospectionResponse = http_get_json(
        client.clone(),
        url(&format!("/rpc/introspect/{}", connector_a_id.as_str())),
    )
    .await?;
    assert_eq!(introspection.connector.id, *connector_a_id);
    assert_eq!(introspection.connector.tool_count, 1);
    assert!(matches!(
        introspection.connector.max_safety_tier,
        fcp_core::SafetyTier::Safe
    ));
    assert!(introspection.connector.health.is_healthy());
    assert_eq!(introspection.tools.len(), 1);
    assert_eq!(introspection.tools[0].name, "test.echo");

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
