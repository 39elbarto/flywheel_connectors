//! Integration tests: fcp-host discovery/introspection against real subprocess connectors.
//!
//! Bead: bd-219o

use std::collections::HashMap;
use std::net::TcpListener as StdTcpListener;
#[cfg(unix)]
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

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
use serde_json::json;

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

struct HttpHostProcess {
    child: Child,
    client: reqwest::Client,
    base_url: String,
}

async fn wait_for_host_readiness(
    child: &mut Child,
    client: &reqwest::Client,
    base_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    for _ in 0..80 {
        if let Some(status) = child.try_wait()? {
            return Err(format!("fcp-host exited early with {status}").into());
        }

        match client.get(format!("{base_url}/rpc/health")).send().await {
            Ok(response) if response.status().is_success() => return Ok(()),
            Ok(_) | Err(_) => fcp_async_core::time::sleep(Duration::from_millis(50)).await,
        }
    }

    let _ = child.kill();
    let _ = child.wait();
    Err("timed out waiting for fcp-host readiness".into())
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

        let client = reqwest::Client::new();
        wait_for_host_readiness(&mut child, &client, &base_url).await?;

        Ok(Self {
            child,
            client,
            base_url,
        })
    }
}

impl Drop for HttpHostProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(unix)]
struct UnixHostProcess {
    child: Child,
    client: reqwest::Client,
    base_url: String,
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

        let client = reqwest::Client::builder()
            .unix_socket(socket_path)
            .build()?;
        wait_for_host_readiness(&mut child, &client, &base_url).await?;

        Ok(Self {
            child,
            client,
            base_url,
        })
    }
}

#[cfg(unix)]
impl Drop for UnixHostProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
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

async fn assert_discovery_routes(
    client: &reqwest::Client,
    base_url: &str,
    connector_a_id: &ConnectorId,
    connector_b_id: &ConnectorId,
) -> Result<(), Box<dyn std::error::Error>> {
    let url = |path: &str| format!("{base_url}{path}");

    let health = client
        .get(url("/rpc/health"))
        .send()
        .await?
        .error_for_status()?
        .json::<HostHealthResponse>()
        .await?;
    assert_eq!(health.status, HostHealthStatus::Healthy);
    assert_eq!(health.connectors.len(), 2);
    assert!(health.connectors.contains_key(connector_a_id));
    assert!(health.connectors.contains_key(connector_b_id));

    let discover_all = client
        .post(url("/rpc/discover"))
        .json(&json!({}))
        .send()
        .await?
        .error_for_status()?
        .json::<DiscoveryResponse>()
        .await?;
    assert_eq!(discover_all.connectors.len(), 2);

    let discover_filtered = client
        .post(url("/rpc/discover"))
        .json(&json!({ "category": "primary" }))
        .send()
        .await?
        .error_for_status()?
        .json::<DiscoveryResponse>()
        .await?;
    assert_eq!(discover_filtered.connectors.len(), 1);
    assert_eq!(discover_filtered.connectors[0].id, *connector_a_id);

    let introspection = client
        .get(url(&format!("/rpc/introspect/{}", connector_a_id.as_str())))
        .send()
        .await?
        .error_for_status()?
        .json::<IntrospectionResponse>()
        .await?;
    assert_eq!(introspection.connector.id, *connector_a_id);
    assert_eq!(introspection.tools.len(), 1);
    assert_eq!(introspection.tools[0].name, "test.echo");

    let preflight = client
        .post(url("/rpc/preflight"))
        .json(&PreflightRequest {
            connector_id: connector_a_id.clone(),
            operation: "test.echo".to_string(),
            params: Some(json!({ "message": "hello" })),
            principal: Some("agent:test".to_string()),
            zone_id: Some(ZoneId::work()),
        })
        .send()
        .await?
        .error_for_status()?
        .json::<PreflightResponse>()
        .await?;
    assert!(preflight.allowed);
    assert!(preflight.reason.is_none());

    let doctor = client
        .post(url("/doctor"))
        .json(&json!({
            "zone_id": "z:work",
            "connectors": [connector_b_id.as_str()],
            "self_check": true,
        }))
        .send()
        .await?
        .error_for_status()?
        .json::<serde_json::Value>()
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
