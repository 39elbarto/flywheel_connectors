//! Integration tests: fcp-host discovery/introspection against real subprocess connectors.
//!
//! Bead: bd-219o

use std::collections::HashMap;
use std::sync::Arc;

use fcp_core::{
    CapabilityToken, ConnectorHealth, ConnectorId, CorrelationId, HandshakeRequest, HealthSnapshot,
    Introspection, InvokeRequest, InvokeResponse, InvokeStatus, OperationId, RequestId,
    SelfCheckReport, ZoneId,
};
use fcp_e2e::{AssertionsSummary, ConnectorProcessRunner, E2eLogEntry, E2eLogger};
use fcp_host::{
    ConnectorArchetype, ConnectorRegistry, ConnectorSummary, DiscoveryEndpoint, PolicyEngine,
    PreflightRequest, PreflightResponse,
};
use fcp_testkit::LogCapture;
use serde_json::json;
use tokio::sync::Mutex;

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
        runner.terminate().await
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

#[tokio::test]
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
