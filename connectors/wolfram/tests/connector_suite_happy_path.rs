use fcp_e2e::{ConnectorSuite, E2eRunner, InvokeExpectations};
use fcp_prelude::{
    CapabilityId, CapabilityToken, ConnectorId, ConnectorMetrics, FcpConnector, FcpError,
    HandshakeRequest, HandshakeResponse, HealthSnapshot, InstanceId, Introspection, InvokeRequest,
    InvokeResponse, OperationId, RequestId, ShutdownRequest, SimulateRequest, SimulateResponse,
    SubscribeRequest, SubscribeResponse, UnsubscribeRequest, ZoneId,
};
use fcp_wolfram::WolframConnector;
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path, query_param},
};

const OP_SHORT_ANSWER: &str = "wolfram.short_answer";
const CAP_QUERY: &str = "wolfram.query";

struct WolframSuiteAdapter {
    connector: WolframConnector,
    id: ConnectorId,
}

impl WolframSuiteAdapter {
    fn new() -> Self {
        Self {
            connector: WolframConnector::new(),
            id: ConnectorId::from_static("wolfram"),
        }
    }
}

fcp_core::impl_fcp_sealed!(WolframSuiteAdapter);

#[fcp_core::async_trait]
impl FcpConnector for WolframSuiteAdapter {
    fn id(&self) -> &ConnectorId {
        &self.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> fcp_core::FcpResult<()> {
        self.connector.handle_configure(config).await.map(|_| ())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> fcp_core::FcpResult<HandshakeResponse> {
        let payload = serde_json::to_value(req).map_err(|error| FcpError::Internal {
            message: format!("Failed to serialize handshake request: {error}"),
        })?;
        let response = self.connector.handle_handshake(payload).await?;
        serde_json::from_value(response).map_err(|error| FcpError::Internal {
            message: format!("Failed to parse handshake response: {error}"),
        })
    }

    async fn health(&self) -> HealthSnapshot {
        match self
            .connector
            .handle_health()
            .get("status")
            .and_then(serde_json::Value::as_str)
        {
            Some("healthy") => HealthSnapshot::ready(),
            Some(other) => HealthSnapshot::degraded(format!("wolfram_status:{other}")),
            None => HealthSnapshot::error("wolfram_status:missing"),
        }
    }

    fn metrics(&self) -> ConnectorMetrics {
        ConnectorMetrics::default()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> fcp_core::FcpResult<()> {
        self.connector.shutdown();
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        self.connector.handle_introspect()
    }

    async fn invoke(&self, req: InvokeRequest) -> fcp_core::FcpResult<InvokeResponse> {
        let request_id = req.id;
        let operation = req.operation.as_str().to_string();
        let value = self
            .connector
            .handle_invoke(json!({
                "operation": operation,
                "input": req.input,
            }))
            .await?;
        Ok(InvokeResponse::ok(request_id, value))
    }

    async fn simulate(&self, req: SimulateRequest) -> fcp_core::FcpResult<SimulateResponse> {
        let value = self
            .connector
            .handle_simulate(
                serde_json::to_value(req).map_err(|error| FcpError::Internal {
                    message: format!("Failed to serialize simulate request: {error}"),
                })?,
            )
            .await?;
        serde_json::from_value(value).map_err(|error| FcpError::Internal {
            message: format!("Failed to parse simulate response: {error}"),
        })
    }

    async fn subscribe(&self, _req: SubscribeRequest) -> fcp_core::FcpResult<SubscribeResponse> {
        Err(FcpError::StreamingNotSupported)
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> fcp_core::FcpResult<()> {
        Ok(())
    }
}

fn handshake_request() -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key: [23u8; 32],
        nonce: [17u8; 32],
        capabilities_requested: vec![CapabilityId::from_static(CAP_QUERY)],
        host: None,
        transport_caps: None,
        requested_instance_id: Some(InstanceId::new()),
    }
}

fn short_answer_invoke(id: &'static str) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new(id),
        connector_id: ConnectorId::from_static("wolfram"),
        operation: OperationId::from_static(OP_SHORT_ANSWER),
        zone_id: ZoneId::work(),
        input: json!({
            "input": "population of France",
            "app_id": "wolfram-suite-app"
        }),
        capability_token: CapabilityToken::test_token(),
        holder_proof: None,
        context: None,
        idempotency_key: None,
        lease_seq: None,
        deadline_ms: None,
        correlation_id: None,
        provenance: None,
        approval_tokens: Vec::new(),
    }
}

fn suite(server: &MockServer) -> ConnectorSuite {
    ConnectorSuite {
        test_name: "wolfram_short_answer_connector_suite_happy_path".into(),
        config: json!({
            "credential_id": fcp_core::CredentialId::new(),
            "base_url": server.uri(),
            "allow_mock_base_url": true
        }),
        handshake: handshake_request(),
        invoke: Some(short_answer_invoke("wolfram-short-answer-suite")),
        invoke_expectations: InvokeExpectations::default(),
    }
}

#[fcp_async_core::runtime::test]
async fn connector_suite_short_answer_happy_path_uses_mock_server() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/result"))
        .and(query_param("i", "population of France"))
        .and(query_param("appid", "wolfram-suite-app"))
        .respond_with(ResponseTemplate::new(200).set_body_string("67.39 million people"))
        .expect(1)
        .mount(&server)
        .await;

    let mut connector = WolframSuiteAdapter::new();
    let mut runner = E2eRunner::new("fcp-wolfram");
    let report = runner
        .run_connector_suite(&mut connector, suite(&server))
        .await
        .expect("connector suite run");

    assert!(report.passed, "connector suite should pass");
    assert!(!report.logs.is_empty(), "structured logs should be present");
}
