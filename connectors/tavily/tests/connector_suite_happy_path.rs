use fcp_e2e::{ConnectorSuite, E2eRunner, InvokeExpectations};
use fcp_prelude::{
    AgentHint, CapabilityGrant, CapabilityId, CapabilityToken, ConnectorId, ConnectorMetrics,
    FcpConnector, FcpError, HandshakeRequest, HandshakeResponse, HealthSnapshot, IdempotencyClass,
    InstanceId, Introspection, InvokeRequest, InvokeResponse, OperationId, OperationInfo,
    RequestId, RiskLevel, SafetyTier, SessionId, ShutdownRequest, SimulateRequest,
    SimulateResponse, SubscribeRequest, SubscribeResponse, UnsubscribeRequest, ZoneId,
};
use fcp_tavily::TavilyConnector;
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

const OP_SEARCH: &str = "tavily.search";
const CAP_SEARCH: &str = "tavily.search";

struct TavilySuiteAdapter {
    connector: TavilyConnector,
    id: ConnectorId,
}

impl TavilySuiteAdapter {
    fn new() -> Self {
        Self {
            connector: TavilyConnector::new(),
            id: ConnectorId::from_static("fcp.tavily"),
        }
    }
}

fcp_core::impl_fcp_sealed!(TavilySuiteAdapter);

#[fcp_core::async_trait]
impl FcpConnector for TavilySuiteAdapter {
    fn id(&self) -> &ConnectorId {
        &self.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> fcp_core::FcpResult<()> {
        self.connector.handle_configure(config).await.map(|_| ())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> fcp_core::FcpResult<HandshakeResponse> {
        self.connector
            .handle_handshake(json!({ "session_id": "tavily-connector-suite" }))
            .await?;

        let capabilities_granted = req
            .capabilities_requested
            .into_iter()
            .map(|capability| CapabilityGrant {
                capability,
                operation: None,
            })
            .collect();

        Ok(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
            session_id: SessionId::new(),
            manifest_hash: "sha256:tavily-connector-suite".into(),
            nonce: req.nonce,
            event_caps: None,
            auth_caps: None,
            op_catalog_hash: None,
        })
    }

    async fn health(&self) -> HealthSnapshot {
        match self.connector.handle_health().await {
            Ok(payload) => match payload.get("status").and_then(serde_json::Value::as_str) {
                Some("healthy") => HealthSnapshot::ready(),
                Some(other) => HealthSnapshot::degraded(format!("tavily_status:{other}")),
                None => HealthSnapshot::error("tavily_status:missing"),
            },
            Err(error) => HealthSnapshot::error(error.to_string()),
        }
    }

    fn metrics(&self) -> ConnectorMetrics {
        ConnectorMetrics::default()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> fcp_core::FcpResult<()> {
        self.connector.handle_shutdown(json!({})).await.map(|_| ())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: vec![OperationInfo {
                id: OperationId::from_static(OP_SEARCH),
                summary: "Run a Tavily search".into(),
                description: None,
                input_schema: json!({
                    "type": "object",
                    "required": ["query"],
                    "properties": {
                        "query": { "type": "string" },
                        "max_results": { "type": "integer" }
                    }
                }),
                output_schema: json!({ "type": "object" }),
                capability: CapabilityId::from_static(CAP_SEARCH),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Use for read-only web search over Tavily.".into(),
                    common_mistakes: Vec::new(),
                    examples: vec![r#"{"query":"fcp connector"}"#.into()],
                    related: Vec::new(),
                },
                rate_limit: None,
                requires_approval: None,
            }],
            events: Vec::new(),
            resource_types: Vec::new(),
            auth_caps: None,
            event_caps: None,
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> fcp_core::FcpResult<InvokeResponse> {
        let request_id = req.id;
        let operation_id = req.operation.as_str().to_string();
        let value = self
            .connector
            .handle_invoke(json!({
                "operation_id": operation_id,
                "input": req.input,
            }))
            .await?;
        Ok(InvokeResponse::ok(request_id, value))
    }

    async fn simulate(&self, req: SimulateRequest) -> fcp_core::FcpResult<SimulateResponse> {
        let request_id = req.id;
        let operation_id = req.operation.as_str().to_string();
        let value = self
            .connector
            .handle_simulate(json!({
                "operation_id": operation_id,
                "input": req.input,
            }))
            .await?;
        if value
            .get("allowed")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        {
            Ok(SimulateResponse::allowed(request_id))
        } else {
            Ok(SimulateResponse::denied(
                request_id,
                "operation is not supported",
                "FCP-3010",
            ))
        }
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
        host_public_key: [29u8; 32],
        nonce: [19u8; 32],
        capabilities_requested: vec![CapabilityId::from_static(CAP_SEARCH)],
        host: None,
        transport_caps: None,
        requested_instance_id: Some(InstanceId::new()),
    }
}

fn search_invoke(id: &'static str) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new(id),
        connector_id: ConnectorId::from_static("fcp.tavily"),
        operation: OperationId::from_static(OP_SEARCH),
        zone_id: ZoneId::work(),
        input: json!({
            "query": "secure connector protocol",
            "max_results": 2
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

fn suite(server: &MockServer, test_name: &'static str, expect_error: bool) -> ConnectorSuite {
    ConnectorSuite {
        test_name: test_name.into(),
        config: json!({
            "api_key": "tavily_test_key",
            "base_url": server.uri()
        }),
        handshake: handshake_request(),
        invoke: Some(search_invoke(test_name)),
        invoke_expectations: InvokeExpectations {
            expect_error,
            ..InvokeExpectations::default()
        },
    }
}

#[fcp_async_core::runtime::test]
async fn connector_suite_search_happy_path_uses_mock_server() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/search"))
        .and(header("Authorization", "Bearer tavily_test_key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "answer": "FCP connects tools safely.",
            "results": [
                {"title": "FCP", "url": "https://example.test/fcp"}
            ]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let mut connector = TavilySuiteAdapter::new();
    let mut runner = E2eRunner::new("fcp-tavily");
    let report = runner
        .run_connector_suite(
            &mut connector,
            suite(&server, "tavily_search_connector_suite_happy_path", false),
        )
        .await
        .expect("connector suite run");

    assert!(report.passed, "connector suite should pass");
    assert!(!report.logs.is_empty(), "structured logs should be present");
}

#[fcp_async_core::runtime::test]
async fn connector_suite_search_error_path_is_expected() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/search"))
        .and(header("Authorization", "Bearer tavily_test_key"))
        .respond_with(ResponseTemplate::new(503).set_body_json(json!({
            "error": "upstream unavailable"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let mut connector = TavilySuiteAdapter::new();
    let mut runner = E2eRunner::new("fcp-tavily");
    let report = runner
        .run_connector_suite(
            &mut connector,
            suite(&server, "tavily_search_connector_suite_error_path", true),
        )
        .await
        .expect("connector suite run");

    assert!(report.passed, "expected upstream error should pass suite");
}
