use fcp_prelude::{
    AgentHint, CapabilityGrant, CapabilityId, CapabilityToken, ConnectorId, ConnectorMetrics,
    FcpConnector, FcpError, HandshakeRequest, HandshakeResponse, HealthSnapshot, IdempotencyClass,
    InstanceId, Introspection, InvokeRequest, InvokeResponse, OperationId, OperationInfo,
    RequestId, RiskLevel, SafetyTier, SessionId, ShutdownRequest, SimulateRequest,
    SimulateResponse, SubscribeRequest, SubscribeResponse, UnsubscribeRequest, ZoneId,
};
use fcp_e2e::{ConnectorSuite, E2eRunner, InvokeExpectations};
use fcp_openrouter::OpenRouterConnector;
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

const OP_MODELS_LIST: &str = "openrouter.models.list";
const CAP_MODELS: &str = "openrouter.models";

struct OpenRouterSuiteAdapter {
    connector: OpenRouterConnector,
    id: ConnectorId,
}

impl OpenRouterSuiteAdapter {
    fn new() -> Self {
        Self {
            connector: OpenRouterConnector::new(),
            id: ConnectorId::from_static("fcp.openrouter"),
        }
    }
}

fcp_core::impl_fcp_sealed!(OpenRouterSuiteAdapter);

#[fcp_core::async_trait]
impl FcpConnector for OpenRouterSuiteAdapter {
    fn id(&self) -> &ConnectorId {
        &self.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> fcp_core::FcpResult<()> {
        self.connector.handle_configure(config).await.map(|_| ())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> fcp_core::FcpResult<HandshakeResponse> {
        self.connector
            .handle_handshake(json!({ "session_id": "openrouter-connector-suite" }))
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
            manifest_hash: "sha256:openrouter-connector-suite".into(),
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
                Some(other) => HealthSnapshot::degraded(format!("openrouter_status:{other}")),
                None => HealthSnapshot::error("openrouter_status:missing"),
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
                id: OperationId::from_static(OP_MODELS_LIST),
                summary: "List OpenRouter models".into(),
                description: None,
                input_schema: json!({ "type": "object", "properties": {} }),
                output_schema: json!({ "type": "object" }),
                capability: CapabilityId::from_static(CAP_MODELS),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Use to discover OpenRouter model identifiers.".into(),
                    common_mistakes: Vec::new(),
                    examples: vec!["{}".into()],
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
        host_public_key: [31u8; 32],
        nonce: [37u8; 32],
        capabilities_requested: vec![CapabilityId::from_static(CAP_MODELS)],
        host: None,
        transport_caps: None,
        requested_instance_id: Some(InstanceId::new()),
    }
}

fn models_invoke(id: &'static str) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new(id),
        connector_id: ConnectorId::from_static("fcp.openrouter"),
        operation: OperationId::from_static(OP_MODELS_LIST),
        zone_id: ZoneId::work(),
        input: json!({}),
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
            "api_key": "openrouter_test_key",
            "base_url": server.uri()
        }),
        handshake: handshake_request(),
        invoke: Some(models_invoke(test_name)),
        invoke_expectations: InvokeExpectations {
            expect_error,
            ..InvokeExpectations::default()
        },
    }
}

#[fcp_async_core::runtime::test]
async fn connector_suite_models_happy_path_uses_mock_server() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/models"))
        .and(header("Authorization", "Bearer openrouter_test_key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {"id": "openai/gpt-4.1-mini", "name": "GPT 4.1 Mini"}
            ]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let mut connector = OpenRouterSuiteAdapter::new();
    let mut runner = E2eRunner::new("fcp-openrouter");
    let report = runner
        .run_connector_suite(
            &mut connector,
            suite(
                &server,
                "openrouter_models_connector_suite_happy_path",
                false,
            ),
        )
        .await
        .expect("connector suite run");

    assert!(report.passed, "connector suite should pass");
    assert!(!report.logs.is_empty(), "structured logs should be present");
}

#[fcp_async_core::runtime::test]
async fn connector_suite_models_error_path_is_expected() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/models"))
        .and(header("Authorization", "Bearer openrouter_test_key"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "0")
                .set_body_json(json!({
                    "error": { "message": "rate limited" }
                })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let mut connector = OpenRouterSuiteAdapter::new();
    let mut runner = E2eRunner::new("fcp-openrouter");
    let report = runner
        .run_connector_suite(
            &mut connector,
            suite(
                &server,
                "openrouter_models_connector_suite_error_path",
                true,
            ),
        )
        .await
        .expect("connector suite run");

    assert!(report.passed, "expected upstream error should pass suite");
}
