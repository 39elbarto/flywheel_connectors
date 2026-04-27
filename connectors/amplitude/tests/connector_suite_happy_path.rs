use chrono::{Duration, Utc};
use fcp_amplitude::connector::AmplitudeConnector;
use fcp_core::{
    AgentHint, CapabilityGrant, CapabilityId, CapabilityToken, ConnectorId, ConnectorMetrics,
    FcpConnector, FcpError, HandshakeRequest, HandshakeResponse, HealthSnapshot, IdempotencyClass,
    InstanceId, Introspection, InvokeRequest, InvokeResponse, OperationId, OperationInfo,
    RequestId, RiskLevel, SafetyTier, SessionId, ShutdownRequest, SimulateRequest,
    SimulateResponse, SubscribeRequest, SubscribeResponse, UnsubscribeRequest, ZoneId,
};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_e2e::{ConnectorSuite, E2eRunner, InvokeExpectations};
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

const OP_COHORTS_LIST: &str = "amplitude.cohorts.list";
const CAP_COHORTS_READ: &str = "amplitude.cohorts.read";

struct AmplitudeSuiteAdapter {
    connector: AmplitudeConnector,
    id: ConnectorId,
}

impl AmplitudeSuiteAdapter {
    fn new() -> Self {
        Self {
            connector: AmplitudeConnector::new(),
            id: ConnectorId::from_static("fcp.amplitude"),
        }
    }
}

fcp_core::impl_fcp_sealed!(AmplitudeSuiteAdapter);

#[fcp_core::async_trait]
impl FcpConnector for AmplitudeSuiteAdapter {
    fn id(&self) -> &ConnectorId {
        &self.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> fcp_core::FcpResult<()> {
        self.connector.handle_configure(config).await.map(|_| ())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> fcp_core::FcpResult<HandshakeResponse> {
        self.connector
            .handle_handshake(json!({ "session_id": "amplitude-connector-suite" }))
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
            manifest_hash: "sha256:amplitude-connector-suite".into(),
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
                Some(other) => HealthSnapshot::degraded(format!("amplitude_status:{other}")),
                None => HealthSnapshot::error("amplitude_status:missing"),
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
                id: OperationId::from_static(OP_COHORTS_LIST),
                summary: "List Amplitude cohorts through the connector".into(),
                description: None,
                input_schema: json!({
                    "type": "object",
                    "properties": {}
                }),
                output_schema: json!({
                    "type": "object",
                    "required": ["cohorts"],
                    "properties": {
                        "cohorts": { "type": "array" }
                    }
                }),
                capability: CapabilityId::from_static(CAP_COHORTS_READ),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "List cohorts available in an Amplitude project.".into(),
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
            .handle_simulate(json!({ "operation_id": operation_id }))
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

fn expected_auth_header() -> String {
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode("test_api_key:test_secret_key");
    format!("Basic {encoded}")
}

fn handshake_request(host_public_key: [u8; 32]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [17u8; 32],
        capabilities_requested: vec![CapabilityId::from_static(CAP_COHORTS_READ)],
        host: None,
        transport_caps: None,
        requested_instance_id: Some(InstanceId::new()),
    }
}

fn build_token(signing_key: &Ed25519SigningKey) -> CapabilityToken {
    let now = Utc::now();
    let raw = CapabilityTokenBuilder::new()
        .capability_id(CAP_COHORTS_READ)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[OP_COHORTS_LIST])
        .issuer("node:test")
        .validity(now, now + Duration::hours(1))
        .sign(signing_key)
        .expect("capability token");
    CapabilityToken::from_raw(raw)
}

fn cohorts_list_invoke(signing_key: &Ed25519SigningKey, id: &'static str) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new(id),
        connector_id: ConnectorId::from_static("fcp.amplitude"),
        operation: OperationId::from_static(OP_COHORTS_LIST),
        zone_id: ZoneId::work(),
        input: json!({}),
        capability_token: build_token(signing_key),
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

#[fcp_async_core::runtime::test]
async fn connector_suite_happy_path_lists_localhost_cohorts() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/cohorts"))
        .and(header("Authorization", expected_auth_header().as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "cohorts": [
                {"id": 1, "name": "Power Users", "size": 1500},
                {"id": 2, "name": "New Users", "size": 500}
            ]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(signing_key.verifying_key().to_bytes());
    let invoke = cohorts_list_invoke(&signing_key, "amplitude-connector-suite");

    let suite = ConnectorSuite {
        test_name: "amplitude_cohorts_list_happy_path".into(),
        config: json!({
            "api_key": "test_api_key",
            "secret_key": "test_secret_key",
            "base_url": server.uri()
        }),
        handshake,
        invoke: Some(invoke),
        invoke_expectations: InvokeExpectations::default(),
    };

    let mut connector = AmplitudeSuiteAdapter::new();
    let mut runner = E2eRunner::new("fcp-amplitude");
    let report = runner
        .run_connector_suite(&mut connector, suite)
        .await
        .expect("connector suite run");

    for entry in &report.logs {
        println!(
            "{}",
            serde_json::to_string(entry).expect("serialize report log")
        );
    }

    assert!(report.passed, "connector suite should pass");
    assert!(!report.logs.is_empty(), "structured logs should be present");
}

#[fcp_async_core::runtime::test]
async fn connector_suite_error_path_reports_rate_limited_cohorts() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/cohorts"))
        .and(header("Authorization", expected_auth_header().as_str()))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "0")
                .set_body_json(json!({
                    "error": "Rate limit exceeded"
                })),
        )
        .expect(3)
        .mount(&server)
        .await;

    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(signing_key.verifying_key().to_bytes());
    let invoke = cohorts_list_invoke(&signing_key, "amplitude-connector-suite-rate-limited");

    let suite = ConnectorSuite {
        test_name: "amplitude_cohorts_list_rate_limited".into(),
        config: json!({
            "api_key": "test_api_key",
            "secret_key": "test_secret_key",
            "base_url": server.uri()
        }),
        handshake,
        invoke: Some(invoke),
        invoke_expectations: InvokeExpectations {
            expect_error: true,
            ..InvokeExpectations::default()
        },
    };

    let mut connector = AmplitudeSuiteAdapter::new();
    let mut runner = E2eRunner::new("fcp-amplitude");
    let report = runner
        .run_connector_suite(&mut connector, suite)
        .await
        .expect("connector suite run");

    for entry in &report.logs {
        println!(
            "{}",
            serde_json::to_string(entry).expect("serialize report log")
        );
    }

    assert!(report.passed, "connector suite should pass");
    let execute = report
        .logs
        .iter()
        .map(|entry| serde_json::to_value(entry).expect("serialize report log"))
        .find(|entry| {
            matches!(
                entry.get("phase").and_then(serde_json::Value::as_str),
                Some("execute")
            )
        })
        .expect("execute log entry");
    assert_eq!(
        execute["context"]["expected_error"],
        json!(true),
        "suite must assert the expected error path"
    );
    assert_eq!(
        execute["context"]["retryable"],
        json!(true),
        "429 responses should be reported as retryable"
    );
    assert_eq!(
        execute["context"]["retry_after_ms"],
        json!(0),
        "retry-after header should be preserved as milliseconds"
    );
}
