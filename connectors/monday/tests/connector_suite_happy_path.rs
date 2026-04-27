use chrono::{Duration, Utc};
use fcp_core::{
    AgentHint, CapabilityConstraints, CapabilityGrant, CapabilityId, CapabilityToken, ConnectorId,
    ConnectorMetrics, EventCaps, FcpConnector, FcpError, HandshakeRequest, HandshakeResponse,
    HealthSnapshot, IdempotencyClass, InstanceId, Introspection, InvokeRequest, InvokeResponse,
    OperationId, OperationInfo, RequestId, RiskLevel, SafetyTier, SessionId, ShutdownRequest,
    SimulateRequest, SimulateResponse, SubscribeRequest, SubscribeResponse, UnsubscribeRequest,
    ZoneId,
};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_e2e::{ConnectorSuite, E2eRunner, InvokeExpectations};
use fcp_monday::connector::MondayConnector;
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

const CONNECTOR_ID: &str = "monday";
const OP_LIST_BOARDS: &str = "monday.boards.list";
const CAP_BOARDS_READ: &str = "monday.boards.read";

struct MondayAdapter {
    connector: MondayConnector,
    id: ConnectorId,
}

impl MondayAdapter {
    fn new() -> Self {
        Self {
            connector: MondayConnector::new(),
            id: ConnectorId::from_static(CONNECTOR_ID),
        }
    }
}

fcp_core::impl_fcp_sealed!(MondayAdapter);

#[fcp_core::async_trait]
impl FcpConnector for MondayAdapter {
    fn id(&self) -> &ConnectorId {
        &self.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> fcp_core::FcpResult<()> {
        self.connector.handle_configure(config).await.map(|_| ())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> fcp_core::FcpResult<HandshakeResponse> {
        let session_id = SessionId::new();
        self.connector
            .handle_handshake(json!({ "session_id": session_id.to_string() }))
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
            status: "accepted".to_string(),
            capabilities_granted,
            session_id,
            manifest_hash: "sha256:monday-connector-suite".to_string(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        })
    }

    async fn health(&self) -> HealthSnapshot {
        match self.connector.handle_health().await {
            Ok(payload) => match payload.get("status").and_then(serde_json::Value::as_str) {
                Some("healthy") => HealthSnapshot::ready(),
                Some(other) => HealthSnapshot::degraded(format!("monday_status:{other}")),
                None => HealthSnapshot::error("monday_status:missing".to_string()),
            },
            Err(err) => HealthSnapshot::error(err.to_string()),
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
                id: OperationId::from_static(OP_LIST_BOARDS),
                summary: "List Monday boards".to_string(),
                description: None,
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "limit": { "type": "integer" }
                    }
                }),
                output_schema: json!({
                    "type": "object",
                    "properties": {
                        "boards": { "type": "array" }
                    }
                }),
                capability: CapabilityId::from_static(CAP_BOARDS_READ),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "List Monday boards visible to the configured token.".to_string(),
                    common_mistakes: Vec::new(),
                    examples: vec![r#"{"limit":2}"#.to_string()],
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
        let value = self
            .connector
            .handle_invoke(json!({
                "operation_id": req.operation.as_str(),
                "input": req.input,
            }))
            .await?;
        Ok(InvokeResponse::ok(request_id, value))
    }

    async fn simulate(&self, req: SimulateRequest) -> fcp_core::FcpResult<SimulateResponse> {
        let value = serde_json::to_value(req).map_err(|err| FcpError::Internal {
            message: format!("failed to serialize simulate request: {err}"),
        })?;
        let value = self.connector.handle_simulate(value).await?;
        serde_json::from_value(value).map_err(|err| FcpError::Internal {
            message: format!("failed to deserialize simulate response: {err}"),
        })
    }

    async fn subscribe(&self, _req: SubscribeRequest) -> fcp_core::FcpResult<SubscribeResponse> {
        Err(FcpError::StreamingNotSupported)
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> fcp_core::FcpResult<()> {
        Ok(())
    }
}

fn handshake_request(host_public_key: [u8; 32]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0".to_string(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [41u8; 32],
        capabilities_requested: vec![CapabilityId::from_static(CAP_BOARDS_READ)],
        host: None,
        transport_caps: None,
        requested_instance_id: Some(InstanceId::new()),
    }
}

fn build_token(signing_key: &Ed25519SigningKey) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["monday:boards".to_string()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");

    let raw = CapabilityTokenBuilder::new()
        .capability_id(CAP_BOARDS_READ)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[OP_LIST_BOARDS])
        .issuer("node:test")
        .token_id(b"monday-connector-suite")
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("valid constraints cbor")
        .sign(signing_key)
        .expect("capability token");
    CapabilityToken::from_raw(raw)
}

fn boards_list_invoke(signing_key: &Ed25519SigningKey, id: &'static str) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".to_string(),
        id: RequestId::new(id),
        connector_id: ConnectorId::from_static(CONNECTOR_ID),
        operation: OperationId::from_static(OP_LIST_BOARDS),
        zone_id: ZoneId::work(),
        input: json!({ "limit": 2 }),
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
async fn connector_suite_happy_path_lists_boards() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(header("Authorization", "monday_test_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "boards": [
                    {
                        "id": "1001",
                        "name": "Platform Roadmap",
                        "state": "active",
                        "board_kind": "public"
                    },
                    {
                        "id": "1002",
                        "name": "Launch Checklist",
                        "state": "active",
                        "board_kind": "private"
                    }
                ]
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let signing_key = Ed25519SigningKey::generate();
    let invoke = boards_list_invoke(&signing_key, "monday-connector-suite");

    let suite = ConnectorSuite {
        test_name: "monday_list_boards_happy_path".to_string(),
        config: json!({
            "api_token": "monday_test_token",
            "base_url": server.uri(),
        }),
        handshake: handshake_request(signing_key.verifying_key().to_bytes()),
        invoke: Some(invoke),
        invoke_expectations: InvokeExpectations::default(),
    };

    let mut connector = MondayAdapter::new();
    let mut runner = E2eRunner::new("fcp-monday");
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
async fn connector_suite_error_path_reports_unauthorized_boards_list() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(header("Authorization", "monday_test_token"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error_message": "Invalid API token"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let signing_key = Ed25519SigningKey::generate();
    let invoke = boards_list_invoke(&signing_key, "monday-connector-suite-unauthorized");

    let suite = ConnectorSuite {
        test_name: "monday_list_boards_unauthorized".to_string(),
        config: json!({
            "api_token": "monday_test_token",
            "base_url": server.uri(),
        }),
        handshake: handshake_request(signing_key.verifying_key().to_bytes()),
        invoke: Some(invoke),
        invoke_expectations: InvokeExpectations {
            expect_error: true,
            expected_reason_code: Some("FCP-2001".to_string()),
            ..InvokeExpectations::default()
        },
    };

    let mut connector = MondayAdapter::new();
    let mut runner = E2eRunner::new("fcp-monday");
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
        execute["context"]["reason_code"],
        json!("FCP-2001"),
        "Monday 401 should map to the FCP unauthorized code"
    );
    assert_eq!(
        execute["context"]["retryable"],
        json!(false),
        "auth failures should be reported as terminal"
    );
}
