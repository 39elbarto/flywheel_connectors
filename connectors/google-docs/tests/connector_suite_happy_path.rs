use chrono::{Duration, Utc};
use fcp_async_core::sync::Mutex;
use fcp_prelude::{
    AgentHint, CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, ConnectorMetrics,
    FcpConnector, FcpError, HandshakeRequest, HandshakeResponse, HealthSnapshot, IdempotencyClass,
    InstanceId, Introspection, InvokeRequest, InvokeResponse, OperationId, OperationInfo,
    RequestId, RiskLevel, SafetyTier, ShutdownRequest, SimulateRequest, SimulateResponse,
    SubscribeRequest, SubscribeResponse, UnsubscribeRequest, ZoneId,
};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_e2e::{ConnectorSuite, E2eRunner, InvokeExpectations};
use fcp_google_docs::connector::DocsConnector;
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

const CONNECTOR_ID: &str = "google-docs";
const OP_GET_DOCUMENT: &str = "docs.get";
const CAP_READ: &str = "docs.read";
const DOCUMENT_ID: &str = "doc_test_123";

struct GoogleDocsAdapter {
    connector: Mutex<DocsConnector>,
    id: ConnectorId,
}

impl GoogleDocsAdapter {
    fn new() -> Self {
        Self {
            connector: Mutex::new(DocsConnector::new()),
            id: ConnectorId::from_static(CONNECTOR_ID),
        }
    }
}

fcp_core::impl_fcp_sealed!(GoogleDocsAdapter);

#[fcp_core::async_trait]
impl FcpConnector for GoogleDocsAdapter {
    fn id(&self) -> &ConnectorId {
        &self.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> fcp_core::FcpResult<()> {
        self.connector
            .lock()
            .await
            .handle_configure(config)
            .await
            .map(|_| ())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> fcp_core::FcpResult<HandshakeResponse> {
        let value = serde_json::to_value(req).map_err(|err| FcpError::Internal {
            message: format!("failed to serialize handshake request: {err}"),
        })?;
        let response = self.connector.lock().await.handle_handshake(value).await?;
        serde_json::from_value(response).map_err(|err| FcpError::Internal {
            message: format!("failed to deserialize handshake response: {err}"),
        })
    }

    async fn health(&self) -> HealthSnapshot {
        match self.connector.lock().await.handle_health().await {
            Ok(payload) => match payload.get("status").and_then(serde_json::Value::as_str) {
                Some("healthy") => HealthSnapshot::ready(),
                Some(other) => HealthSnapshot::degraded(format!("docs_status:{other}")),
                None => HealthSnapshot::error("docs_status:missing".to_string()),
            },
            Err(err) => HealthSnapshot::error(err.to_string()),
        }
    }

    fn metrics(&self) -> ConnectorMetrics {
        ConnectorMetrics::default()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> fcp_core::FcpResult<()> {
        self.connector
            .lock()
            .await
            .handle_shutdown(json!({}))
            .await
            .map(|_| ())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: vec![OperationInfo {
                id: OperationId::from_static(OP_GET_DOCUMENT),
                summary: "Get a Google Docs document by ID".to_string(),
                description: None,
                input_schema: json!({
                    "type": "object",
                    "required": ["document_id"],
                    "properties": {
                        "document_id": { "type": "string" }
                    }
                }),
                output_schema: json!({
                    "type": "object",
                    "properties": {
                        "document": { "type": "object" }
                    }
                }),
                capability: CapabilityId::from_static(CAP_READ),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Retrieve a Google Docs document.".to_string(),
                    common_mistakes: Vec::new(),
                    examples: vec![r#"{"document_id":"doc_test_123"}"#.to_string()],
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
        let params = json!({
            "operation": req.operation.as_str(),
            "input": req.input,
            "capability_token": req.capability_token,
        });
        let value = self.connector.lock().await.handle_invoke(params).await?;
        Ok(InvokeResponse::ok(request_id, value))
    }

    async fn simulate(&self, req: SimulateRequest) -> fcp_core::FcpResult<SimulateResponse> {
        Ok(SimulateResponse::allowed(req.id))
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
        nonce: [23u8; 32],
        capabilities_requested: vec![CapabilityId::from_static(CAP_READ)],
        host: None,
        transport_caps: None,
        requested_instance_id: Some(InstanceId::new()),
    }
}

fn build_token(signing_key: &Ed25519SigningKey) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec![format!("google-docs:document:{DOCUMENT_ID}")],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");

    let raw = CapabilityTokenBuilder::new()
        .capability_id(CAP_READ)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[OP_GET_DOCUMENT])
        .issuer("node:test")
        .audience("z:work")
        .token_id(b"google-docs-connector-suite")
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("valid constraints cbor")
        .sign(signing_key)
        .expect("capability token");
    CapabilityToken::from_raw(raw)
}

#[fcp_async_core::runtime::test]
async fn connector_suite_happy_path_gets_document() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(format!("/v1/documents/{DOCUMENT_ID}")))
        .and(header("authorization", "Bearer ya29_test_docs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "documentId": DOCUMENT_ID,
            "title": "Connector Suite Notes",
            "revisionId": "rev-1",
            "body": {
                "content": [{
                    "startIndex": 1,
                    "endIndex": 18,
                    "paragraph": {
                        "elements": [{
                            "startIndex": 1,
                            "endIndex": 18,
                            "textRun": {
                                "content": "Hello from Docs"
                            }
                        }]
                    }
                }]
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let signing_key = Ed25519SigningKey::generate();
    let invoke = InvokeRequest {
        r#type: "invoke".to_string(),
        id: RequestId::new("google-docs-connector-suite"),
        connector_id: ConnectorId::from_static(CONNECTOR_ID),
        operation: OperationId::from_static(OP_GET_DOCUMENT),
        zone_id: ZoneId::work(),
        input: json!({ "document_id": DOCUMENT_ID }),
        capability_token: build_token(&signing_key),
        holder_proof: None,
        context: None,
        idempotency_key: None,
        lease_seq: None,
        deadline_ms: None,
        correlation_id: None,
        provenance: None,
        approval_tokens: Vec::new(),
    };

    let suite = ConnectorSuite {
        test_name: "google_docs_get_document_happy_path".to_string(),
        config: json!({
            "access_token": "ya29_test_docs",
            "base_url": format!("{}/v1", server.uri()),
        }),
        handshake: handshake_request(signing_key.verifying_key().to_bytes()),
        invoke: Some(invoke),
        invoke_expectations: InvokeExpectations::default(),
    };

    let mut connector = GoogleDocsAdapter::new();
    let mut runner = E2eRunner::new("fcp-google-docs");
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
