use chrono::{Duration, Utc};
use fcp_async_core::sync::Mutex;
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_e2e::{ConnectorSuite, E2eRunner, InvokeExpectations};
use fcp_google_slides::connector::SlidesConnector;
use fcp_prelude::{
    AgentHint, CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, ConnectorMetrics,
    FcpConnector, FcpError, HandshakeRequest, HandshakeResponse, HealthSnapshot, IdempotencyClass,
    InstanceId, Introspection, InvokeRequest, InvokeResponse, OperationId, OperationInfo,
    RequestId, RiskLevel, SafetyTier, ShutdownRequest, SimulateRequest, SimulateResponse,
    SubscribeRequest, SubscribeResponse, UnsubscribeRequest, ZoneId,
};
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path, query_param},
};

const CONNECTOR_ID: &str = "google-slides";
const OP_GET_DOCUMENT: &str = "slides.get";
const CAP_READ: &str = "slides.read";
const CAP_WRITE: &str = "slides.write";
const DOCUMENT_ID: &str = "doc_test_123";

struct GoogleSlidesAdapter {
    connector: Mutex<SlidesConnector>,
    id: ConnectorId,
}

impl GoogleSlidesAdapter {
    fn new() -> Self {
        Self {
            connector: Mutex::new(SlidesConnector::new()),
            id: ConnectorId::from_static(CONNECTOR_ID),
        }
    }
}

fcp_core::impl_fcp_sealed!(GoogleSlidesAdapter);

#[fcp_core::async_trait]
impl FcpConnector for GoogleSlidesAdapter {
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
                Some(other) => HealthSnapshot::degraded(format!("slides_status:{other}")),
                None => HealthSnapshot::error("slides_status:missing".to_string()),
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
                summary: "Get a Google Slides presentation by ID".to_string(),
                description: None,
                input_schema: json!({
                    "type": "object",
                    "required": ["presentation_id"],
                    "properties": {
                        "presentation_id": { "type": "string" }
                    }
                }),
                output_schema: json!({
                    "type": "object",
                    "properties": {
                        "presentation": { "type": "object" }
                    }
                }),
                capability: CapabilityId::from_static(CAP_READ),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Retrieve a Google Slides presentation.".to_string(),
                    common_mistakes: Vec::new(),
                    examples: vec![r#"{"presentation_id":"doc_test_123"}"#.to_string()],
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

fn handshake_request(host_public_key: [u8; 32], instance_id: InstanceId) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0".to_string(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [23u8; 32],
        capabilities_requested: vec![
            CapabilityId::from_static(CAP_READ),
            CapabilityId::from_static(CAP_WRITE),
        ],
        host: None,
        transport_caps: None,
        requested_instance_id: Some(instance_id),
    }
}

fn build_token(signing_key: &Ed25519SigningKey, instance_id: &InstanceId) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec![format!("google-slides:presentation:{DOCUMENT_ID}")],
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
        .token_id(b"google-slides-connector-suite")
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("valid constraints cbor")
        .target_instance(instance_id.as_str())
        .sign(signing_key)
        .expect("capability token");
    CapabilityToken::from_raw(raw)
}

fn build_write_token(signing_key: &Ed25519SigningKey, instance_id: &InstanceId) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec![format!("google-slides:presentation:{DOCUMENT_ID}")],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let raw = CapabilityTokenBuilder::new()
        .capability_id(CAP_WRITE)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&["slides.batch_update"])
        .issuer("node:test")
        .audience("z:work")
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("valid constraints cbor")
        .target_instance(instance_id.as_str())
        .sign(signing_key)
        .expect("capability token");
    CapabilityToken::from_raw(raw)
}

fn build_create_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["google-slides:presentations".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let raw = CapabilityTokenBuilder::new()
        .capability_id(CAP_WRITE)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&["slides.create"])
        .issuer("node:test")
        .audience("z:work")
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("valid constraints cbor")
        .target_instance(instance_id.as_str())
        .sign(signing_key)
        .expect("capability token");
    CapabilityToken::from_raw(raw)
}

fn build_page_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    operation: &str,
    page_object_id: &str,
) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec![
            format!("google-slides:presentation:{DOCUMENT_ID}"),
            format!("google-slides:page:{DOCUMENT_ID}:{page_object_id}"),
        ],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let raw = CapabilityTokenBuilder::new()
        .capability_id(CAP_READ)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[operation])
        .issuer("node:test")
        .audience("z:work")
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("valid constraints cbor")
        .target_instance(instance_id.as_str())
        .sign(signing_key)
        .expect("capability token");
    CapabilityToken::from_raw(raw)
}

#[fcp_async_core::runtime::test]
async fn page_and_thumbnail_reads_are_bounded_and_capability_bound() {
    const PAGE_ID: &str = "slide_001";
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/presentations/{DOCUMENT_ID}/pages/{PAGE_ID}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "objectId": PAGE_ID,
            "pageType": "SLIDE",
            "pageElements": [{
                "shape": { "text": { "textElements": [{ "textRun": { "content": "speaker-safe text" } }] } }
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/presentations/{DOCUMENT_ID}/pages/{PAGE_ID}/thumbnail"
        )))
        .and(query_param("thumbnailProperties.mimeType", "PNG"))
        .and(query_param("thumbnailProperties.thumbnailSize", "SMALL"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "width": 200,
            "height": 112,
            "contentUrl": "https://example.com/transient-thumbnail"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();
    let mut connector = SlidesConnector::new();
    connector
        .handle_configure(json!({
            "access_token": "ya29_test_slides",
            "base_url": format!("{}/v1", server.uri()),
        }))
        .await
        .expect("configure connector");
    connector
        .handle_handshake(
            serde_json::to_value(handshake_request(
                signing_key.verifying_key().to_bytes(),
                instance_id.clone(),
            ))
            .expect("serialize handshake"),
        )
        .await
        .expect("handshake connector");

    let page = connector
        .handle_invoke(json!({
            "operation": "slides.pages.get",
            "input": { "presentation_id": DOCUMENT_ID, "page_object_id": PAGE_ID },
            "capability_token": build_page_token(&signing_key, &instance_id, "slides.pages.get", PAGE_ID),
        }))
        .await
        .expect("page get");
    assert_eq!(page["page"]["object_id"], PAGE_ID);
    assert_eq!(page["page"]["text"], "speaker-safe text");

    let thumbnail = connector
        .handle_invoke(json!({
            "operation": "slides.pages.get_thumbnail",
            "input": { "presentation_id": DOCUMENT_ID, "page_object_id": PAGE_ID, "size": "SMALL" },
            "capability_token": build_page_token(&signing_key, &instance_id, "slides.pages.get_thumbnail", PAGE_ID),
        }))
        .await
        .expect("thumbnail get");
    assert_eq!(thumbnail["thumbnail"]["width"], 200);
    assert_eq!(thumbnail["thumbnail"]["size"], "SMALL");
}

#[fcp_async_core::runtime::test]
async fn connector_suite_happy_path_gets_presentation() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(format!("/v1/presentations/{DOCUMENT_ID}")))
        .and(header("authorization", "Bearer ya29_test_slides"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "presentationId": DOCUMENT_ID,
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
                                "content": "Hello from Slides"
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
    let instance_id = InstanceId::new();
    let invoke = InvokeRequest {
        r#type: "invoke".to_string(),
        id: RequestId::new("google-slides-connector-suite"),
        connector_id: ConnectorId::from_static(CONNECTOR_ID),
        operation: OperationId::from_static(OP_GET_DOCUMENT),
        zone_id: ZoneId::work(),
        input: json!({ "presentation_id": DOCUMENT_ID }),
        capability_token: build_token(&signing_key, &instance_id),
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
        test_name: "google_slides_get_presentation_happy_path".to_string(),
        config: json!({
            "access_token": "ya29_test_slides",
            "base_url": format!("{}/v1", server.uri()),
        }),
        handshake: handshake_request(signing_key.verifying_key().to_bytes(), instance_id),
        invoke: Some(invoke),
        invoke_expectations: InvokeExpectations::default(),
    };

    let mut connector = GoogleSlidesAdapter::new();
    let mut runner = E2eRunner::new("fcp-google-slides");
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
async fn create_presentation_performs_metadata_readback_without_retry_receipt() {
    use wiremock::matchers::body_json;

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/presentations"))
        .and(body_json(json!({ "title": "Created once" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "presentationId": DOCUMENT_ID,
            "title": "Created once"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/presentations/{DOCUMENT_ID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "presentationId": DOCUMENT_ID,
            "title": "Created once",
            "revisionId": "rev-created",
            "body": { "content": [] }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();
    let mut connector = SlidesConnector::new();
    connector
        .handle_configure(json!({
            "access_token": "ya29_test_slides",
            "base_url": format!("{}/v1", server.uri()),
        }))
        .await
        .expect("configure connector");
    connector
        .handle_handshake(
            serde_json::to_value(handshake_request(
                signing_key.verifying_key().to_bytes(),
                instance_id.clone(),
            ))
            .expect("serialize handshake"),
        )
        .await
        .expect("handshake connector");

    let result = connector
        .handle_invoke(json!({
            "operation": "slides.create",
            "input": { "title": "Created once" },
            "capability_token": build_create_token(&signing_key, &instance_id),
        }))
        .await
        .expect("create and read back presentation");
    assert_eq!(result["status"], "created_and_verified");
    assert_eq!(result["presentation"]["presentation_id"], DOCUMENT_ID);
    assert_eq!(result["readback"]["revision_id"], "rev-created");
    assert_eq!(result["retry_safe"], false);
}

#[fcp_async_core::runtime::test]
async fn destructive_batch_requires_bound_confirmation_revision_and_readback() {
    use wiremock::matchers::body_json;

    let server = MockServer::start().await;
    let presentation = json!({
        "presentationId": DOCUMENT_ID,
        "title": "Bounded edit",
        "revisionId": "rev-1",
        "slides": []
    });
    Mock::given(method("GET"))
        .and(path(format!("/v1/presentations/{DOCUMENT_ID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(presentation))
        .expect(4)
        .mount(&server)
        .await;

    let requests = json!([{
        "deleteText": {
            "objectId": "shape_001",
            "textRange": { "type": "FIXED_RANGE", "startIndex": 2, "endIndex": 5 }
        }
    }]);
    Mock::given(method("POST"))
        .and(path(format!("/v1/presentations/{DOCUMENT_ID}:batchUpdate")))
        .and(body_json(json!({
            "requests": requests,
            "writeControl": { "requiredRevisionId": "rev-1" }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "presentationId": DOCUMENT_ID,
            "replies": [{}],
            "writeControl": { "requiredRevisionId": "rev-2" }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();
    let mut connector = SlidesConnector::new();
    connector
        .handle_configure(json!({
            "access_token": "ya29_test_slides",
            "base_url": format!("{}/v1", server.uri()),
        }))
        .await
        .expect("configure connector");
    connector
        .handle_handshake(
            serde_json::to_value(handshake_request(
                signing_key.verifying_key().to_bytes(),
                instance_id.clone(),
            ))
            .expect("serialize handshake"),
        )
        .await
        .expect("handshake connector");

    let token = build_write_token(&signing_key, &instance_id);
    let preflight = connector
        .handle_invoke(json!({
            "operation": "slides.batch_update",
            "input": { "presentation_id": DOCUMENT_ID, "requests": requests },
            "capability_token": token,
        }))
        .await
        .expect("destructive preflight");
    assert_eq!(preflight["status"], "confirmation_required");
    assert_eq!(preflight["impact"][0]["start_index"], 2);
    assert_eq!(preflight["impact"][0]["end_index"], 5);
    let confirmation = preflight["confirmation_sha256"]
        .as_str()
        .expect("confirmation hash");

    let stale_revision = connector
        .handle_invoke(json!({
            "operation": "slides.batch_update",
            "input": {
                "presentation_id": DOCUMENT_ID,
                "requests": requests,
                "required_revision_id": "stale-revision",
                "confirm_destructive": true,
                "confirmation_sha256": confirmation,
            },
            "capability_token": build_write_token(&signing_key, &instance_id),
        }))
        .await
        .expect_err("stale revision must fail before provider write");
    assert!(matches!(stale_revision, FcpError::InvalidRequest { .. }));

    let result = connector
        .handle_invoke(json!({
            "operation": "slides.batch_update",
            "input": {
                "presentation_id": DOCUMENT_ID,
                "requests": requests,
                "required_revision_id": "rev-1",
                "confirm_destructive": true,
                "confirmation_sha256": confirmation,
            },
            "capability_token": build_write_token(&signing_key, &instance_id),
        }))
        .await
        .expect("confirmed destructive update");
    assert_eq!(result["status"], "applied_and_verified");
    assert_eq!(result["destructive"], true);
    assert_eq!(result["reply_count"], 1);
    assert_eq!(result["readback"]["revision_id"], "rev-1");
}
