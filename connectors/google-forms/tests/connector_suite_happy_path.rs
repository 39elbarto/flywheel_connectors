use chrono::{Duration, Utc};
use fcp_async_core::sync::Mutex;
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_e2e::{ConnectorSuite, E2eRunner, InvokeExpectations};
use fcp_google_forms::connector::FormsConnector;
use fcp_prelude::{
    AgentHint, CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, ConnectorMetrics,
    FcpConnector, FcpError, HandshakeRequest, HandshakeResponse, HealthSnapshot, IdempotencyClass,
    InstanceId, Introspection, InvokeRequest, InvokeResponse, OperationId, OperationInfo,
    RequestId, RiskLevel, SafetyTier, ShutdownRequest, SimulateRequest, SimulateResponse,
    SubscribeRequest, SubscribeResponse, UnsubscribeRequest, ZoneId,
};
use serde_json::json;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use wiremock::{
    Mock, MockServer, Request, Respond, ResponseTemplate,
    matchers::{header, method, path, query_param},
};

struct TwoPageResponder {
    calls: Arc<AtomicUsize>,
}

impl Respond for TwoPageResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        let token = request
            .url
            .query_pairs()
            .find(|(name, _)| name == "pageToken")
            .map(|(_, value)| value.into_owned());
        match (call, token.as_deref()) {
            (0, None) => ResponseTemplate::new(200).set_body_json(json!({
                "responses": [{"responseId": "response-page-1"}],
                "nextPageToken": "opaque/token+page=2"
            })),
            (1, Some("opaque/token+page=2")) => ResponseTemplate::new(200).set_body_json(json!({
                "responses": [{"responseId": "response-page-2"}]
            })),
            _ => ResponseTemplate::new(400).set_body_json(json!({
                "error": {"code":400,"message":"unexpected page sequence"}
            })),
        }
    }
}

const FORM_ID: &str = "form_test_123";
const OPERATION: &str = "forms.get";
const CAPABILITY: &str = "forms.read";

struct Adapter {
    connector: Mutex<FormsConnector>,
    id: ConnectorId,
}

impl Adapter {
    fn new() -> Self {
        Self {
            connector: Mutex::new(FormsConnector::new()),
            id: ConnectorId::from_static("google-forms"),
        }
    }
}

fcp_core::impl_fcp_sealed!(Adapter);

#[fcp_core::async_trait]
impl FcpConnector for Adapter {
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

    async fn handshake(
        &mut self,
        request: HandshakeRequest,
    ) -> fcp_core::FcpResult<HandshakeResponse> {
        let value = self
            .connector
            .lock()
            .await
            .handle_handshake(serde_json::to_value(request).map_err(|error| {
                FcpError::Internal {
                    message: error.to_string(),
                }
            })?)
            .await?;
        serde_json::from_value(value).map_err(|error| FcpError::Internal {
            message: error.to_string(),
        })
    }

    async fn health(&self) -> HealthSnapshot {
        match self.connector.lock().await.handle_health().await {
            Ok(value) if value["status"] == "healthy" => HealthSnapshot::ready(),
            Ok(_) => HealthSnapshot::degraded("forms_not_ready".to_string()),
            Err(error) => HealthSnapshot::error(error.to_string()),
        }
    }

    fn metrics(&self) -> ConnectorMetrics {
        ConnectorMetrics::default()
    }

    async fn shutdown(&mut self, _request: ShutdownRequest) -> fcp_core::FcpResult<()> {
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
                id: OperationId::from_static(OPERATION),
                summary: "Read a form".into(),
                description: None,
                input_schema: json!({"type":"object"}),
                output_schema: json!({"type":"object"}),
                capability: CapabilityId::from_static(CAPABILITY),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Read a form".into(),
                    common_mistakes: vec![],
                    examples: vec![],
                    related: vec![],
                },
                rate_limit: None,
                requires_approval: None,
            }],
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        }
    }

    async fn invoke(&self, request: InvokeRequest) -> fcp_core::FcpResult<InvokeResponse> {
        let id = request.id;
        let value = self
            .connector
            .lock()
            .await
            .handle_invoke(json!({
                "operation": request.operation.as_str(),
                "input": request.input,
                "capability_token": request.capability_token,
            }))
            .await?;
        Ok(InvokeResponse::ok(id, value))
    }

    async fn simulate(&self, request: SimulateRequest) -> fcp_core::FcpResult<SimulateResponse> {
        Ok(SimulateResponse::allowed(request.id))
    }

    async fn subscribe(
        &self,
        _request: SubscribeRequest,
    ) -> fcp_core::FcpResult<SubscribeResponse> {
        Err(FcpError::StreamingNotSupported)
    }

    async fn unsubscribe(&self, _request: UnsubscribeRequest) -> fcp_core::FcpResult<()> {
        Ok(())
    }
}

fn handshake(host_public_key: [u8; 32], instance_id: InstanceId) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [29u8; 32],
        capabilities_requested: vec![
            CapabilityId::from_static("forms.read"),
            CapabilityId::from_static("form.structure.write"),
            CapabilityId::from_static("form.publish.write"),
            CapabilityId::from_static("forms.responses.read"),
        ],
        host: None,
        transport_caps: None,
        requested_instance_id: Some(instance_id),
    }
}

fn token(signing_key: &Ed25519SigningKey, instance_id: &InstanceId) -> CapabilityToken {
    token_for(
        signing_key,
        instance_id,
        CAPABILITY,
        OPERATION,
        format!("google-forms:form:{FORM_ID}"),
    )
}

fn token_for(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    capability: &str,
    operation: &str,
    resource: String,
) -> CapabilityToken {
    let constraints = CapabilityConstraints {
        resource_allow: vec![resource],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("constraints");
    let now = Utc::now();
    CapabilityToken::from_raw(
        CapabilityTokenBuilder::new()
            .capability_id(capability)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[operation])
            .issuer("node:test")
            .audience("z:work")
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&cbor)
            .expect("constraints cbor")
            .target_instance(instance_id.as_str())
            .sign(signing_key)
            .expect("token"),
    )
}

async fn direct_connector(server: &MockServer) -> (FormsConnector, Ed25519SigningKey, InstanceId) {
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();
    let mut connector = FormsConnector::new();
    connector
        .handle_configure(json!({
            "access_token": "local-forms-suite-token",
            "base_url": format!("{}/v1", server.uri())
        }))
        .await
        .expect("configure");
    connector
        .handle_handshake(
            serde_json::to_value(handshake(
                signing_key.verifying_key().to_bytes(),
                instance_id.clone(),
            ))
            .expect("handshake request"),
        )
        .await
        .expect("handshake");
    (connector, signing_key, instance_id)
}

#[fcp_async_core::runtime::test]
async fn connector_suite_reads_bounded_form_structure() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/forms/{FORM_ID}")))
        .and(header("authorization", "Bearer local-forms-suite-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "formId": FORM_ID,
            "revisionId": "rev-1",
            "info": {"title": "Private title"},
            "settings": {"quizSettings": {"isQuiz": false}},
            "items": [{"itemId":"item-1","title":"Question","textItem":{}}]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();
    let invoke = InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new("google-forms-suite"),
        connector_id: ConnectorId::from_static("google-forms"),
        operation: OperationId::from_static(OPERATION),
        zone_id: ZoneId::work(),
        input: json!({"form_id": FORM_ID, "item_limit": 10}),
        capability_token: token(&signing_key, &instance_id),
        holder_proof: None,
        context: None,
        idempotency_key: None,
        lease_seq: None,
        deadline_ms: None,
        correlation_id: None,
        provenance: None,
        approval_tokens: vec![],
    };
    let suite = ConnectorSuite {
        test_name: "google_forms_get_happy_path".into(),
        config: json!({
            "access_token": "local-forms-suite-token",
            "base_url": format!("{}/v1", server.uri())
        }),
        handshake: handshake(signing_key.verifying_key().to_bytes(), instance_id),
        invoke: Some(invoke),
        invoke_expectations: InvokeExpectations::default(),
    };
    let report = E2eRunner::new("fcp-google-forms")
        .run_connector_suite(&mut Adapter::new(), suite)
        .await
        .expect("suite");
    assert!(report.passed, "{:?}", report.logs);
}

#[fcp_async_core::runtime::test]
async fn destructive_batch_stops_at_exact_preflight() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/forms/{FORM_ID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "formId": FORM_ID,
            "revisionId": "rev-current",
            "info": {"title": "Private title"},
            "items": [{"itemId":"item-1","title":"Question","textItem":{}}]
        })))
        .expect(1)
        .mount(&server)
        .await;
    let (mut connector, signing_key, instance_id) = direct_connector(&server).await;
    let result = connector
        .handle_invoke(json!({
            "operation": "forms.batch_update",
            "input": {
                "form_id": FORM_ID,
                "requests": [{"deleteItem": {"location": {"index": 0}}}]
            },
            "capability_token": token_for(
                &signing_key,
                &instance_id,
                "form.structure.write",
                "forms.batch_update",
                format!("google-forms:form:{FORM_ID}")
            )
        }))
        .await
        .expect("preflight");
    assert_eq!(result["status"], "confirmation_required");
    assert_eq!(result["preflight"]["revision_id"], "rev-current");
    assert_eq!(
        result["confirmation_sha256"].as_str().map(str::len),
        Some(64)
    );
}

#[fcp_async_core::runtime::test]
async fn response_list_binds_private_continuation_token() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/forms/{FORM_ID}/responses")))
        .and(query_param("pageSize", "2"))
        .and(query_param("filter", "timestamp >= 2026-08-04T00:00:00Z"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "responses": [{
                "responseId": "private-response-id",
                "respondentEmail": "private@example.invalid",
                "answers": {"q1": {"textAnswers": {"answers": [{"value": "private answer"}]}}}
            }],
            "nextPageToken": "private-next-token"
        })))
        .expect(1)
        .mount(&server)
        .await;
    let (mut connector, signing_key, instance_id) = direct_connector(&server).await;
    let result = connector
        .handle_invoke(json!({
            "operation": "forms.responses.list",
            "input": {
                "form_id": FORM_ID,
                "filter": "timestamp >= 2026-08-04T00:00:00Z",
                "page_size": 2
            },
            "capability_token": token_for(
                &signing_key,
                &instance_id,
                "forms.responses.read",
                "forms.responses.list",
                format!("google-forms:responses:{FORM_ID}")
            )
        }))
        .await
        .expect("response list");
    assert_eq!(result["responses"].as_array().map(Vec::len), Some(1));
    assert_eq!(result["next_cursor"]["page_token"], "private-next-token");
    assert_eq!(
        result["next_cursor"]["cursor_binding_sha256"]
            .as_str()
            .map(str::len),
        Some(64)
    );
}

#[fcp_async_core::runtime::test]
async fn response_pagination_returns_two_pages_without_gap_or_duplicate() {
    let server = MockServer::start().await;
    let calls = Arc::new(AtomicUsize::new(0));
    Mock::given(method("GET"))
        .and(path(format!("/v1/forms/{FORM_ID}/responses")))
        .and(query_param("pageSize", "1"))
        .respond_with(TwoPageResponder {
            calls: Arc::clone(&calls),
        })
        .expect(2)
        .mount(&server)
        .await;
    let (mut connector, signing_key, instance_id) = direct_connector(&server).await;
    let capability = || {
        token_for(
            &signing_key,
            &instance_id,
            "forms.responses.read",
            "forms.responses.list",
            format!("google-forms:responses:{FORM_ID}"),
        )
    };
    let first = connector
        .handle_invoke(json!({
            "operation": "forms.responses.list",
            "input": {"form_id": FORM_ID, "page_size": 1},
            "capability_token": capability()
        }))
        .await
        .expect("first page");
    let second = connector
        .handle_invoke(json!({
            "operation": "forms.responses.list",
            "input": {
                "form_id": FORM_ID,
                "page_size": 1,
                "page_token": first["next_cursor"]["page_token"],
                "cursor_binding_sha256": first["next_cursor"]["cursor_binding_sha256"]
            },
            "capability_token": capability()
        }))
        .await
        .expect("second page");
    let ids = [
        first["responses"][0]["responseId"].as_str(),
        second["responses"][0]["responseId"].as_str(),
    ];
    assert_eq!(ids, [Some("response-page-1"), Some("response-page-2")]);
    assert!(second["next_cursor"].is_null());
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[fcp_async_core::runtime::test]
async fn publish_change_requires_revision_state_and_confirmation() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/forms/{FORM_ID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "formId": FORM_ID,
            "revisionId": "rev-publish",
            "info": {"title": "Private title"},
            "publishSettings": {
                "publishState": {"isPublished": true, "isAcceptingResponses": true}
            }
        })))
        .expect(1)
        .mount(&server)
        .await;
    let (mut connector, signing_key, instance_id) = direct_connector(&server).await;
    let result = connector
        .handle_invoke(json!({
            "operation": "forms.set_publish_settings",
            "input": {
                "form_id": FORM_ID,
                "is_published": false,
                "is_accepting_responses": false
            },
            "capability_token": token_for(
                &signing_key,
                &instance_id,
                "form.publish.write",
                "forms.set_publish_settings",
                format!("google-forms:form:{FORM_ID}")
            )
        }))
        .await
        .expect("publish preflight");
    assert_eq!(result["status"], "confirmation_required");
    assert_eq!(result["required_revision_id"], "rev-publish");
    assert_eq!(
        result["required_state_sha256"].as_str().map(str::len),
        Some(64)
    );
    assert_eq!(
        result["confirmation_sha256"].as_str().map(str::len),
        Some(64)
    );
}

#[fcp_async_core::runtime::test]
async fn legacy_form_publish_settings_fail_before_write() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/forms/{FORM_ID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "formId": FORM_ID,
            "revisionId": "legacy-revision",
            "info": {"title": "Legacy form"}
        })))
        .expect(1)
        .mount(&server)
        .await;
    let (mut connector, signing_key, instance_id) = direct_connector(&server).await;
    let error = connector
        .handle_invoke(json!({
            "operation": "forms.set_publish_settings",
            "input": {
                "form_id": FORM_ID,
                "is_published": false,
                "is_accepting_responses": false
            },
            "capability_token": token_for(
                &signing_key,
                &instance_id,
                "form.publish.write",
                "forms.set_publish_settings",
                format!("google-forms:form:{FORM_ID}")
            )
        }))
        .await
        .expect_err("legacy form must reject publishing");
    assert!(error.to_string().contains("legacy form"));
}
