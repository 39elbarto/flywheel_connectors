use std::sync::Once;

use chrono::{Duration as ChronoDuration, Utc};
use fcp_core::{
    AgentHint, CapabilityId, CapabilityToken, ConnectorId, ConnectorMetrics, FcpConnector,
    FcpError, HandshakeRequest, HandshakeResponse, HealthSnapshot, IdempotencyClass, InstanceId,
    Introspection, InvokeRequest, InvokeResponse, OperationId, OperationInfo, RequestId,
    RiskLevel, SafetyTier, ShutdownRequest, SimulateRequest, SimulateResponse, SubscribeRequest,
    SubscribeResponse, UnsubscribeRequest, ZoneId,
};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_e2e::{ConnectorSuite, E2eRunner, InvokeExpectations};
use fcp_google_drive::connector::DriveConnector;
use serde_json::json;
use tracing::info;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

static TEST_LOGGER: Once = Once::new();

fn init_json_test_logging() {
    TEST_LOGGER.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_test_writer()
            .json()
            .try_init();
    });
}

struct GoogleDriveAdapter {
    connector: DriveConnector,
    id: ConnectorId,
}

impl GoogleDriveAdapter {
    fn new() -> Self {
        Self {
            connector: DriveConnector::new(),
            id: ConnectorId::from_static("google-drive"),
        }
    }
}

fcp_core::impl_fcp_sealed!(GoogleDriveAdapter);

#[fcp_core::async_trait]
impl FcpConnector for GoogleDriveAdapter {
    fn id(&self) -> &ConnectorId {
        &self.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> fcp_core::FcpResult<()> {
        self.connector.handle_configure(config).await.map(|_| ())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> fcp_core::FcpResult<HandshakeResponse> {
        let value = serde_json::to_value(req).map_err(|err| FcpError::Internal {
            message: format!("failed to serialize handshake request: {err}"),
        })?;
        let response = self.connector.handle_handshake(value).await?;
        serde_json::from_value(response).map_err(|err| FcpError::Internal {
            message: format!("failed to deserialize handshake response: {err}"),
        })
    }

    async fn health(&self) -> HealthSnapshot {
        match self.connector.handle_health().await {
            Ok(payload) => match payload.get("status").and_then(serde_json::Value::as_str) {
                Some("healthy") => HealthSnapshot::ready(),
                Some(other) => HealthSnapshot::degraded(format!("drive_status:{other}")),
                None => HealthSnapshot::error("drive_status:missing".to_string()),
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
                id: OperationId::from_static("drive.list_files"),
                summary: "List files and folders in Google Drive".to_string(),
                description: None,
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "query": { "type": "string" }
                    }
                }),
                output_schema: json!({
                    "type": "object",
                    "properties": {
                        "files": { "type": "array" }
                    }
                }),
                capability: CapabilityId::from_static("drive.read"),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "List Drive files via the connector.".to_string(),
                    common_mistakes: Vec::new(),
                    examples: vec![r#"{"query":"name contains 'report'"}"#.to_string()],
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
        let value = self.connector.handle_invoke(params).await?;
        Ok(InvokeResponse::ok(request_id, value))
    }

    async fn simulate(&self, req: SimulateRequest) -> fcp_core::FcpResult<SimulateResponse> {
        let value = serde_json::to_value(req).map_err(|err| FcpError::Internal {
            message: format!("failed to serialize simulate request: {err}"),
        })?;
        let response = self.connector.handle_simulate(value).await?;
        serde_json::from_value(response).map_err(|err| FcpError::Internal {
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

fn handshake_request(host_public_key: [u8; 32], capabilities: &[&str]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0".to_string(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [11u8; 32],
        capabilities_requested: capabilities
            .iter()
            .map(|cap| cap.parse::<CapabilityId>().expect("capability id"))
            .collect(),
        host: None,
        transport_caps: None,
        requested_instance_id: Some(InstanceId::new()),
    }
}

fn build_token(signing_key: &Ed25519SigningKey) -> CapabilityToken {
    let now = Utc::now();
    let cose = CapabilityTokenBuilder::new()
        .capability_id("drive.read")
        .zone_id("z:work")
        .principal("user:test")
        .operations(&["drive.list_files"])
        .issuer("node:test")
        .validity(now, now + ChronoDuration::hours(1))
        .sign(signing_key)
        .expect("capability token");
    CapabilityToken::from_raw(cose)
}

#[fcp_async_core::runtime::test]
async fn connector_suite_happy_path_lists_files() {
    init_json_test_logging();
    info!(test = "google_drive_connector_suite_happy_path", phase = "setup");

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/drive/v3/files"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "files": [
                {
                    "id": "file_123",
                    "name": "Quarterly Report",
                    "mimeType": "application/pdf"
                }
            ],
            "nextPageToken": null
        })))
        .mount(&server)
        .await;

    let mut connector = GoogleDriveAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(signing_key.verifying_key().to_bytes(), &["drive.read"]);
    let token = build_token(&signing_key);
    let invoke = InvokeRequest {
        r#type: "invoke".to_string(),
        id: RequestId::from("drive-happy-path"),
        connector_id: ConnectorId::from_static("google-drive"),
        operation: OperationId::from_static("drive.list_files"),
        zone_id: ZoneId::work(),
        input: json!({ "query": "name contains 'Report'" }),
        capability_token: token,
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
        test_name: "google_drive_happy_path".to_string(),
        config: json!({
            "access_token": "ya29_test_drive",
            "base_url": format!("{}/drive/v3", server.uri()),
        }),
        handshake,
        invoke: Some(invoke),
        invoke_expectations: InvokeExpectations::default(),
    };

    let mut runner = E2eRunner::new("fcp-google-drive");
    let report = runner
        .run_connector_suite(&mut connector, suite)
        .await
        .expect("connector suite run");

    for entry in &report.logs {
        println!("{}", serde_json::to_string(entry).expect("serialize report log"));
    }

    info!(
        test = "google_drive_connector_suite_happy_path",
        phase = "verify",
        passed = report.passed,
        log_entries = report.logs.len()
    );
    assert!(report.passed, "connector suite should pass");
    assert!(!report.logs.is_empty(), "structured logs should be present");
}
