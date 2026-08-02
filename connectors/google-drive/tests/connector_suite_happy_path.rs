use std::sync::Once;

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_e2e::{ConnectorSuite, E2eRunner, InvokeExpectations};
use fcp_google_discovery::auth::{GoogleAuthSourceKind, GoogleMaterializedAuth};
use fcp_google_drive::client::DriveClient;
use fcp_google_drive::connector::DriveConnector;
use fcp_prelude::{
    AgentHint, CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, ConnectorMetrics,
    FcpConnector, FcpError, HandshakeRequest, HandshakeResponse, HealthSnapshot, IdempotencyClass,
    InstanceId, Introspection, InvokeRequest, InvokeResponse, OperationId, OperationInfo,
    RequestId, RiskLevel, SafetyTier, ShutdownRequest, SimulateRequest, SimulateResponse,
    SubscribeRequest, SubscribeResponse, UnsubscribeRequest, ZoneId,
};
use serde_json::json;
use tracing::info;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, body_string_contains, header, method, path, query_param},
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

fn fixture_bearer() -> String {
    "ya29_test_drive".to_owned()
}

fn direct_test_client(server: &MockServer) -> DriveClient {
    DriveClient::new_with_auth(GoogleMaterializedAuth::BearerToken {
        access_token: fixture_bearer(),
        source: GoogleAuthSourceKind::AccessToken,
        granted_scopes: Vec::new(),
        quota_project_id: None,
    })
    .expect("test client")
    .with_base_url(&format!("{}/drive/v3", server.uri()))
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
            Ok(payload) => serde_json::from_value(payload)
                .unwrap_or_else(|err| HealthSnapshot::error(err.to_string())),
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
            operations: vec![
                OperationInfo {
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
                },
                OperationInfo {
                    id: OperationId::from_static("drive.get_file"),
                    summary: "Get Google Drive file metadata".to_string(),
                    description: None,
                    input_schema: json!({
                        "type": "object",
                        "required": ["file_id"],
                        "properties": {
                            "file_id": { "type": "string" }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "properties": {
                            "file": { "type": "object" }
                        }
                    }),
                    capability: CapabilityId::from_static("drive.read"),
                    risk_level: RiskLevel::Low,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Retrieve metadata for one Drive file.".to_string(),
                        common_mistakes: Vec::new(),
                        examples: vec![r#"{"file_id":"file_123"}"#.to_string()],
                        related: Vec::new(),
                    },
                    rate_limit: None,
                    requires_approval: None,
                },
            ],
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

fn handshake_request(
    host_public_key: [u8; 32],
    capabilities: &[&str],
    instance_id: &InstanceId,
) -> HandshakeRequest {
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
        requested_instance_id: Some(instance_id.clone()),
    }
}

fn build_token(
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
    instance_id: &InstanceId,
) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".to_string()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");

    let capability = match operation {
        "drive.mark_for_deletion_review" | "drive.restore_from_deletion_review" => {
            "drive.quarantine.write"
        }
        "drive.upload_file" | "drive.update_content" => "drive.content.write",
        _ => "drive.read",
    };
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .target_instance(instance_id.as_str())
        .principal("user:test")
        .operations(&[operation])
        .issuer("node:test")
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("valid constraints cbor")
        .sign(signing_key)
        .expect("capability token");
    CapabilityToken::from_raw(cose)
}

fn drive_invoke(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    id: &'static str,
    operation: &'static str,
    input: serde_json::Value,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".to_string(),
        id: RequestId::from(id),
        connector_id: ConnectorId::from_static("google-drive"),
        operation: OperationId::from_static(operation),
        zone_id: ZoneId::work(),
        input,
        capability_token: build_token(signing_key, operation, instance_id),
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
async fn direct_client_covers_shared_pagination_drives_and_resource_keys() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/drive/v3/files"))
        .and(query_param(
            "q",
            "(sharedWithMe = true and (name contains 'report')) and trashed = false",
        ))
        .and(query_param("pageSize", "25"))
        .and(query_param("pageToken", "page_2"))
        .and(query_param("supportsAllDrives", "true"))
        .and(query_param("includeItemsFromAllDrives", "true"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "drive#fileList",
            "nextPageToken": "page_3",
            "files": [{
                "id": "shared_file",
                "name": "report.pdf",
                "mimeType": "application/pdf",
                "shared": true,
                "trashed": false
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/drive/v3/drives"))
        .and(query_param("pageSize", "10"))
        .and(query_param("pageToken", "drive_page_2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "nextPageToken": "drive_page_3",
            "drives": [{"id": "shared_drive", "name": "Team Drive"}]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/drive/v3/files/shared_file"))
        .and(query_param("resourceKey", "resource_key_1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "shared_file",
            "name": "report.pdf",
            "mimeType": "application/pdf",
            "trashed": false
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = direct_test_client(&server);
    let shared = client
        .list_shared_with_me(Some("name contains 'report'"), Some(25), Some("page_2"))
        .await
        .expect("shared files");
    assert_eq!(shared.next_page_token.as_deref(), Some("page_3"));
    assert_eq!(shared.files[0].id, "shared_file");
    let drives = client
        .list_drives(Some(10), Some("drive_page_2"))
        .await
        .expect("shared drives");
    assert_eq!(drives["nextPageToken"], "drive_page_3");
    let file = client
        .get_file("shared_file", Some("resource_key_1"))
        .await
        .expect("resource-key file");
    assert_eq!(file.id, "shared_file");
}

#[fcp_async_core::runtime::test]
async fn direct_client_covers_permission_add_update_and_revoke() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/drive/v3/files/file_acl/permissions"))
        .and(body_json(json!({
            "type": "user",
            "role": "reader",
            "emailAddress": "reader@example.com"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "permission_1",
            "type": "user",
            "role": "reader",
            "emailAddress": "reader@example.com"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/drive/v3/files/file_acl/permissions/permission_1"))
        .and(body_json(json!({"role": "writer"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "permission_1",
            "type": "user",
            "role": "writer",
            "emailAddress": "reader@example.com"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/drive/v3/files/file_acl/permissions/permission_1"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = direct_test_client(&server);
    let added = client
        .add_permission(
            "file_acl",
            "user",
            "reader",
            Some("reader@example.com"),
            None,
        )
        .await
        .expect("add permission");
    assert_eq!(added.id, "permission_1");
    let updated = client
        .update_permission("file_acl", "permission_1", "writer")
        .await
        .expect("update permission");
    assert_eq!(updated.role, "writer");
    client
        .revoke_permission("file_acl", "permission_1")
        .await
        .expect("revoke permission");
}

#[fcp_async_core::runtime::test]
async fn direct_client_surfaces_rate_limit_after_bounded_retries() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/drive/v3/files"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("Retry-After", "0")
                .set_body_json(json!({
                    "error": {"code": 429, "message": "rate limited", "status": "RESOURCE_EXHAUSTED"}
                })),
        )
        .expect(3)
        .mount(&server)
        .await;

    let error = direct_test_client(&server)
        .list_files(None, Some(10), None, None, None)
        .await
        .expect_err("rate limit");
    assert!(matches!(
        error,
        fcp_google_drive::error::DriveError::RateLimited { .. }
            | fcp_google_drive::error::DriveError::Api {
                status_code: 429,
                ..
            }
    ));
}

#[fcp_async_core::runtime::test]
async fn connector_suite_happy_path_lists_files() {
    init_json_test_logging();
    info!(
        test = "google_drive_connector_suite_happy_path",
        phase = "setup"
    );

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/drive/v3/files"))
        .and(header("authorization", "Bearer ya29_test_drive"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "drive#fileList",
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
    let instance_id = InstanceId::new();
    let handshake = handshake_request(
        signing_key.verifying_key().to_bytes(),
        &["drive.read"],
        &instance_id,
    );
    let invoke = drive_invoke(
        &signing_key,
        &instance_id,
        "drive-happy-path",
        "drive.list_files",
        json!({ "query": "name contains 'Report'" }),
    );

    let suite = ConnectorSuite {
        test_name: "google_drive_happy_path".to_string(),
        config: json!({
            "access_token": fixture_bearer(),
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
        println!(
            "{}",
            serde_json::to_string(entry).expect("serialize report log")
        );
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

#[fcp_async_core::runtime::test]
async fn mark_for_deletion_review_moves_owned_file_without_trashing_it() {
    let server = MockServer::start().await;
    let review_name = format!(
        "[FCP-DELETE-REVIEW {}] report.txt",
        Utc::now().format("%Y-%m-%d")
    );
    let file_json = json!({
        "id": "file_owned",
        "name": "report.txt",
        "mimeType": "text/plain",
        "parents": ["folder_original"],
        "trashed": false,
        "owners": [{"emailAddress": "owner@example.com"}],
        "permissions": [{"id": "perm_owner", "role": "owner", "type": "user", "emailAddress": "Owner@Example.com", "displayName": "Owner Full Name"}],
        "md5Checksum": "abc123"
    });
    Mock::given(method("GET"))
        .and(path("/drive/v3/files/file_owned"))
        .respond_with(ResponseTemplate::new(200).set_body_json(file_json))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/drive/v3/about"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "drive#about",
            "user": {"emailAddress": "owner@example.com"}
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/drive/v3/files"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "drive#fileList",
            "files": []
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/drive/v3/files"))
        .and(body_json(json!({
            "name": "_FCP_DELETE_REVIEW",
            "mimeType": "application/vnd.google-apps.folder",
            "parents": ["root"]
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "folder_review",
            "name": "_FCP_DELETE_REVIEW",
            "mimeType": "application/vnd.google-apps.folder",
            "parents": ["root"],
            "trashed": false
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/drive/v3/files/file_owned"))
        .and(body_json(json!({"name": review_name})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "file_owned",
            "name": review_name,
            "mimeType": "text/plain",
            "parents": ["folder_original"],
            "trashed": false
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/drive/v3/files/file_owned"))
        .and(query_param("addParents", "folder_review"))
        .and(query_param("removeParents", "folder_original"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "file_owned",
            "name": review_name,
            "mimeType": "text/plain",
            "parents": ["folder_review"],
            "trashed": false,
            "owners": [{"emailAddress": "owner@example.com"}],
            "permissions": [{"id": "perm_owner", "role": "owner", "type": "user", "emailAddress": "owner@example.com", "displayName": "owner-alias"}],
            "md5Checksum": "abc123"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let mut connector = GoogleDriveAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();
    let suite = ConnectorSuite {
        test_name: "google_drive_mark_deletion_review".to_string(),
        config: json!({
            "access_token": fixture_bearer(),
            "base_url": format!("{}/drive/v3", server.uri()),
        }),
        handshake: handshake_request(
            signing_key.verifying_key().to_bytes(),
            &["drive.quarantine.write"],
            &instance_id,
        ),
        invoke: Some(drive_invoke(
            &signing_key,
            &instance_id,
            "drive-mark-review",
            "drive.mark_for_deletion_review",
            json!({"file_id": "file_owned"}),
        )),
        invoke_expectations: InvokeExpectations::default(),
    };
    let mut runner = E2eRunner::new("fcp-google-drive");
    let report = runner
        .run_connector_suite(&mut connector, suite)
        .await
        .expect("connector suite run");
    assert!(report.passed, "owned file should move into review folder");
}

#[fcp_async_core::runtime::test]
async fn mark_for_deletion_review_rolls_back_security_verification_failure() {
    let server = MockServer::start().await;
    let review_name = format!(
        "[FCP-DELETE-REVIEW {}] report.txt",
        Utc::now().format("%Y-%m-%d")
    );
    Mock::given(method("GET"))
        .and(path("/drive/v3/files/file_owned"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "file_owned",
            "name": "report.txt",
            "mimeType": "text/plain",
            "parents": ["folder_original"],
            "trashed": false,
            "owners": [{"emailAddress": "owner@example.com"}],
            "permissions": [{"id": "perm_owner", "role": "owner", "type": "user"}],
            "md5Checksum": "abc123"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/drive/v3/about"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "drive#about",
            "user": {"emailAddress": "owner@example.com"}
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/drive/v3/files"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "drive#fileList",
            "files": []
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/drive/v3/files"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "folder_review",
            "name": "_FCP_DELETE_REVIEW",
            "mimeType": "application/vnd.google-apps.folder",
            "parents": ["root"],
            "trashed": false
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/drive/v3/files/file_owned"))
        .and(body_json(json!({"name": review_name})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "file_owned",
            "name": review_name,
            "mimeType": "text/plain",
            "parents": ["folder_original"],
            "trashed": false
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/drive/v3/files/file_owned"))
        .and(query_param("addParents", "folder_review"))
        .and(query_param("removeParents", "folder_original"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "file_owned",
            "name": review_name,
            "mimeType": "text/plain",
            "parents": ["folder_review"],
            "trashed": false,
            "owners": [{"emailAddress": "owner@example.com"}],
            "permissions": [{"id": "perm_owner", "role": "writer", "type": "user"}],
            "md5Checksum": "abc123"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/drive/v3/files/file_owned"))
        .and(query_param("addParents", "folder_original"))
        .and(query_param("removeParents", "folder_review"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "file_owned",
            "name": review_name,
            "mimeType": "text/plain",
            "parents": ["folder_original"],
            "trashed": false
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/drive/v3/files/file_owned"))
        .and(body_json(json!({"name": "report.txt"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "file_owned",
            "name": "report.txt",
            "mimeType": "text/plain",
            "parents": ["folder_original"],
            "trashed": false
        })))
        .expect(1)
        .mount(&server)
        .await;

    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();
    let mut connector = DriveConnector::new();
    connector
        .handle_configure(json!({
            "access_token": fixture_bearer(),
            "base_url": format!("{}/drive/v3", server.uri()),
        }))
        .await
        .unwrap();
    connector
        .handle_handshake(
            serde_json::to_value(handshake_request(
                signing_key.verifying_key().to_bytes(),
                &["drive.quarantine.write"],
                &instance_id,
            ))
            .unwrap(),
        )
        .await
        .unwrap();

    let error = connector
        .handle_invoke(json!({
            "operation": "drive.mark_for_deletion_review",
            "input": {"file_id": "file_owned"},
            "capability_token": build_token(
                &signing_key,
                "drive.mark_for_deletion_review",
                &instance_id,
            )
        }))
        .await
        .expect_err("security-relevant permission drift must fail after rollback");
    assert!(
        matches!(error, FcpError::External { ref message, .. } if message.contains("rolled back"))
    );
}

#[fcp_async_core::runtime::test]
async fn mark_for_deletion_review_shortcuts_foreign_file_without_changing_original() {
    let server = MockServer::start().await;
    let review_name = format!(
        "[FCP-DELETE-REVIEW {}] shared.pdf",
        Utc::now().format("%Y-%m-%d")
    );
    let original = json!({
        "id": "file_foreign",
        "name": "shared.pdf",
        "mimeType": "application/pdf",
        "parents": ["foreign_parent"],
        "trashed": false,
        "owners": [{"emailAddress": "someone@example.com"}],
        "permissions": [{"id": "perm_reader", "role": "reader", "type": "user"}],
        "md5Checksum": "foreign123"
    });
    Mock::given(method("GET"))
        .and(path("/drive/v3/files/file_foreign"))
        .respond_with(ResponseTemplate::new(200).set_body_json(original))
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/drive/v3/about"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "drive#about",
            "user": {"emailAddress": "me@example.com"}
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/drive/v3/files"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "drive#fileList",
            "files": []
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/drive/v3/files"))
        .and(body_json(json!({
            "name": "_FCP_DELETE_REVIEW",
            "mimeType": "application/vnd.google-apps.folder",
            "parents": ["root"]
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "folder_review",
            "name": "_FCP_DELETE_REVIEW",
            "mimeType": "application/vnd.google-apps.folder",
            "parents": ["root"],
            "trashed": false
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/drive/v3/files"))
        .and(body_json(json!({
            "name": format!("{review_name} [owner: someone@example.com]"),
            "mimeType": "application/vnd.google-apps.shortcut",
            "shortcutDetails": {"targetId": "file_foreign"},
            "parents": ["folder_review"]
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "shortcut_review",
            "name": review_name,
            "mimeType": "application/vnd.google-apps.shortcut",
            "parents": ["folder_review"],
            "shortcutDetails": {"targetId": "file_foreign"}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let mut connector = GoogleDriveAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();
    let suite = ConnectorSuite {
        test_name: "google_drive_mark_foreign_deletion_review".to_string(),
        config: json!({
            "access_token": fixture_bearer(),
            "base_url": format!("{}/drive/v3", server.uri()),
        }),
        handshake: handshake_request(
            signing_key.verifying_key().to_bytes(),
            &["drive.quarantine.write"],
            &instance_id,
        ),
        invoke: Some(drive_invoke(
            &signing_key,
            &instance_id,
            "drive-mark-foreign-review",
            "drive.mark_for_deletion_review",
            json!({"file_id": "file_foreign"}),
        )),
        invoke_expectations: InvokeExpectations::default(),
    };
    let report = E2eRunner::new("fcp-google-drive")
        .run_connector_suite(&mut connector, suite)
        .await
        .expect("connector suite run");
    assert!(report.passed, "foreign original should remain unchanged");
}

#[fcp_async_core::runtime::test]
async fn shared_drive_original_move_requires_confirmation_and_stays_in_the_same_drive() {
    let server = MockServer::start().await;
    let review_name = format!(
        "[FCP-DELETE-REVIEW {}] team-plan.pdf",
        Utc::now().format("%Y-%m-%d")
    );
    let original = json!({
        "id": "file_shared_drive",
        "name": "team-plan.pdf",
        "mimeType": "application/pdf",
        "parents": ["team_parent"],
        "trashed": false,
        "owners": [],
        "permissions": [{"id": "perm_team", "role": "organizer", "type": "user"}],
        "driveId": "team_drive",
        "md5Checksum": "team123",
        "capabilities": {"canMoveItemWithinDrive": true}
    });
    Mock::given(method("GET"))
        .and(path("/drive/v3/files/file_shared_drive"))
        .respond_with(ResponseTemplate::new(200).set_body_json(original))
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/drive/v3/about"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "drive#about",
            "user": {"emailAddress": "me@example.com"}
        })))
        .expect(2)
        .mount(&server)
        .await;

    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();
    let mut connector = DriveConnector::new();
    connector
        .handle_configure(json!({
            "access_token": fixture_bearer(),
            "base_url": format!("{}/drive/v3", server.uri()),
        }))
        .await
        .unwrap();
    connector
        .handle_handshake(
            serde_json::to_value(handshake_request(
                signing_key.verifying_key().to_bytes(),
                &["drive.quarantine.write"],
                &instance_id,
            ))
            .unwrap(),
        )
        .await
        .unwrap();

    let denied = connector
        .handle_invoke(json!({
            "operation": "drive.mark_for_deletion_review",
            "input": {
                "file_id": "file_shared_drive",
                "mode": "move_shared_drive_original"
            },
            "capability_token": build_token(
                &signing_key,
                "drive.mark_for_deletion_review",
                &instance_id,
            )
        }))
        .await
        .expect_err("shared Drive original move must require explicit confirmation");
    assert!(matches!(denied, FcpError::InvalidRequest { .. }));

    Mock::given(method("GET"))
        .and(path("/drive/v3/files"))
        .and(query_param("corpora", "drive"))
        .and(query_param("driveId", "team_drive"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "drive#fileList",
            "files": []
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/drive/v3/files"))
        .and(body_json(json!({
            "name": "_FCP_DELETE_REVIEW",
            "mimeType": "application/vnd.google-apps.folder",
            "parents": ["team_drive"]
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "team_review",
            "name": "_FCP_DELETE_REVIEW",
            "mimeType": "application/vnd.google-apps.folder",
            "parents": ["team_drive"],
            "driveId": "team_drive",
            "trashed": false
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/drive/v3/files/file_shared_drive"))
        .and(body_json(json!({"name": review_name})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "file_shared_drive",
            "name": review_name,
            "mimeType": "application/pdf",
            "parents": ["team_parent"],
            "driveId": "team_drive",
            "trashed": false
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/drive/v3/files/file_shared_drive"))
        .and(query_param("addParents", "team_review"))
        .and(query_param("removeParents", "team_parent"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "file_shared_drive",
            "name": review_name,
            "mimeType": "application/pdf",
            "parents": ["team_review"],
            "trashed": false,
            "owners": [],
            "permissions": [{"id": "perm_team", "role": "organizer", "type": "user"}],
            "driveId": "team_drive",
            "md5Checksum": "team123",
            "capabilities": {"canMoveItemWithinDrive": true}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let result = connector
        .handle_invoke(json!({
            "operation": "drive.mark_for_deletion_review",
            "input": {
                "file_id": "file_shared_drive",
                "mode": "move_shared_drive_original",
                "confirm_shared_drive_move": true
            },
            "capability_token": build_token(
                &signing_key,
                "drive.mark_for_deletion_review",
                &instance_id,
            )
        }))
        .await
        .expect("confirmed Shared Drive move within the same Drive");
    assert_eq!(result["receipt"]["mode"], "shared_drive_move");
    assert_eq!(result["receipt"]["drive_id"], "team_drive");
    assert_eq!(result["file"]["parents"], json!(["team_review"]));
    assert_eq!(result["file"]["trashed"], false);
}

#[fcp_async_core::runtime::test]
async fn restore_from_deletion_review_moves_and_renames_owned_file() {
    let server = MockServer::start().await;
    let review_name = "[FCP-DELETE-REVIEW 2026-08-02] report.txt";
    let permissions = json!([{"id": "perm_owner", "role": "owner", "type": "user"}]);
    Mock::given(method("GET"))
        .and(path("/drive/v3/files/file_owned"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "file_owned",
            "name": review_name,
            "mimeType": "text/plain",
            "parents": ["folder_review"],
            "trashed": false,
            "permissions": permissions.clone(),
            "md5Checksum": "abc123"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/drive/v3/files/file_owned"))
        .and(query_param("addParents", "folder_original"))
        .and(query_param("removeParents", "folder_review"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "file_owned",
            "name": review_name,
            "mimeType": "text/plain",
            "parents": ["folder_original"],
            "trashed": false,
            "permissions": permissions.clone(),
            "md5Checksum": "abc123"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/drive/v3/files/file_owned"))
        .and(body_json(json!({"name": "report.txt"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "file_owned",
            "name": "report.txt",
            "mimeType": "text/plain",
            "parents": ["folder_original"],
            "trashed": false,
            "permissions": permissions.clone(),
            "md5Checksum": "abc123"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let receipt = json!({
        "version": 1,
        "mode": "owned_move",
        "file_id": "file_owned",
        "original_name": "report.txt",
        "original_parents": ["folder_original"],
        "review_name": review_name,
        "review_folder_id": "folder_review",
        "drive_id": null,
        "md5_checksum": "abc123",
        "permissions": permissions,
        "shortcut_id": null,
        "resource_key": null
    });
    let mut connector = GoogleDriveAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();
    let suite = ConnectorSuite {
        test_name: "google_drive_restore_deletion_review".to_string(),
        config: json!({
            "access_token": fixture_bearer(),
            "base_url": format!("{}/drive/v3", server.uri()),
        }),
        handshake: handshake_request(
            signing_key.verifying_key().to_bytes(),
            &["drive.quarantine.write"],
            &instance_id,
        ),
        invoke: Some(drive_invoke(
            &signing_key,
            &instance_id,
            "drive-restore-review",
            "drive.restore_from_deletion_review",
            json!({"receipt": receipt}),
        )),
        invoke_expectations: InvokeExpectations::default(),
    };
    let report = E2eRunner::new("fcp-google-drive")
        .run_connector_suite(&mut connector, suite)
        .await
        .expect("connector suite run");
    assert!(report.passed, "owned file should restore from receipt");
}

#[fcp_async_core::runtime::test]
async fn upload_file_sends_real_multipart_related_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/upload/drive/v3/files"))
        .and(query_param("uploadType", "multipart"))
        .and(header(
            "content-type",
            "multipart/related; boundary=fcp-google-upload-boundary-0",
        ))
        .and(header("authorization", "Bearer ya29_test_drive"))
        .and(body_string_contains(
            "{\"mimeType\":\"text/plain\",\"name\":\"notes.txt\",\"parents\":[\"folder_a\"]}",
        ))
        .and(body_string_contains(
            "Content-Type: text/plain\r\n\r\nhello",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "file_new",
            "name": "notes.txt",
            "mimeType": "text/plain",
            "size": "5",
            "parents": ["folder_a"],
            "trashed": false
        })))
        .expect(1)
        .mount(&server)
        .await;

    let mut connector = GoogleDriveAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();
    let suite = ConnectorSuite {
        test_name: "google_drive_multipart_upload".to_string(),
        config: json!({
            "access_token": fixture_bearer(),
            "base_url": format!("{}/drive/v3", server.uri()),
        }),
        handshake: handshake_request(
            signing_key.verifying_key().to_bytes(),
            &["drive.content.write"],
            &instance_id,
        ),
        invoke: Some(drive_invoke(
            &signing_key,
            &instance_id,
            "drive-upload-multipart",
            "drive.upload_file",
            json!({
                "name": "notes.txt",
                "mime_type": "text/plain",
                "content_base64": "aGVsbG8=",
                "parent_id": "folder_a",
                "upload_mode": "multipart"
            }),
        )),
        invoke_expectations: InvokeExpectations::default(),
    };
    let report = E2eRunner::new("fcp-google-drive")
        .run_connector_suite(&mut connector, suite)
        .await
        .expect("connector suite run");
    assert!(report.passed, "multipart upload should pass");
}

#[fcp_async_core::runtime::test]
async fn upload_file_completes_validated_resumable_session() {
    let server = MockServer::start().await;
    let session_url = format!(
        "{}/upload/drive/v3/files?uploadType=resumable&upload_id=session_1",
        server.uri()
    );
    Mock::given(method("POST"))
        .and(path("/upload/drive/v3/files"))
        .and(query_param("uploadType", "resumable"))
        .and(header("x-upload-content-type", "application/octet-stream"))
        .and(header("x-upload-content-length", "4"))
        .and(body_json(json!({
            "name": "blob.bin",
            "mimeType": "application/octet-stream"
        })))
        .respond_with(ResponseTemplate::new(200).insert_header("Location", session_url.as_str()))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/upload/drive/v3/files"))
        .and(query_param("upload_id", "session_1"))
        .and(header("content-type", "application/octet-stream"))
        .and(header("content-length", "4"))
        .and(header("authorization", "Bearer ya29_test_drive"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "file_resumable",
            "name": "blob.bin",
            "mimeType": "application/octet-stream",
            "size": "4",
            "trashed": false
        })))
        .expect(1)
        .mount(&server)
        .await;

    let mut connector = GoogleDriveAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();
    let suite = ConnectorSuite {
        test_name: "google_drive_resumable_upload".to_string(),
        config: json!({
            "access_token": fixture_bearer(),
            "base_url": format!("{}/drive/v3", server.uri()),
        }),
        handshake: handshake_request(
            signing_key.verifying_key().to_bytes(),
            &["drive.content.write"],
            &instance_id,
        ),
        invoke: Some(drive_invoke(
            &signing_key,
            &instance_id,
            "drive-upload-resumable",
            "drive.upload_file",
            json!({
                "name": "blob.bin",
                "mime_type": "application/octet-stream",
                "content_base64": "AAECAw==",
                "upload_mode": "resumable"
            }),
        )),
        invoke_expectations: InvokeExpectations::default(),
    };
    let report = E2eRunner::new("fcp-google-drive")
        .run_connector_suite(&mut connector, suite)
        .await
        .expect("connector suite run");
    assert!(report.passed, "resumable upload should pass");
}

#[fcp_async_core::runtime::test]
async fn update_content_uses_patch_without_trash_fields() {
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path("/upload/drive/v3/files/file_existing"))
        .and(query_param("uploadType", "multipart"))
        .and(header(
            "content-type",
            "multipart/related; boundary=fcp-google-upload-boundary-0",
        ))
        .and(body_string_contains("{\"mimeType\":\"text/plain\"}"))
        .and(body_string_contains("Content-Type: text/plain\r\n\r\nnew"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "file_existing",
            "name": "existing.txt",
            "mimeType": "text/plain",
            "size": "3",
            "trashed": false
        })))
        .expect(1)
        .mount(&server)
        .await;

    let mut connector = GoogleDriveAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();
    let suite = ConnectorSuite {
        test_name: "google_drive_update_content".to_string(),
        config: json!({
            "access_token": fixture_bearer(),
            "base_url": format!("{}/drive/v3", server.uri()),
        }),
        handshake: handshake_request(
            signing_key.verifying_key().to_bytes(),
            &["drive.content.write"],
            &instance_id,
        ),
        invoke: Some(drive_invoke(
            &signing_key,
            &instance_id,
            "drive-update-content",
            "drive.update_content",
            json!({
                "file_id": "file_existing",
                "mime_type": "text/plain",
                "content_base64": "bmV3"
            }),
        )),
        invoke_expectations: InvokeExpectations::default(),
    };
    let report = E2eRunner::new("fcp-google-drive")
        .run_connector_suite(&mut connector, suite)
        .await
        .expect("connector suite run");
    assert!(report.passed, "content update should pass");
}

#[fcp_async_core::runtime::test]
async fn resumable_upload_rejects_session_location_path_change() {
    let server = MockServer::start().await;
    let invalid_location = format!("{}/unexpected-upload-target?upload_id=evil", server.uri());
    Mock::given(method("POST"))
        .and(path("/upload/drive/v3/files"))
        .and(query_param("uploadType", "resumable"))
        .respond_with(
            ResponseTemplate::new(200).insert_header("Location", invalid_location.as_str()),
        )
        .expect(1)
        .mount(&server)
        .await;

    let mut connector = GoogleDriveAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();
    let suite = ConnectorSuite {
        test_name: "google_drive_resumable_location_rejected".to_string(),
        config: json!({
            "access_token": fixture_bearer(),
            "base_url": format!("{}/drive/v3", server.uri()),
        }),
        handshake: handshake_request(
            signing_key.verifying_key().to_bytes(),
            &["drive.content.write"],
            &instance_id,
        ),
        invoke: Some(drive_invoke(
            &signing_key,
            &instance_id,
            "drive-upload-invalid-location",
            "drive.upload_file",
            json!({
                "name": "blob.bin",
                "mime_type": "application/octet-stream",
                "content_base64": "AAECAw==",
                "upload_mode": "resumable"
            }),
        )),
        invoke_expectations: InvokeExpectations {
            expect_error: true,
            ..InvokeExpectations::default()
        },
    };
    let report = E2eRunner::new("fcp-google-drive")
        .run_connector_suite(&mut connector, suite)
        .await
        .expect("connector suite run");
    assert!(report.passed, "unsafe session Location should be rejected");
    assert_eq!(server.received_requests().await.expect("requests").len(), 1);
}

#[fcp_async_core::runtime::test]
async fn upload_rejects_invalid_base64_before_provider_io() {
    let server = MockServer::start().await;
    let mut connector = GoogleDriveAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();
    let suite = ConnectorSuite {
        test_name: "google_drive_invalid_upload_base64".to_string(),
        config: json!({
            "access_token": fixture_bearer(),
            "base_url": format!("{}/drive/v3", server.uri()),
        }),
        handshake: handshake_request(
            signing_key.verifying_key().to_bytes(),
            &["drive.content.write"],
            &instance_id,
        ),
        invoke: Some(drive_invoke(
            &signing_key,
            &instance_id,
            "drive-upload-invalid-base64",
            "drive.upload_file",
            json!({
                "name": "bad.bin",
                "mime_type": "application/octet-stream",
                "content_base64": "%%%not-base64%%%"
            }),
        )),
        invoke_expectations: InvokeExpectations {
            expect_error: true,
            ..InvokeExpectations::default()
        },
    };
    let report = E2eRunner::new("fcp-google-drive")
        .run_connector_suite(&mut connector, suite)
        .await
        .expect("connector suite run");
    assert!(report.passed, "invalid base64 should be rejected");
    assert!(
        server
            .received_requests()
            .await
            .expect("requests")
            .is_empty(),
        "invalid content must be rejected before provider I/O"
    );
}

#[fcp_async_core::runtime::test]
async fn connector_suite_error_path_reports_not_found_file() {
    init_json_test_logging();
    info!(
        test = "google_drive_connector_suite_not_found",
        phase = "setup"
    );

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/drive/v3/files/file_missing"))
        .and(header("authorization", "Bearer ya29_test_drive"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": {
                "code": 404,
                "message": "File not found: file_missing",
                "status": "NOT_FOUND",
                "errors": [
                    {
                        "domain": "global",
                        "reason": "notFound",
                        "message": "File not found: file_missing"
                    }
                ]
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let mut connector = GoogleDriveAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();
    let handshake = handshake_request(
        signing_key.verifying_key().to_bytes(),
        &["drive.read"],
        &instance_id,
    );
    let invoke = drive_invoke(
        &signing_key,
        &instance_id,
        "drive-not-found",
        "drive.get_file",
        json!({ "file_id": "file_missing" }),
    );

    let suite = ConnectorSuite {
        test_name: "google_drive_get_file_not_found".to_string(),
        config: json!({
            "access_token": fixture_bearer(),
            "base_url": format!("{}/drive/v3", server.uri()),
        }),
        handshake,
        invoke: Some(invoke),
        invoke_expectations: InvokeExpectations {
            expect_error: true,
            expected_reason_code: Some("FCP-6001".to_string()),
            ..InvokeExpectations::default()
        },
    };

    let mut runner = E2eRunner::new("fcp-google-drive");
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

    info!(
        test = "google_drive_connector_suite_not_found",
        phase = "verify",
        passed = report.passed,
        log_entries = report.logs.len()
    );
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
        json!("FCP-6001"),
        "Drive 404 should map to the FCP not-found code"
    );
    assert_eq!(
        execute["context"]["retryable"],
        json!(false),
        "not-found responses should be reported as terminal"
    );
}
