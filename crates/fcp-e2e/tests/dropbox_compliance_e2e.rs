//! E2E Dropbox connector compliance tests.
//!
//! Exercises the Dropbox connector through the shared E2E harness:
//! - Default deny behavior for capability mismatch
//! - Allow path with valid capability token
//! - Network guard allow/deny checks via manifest constraints
//!
//! All tests are deterministic with mock servers only.
//! Run: `cargo test --package fcp-e2e --features dropbox`

#![cfg(feature = "dropbox")]
#![allow(clippy::too_many_lines)]

use chrono::{Duration as ChronoDuration, Utc};
use fcp_conformance::DynamicSuite;
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_dropbox::connector::DropboxConnector;
use fcp_e2e::{
    ComplianceSuite, ConnectorSuite, E2eReport, E2eRunner, InvokeExpectations, scan_log_jsonl,
    validate_log_entry_value,
};
use fcp_manifest::ConnectorManifest;
use fcp_prelude::InvokeStatus;
use fcp_prelude::{
    AgentHint, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier, ConnectorId,
    ConnectorMetrics, FcpConnector, FcpError, HandshakeRequest, HandshakeResponse, HealthSnapshot,
    IdempotencyClass, InstanceId, Introspection, InvokeRequest, InvokeResponse, OperationId,
    OperationInfo, RequestId, RiskLevel, SafetyTier, SessionId, ShutdownRequest, SimulateRequest,
    SimulateResponse, SubscribeRequest, SubscribeResponse, UnsubscribeRequest, ZoneId,
};
use fcp_testkit::MockApiServer;
use serde_json::json;
use wiremock::{
    Mock, ResponseTemplate,
    matchers::{method, path_regex},
};

struct DropboxConnectorAdapter {
    connector: DropboxConnector,
    id: ConnectorId,
    instance_id: InstanceId,
    verifier: Option<CapabilityVerifier>,
}

impl DropboxConnectorAdapter {
    fn new() -> Self {
        Self {
            connector: DropboxConnector::new(),
            id: ConnectorId::from_static("dropbox"),
            instance_id: InstanceId::new(),
            verifier: None,
        }
    }
}

fcp_core::impl_fcp_sealed!(DropboxConnectorAdapter);

#[fcp_core::async_trait]
impl FcpConnector for DropboxConnectorAdapter {
    fn id(&self) -> &ConnectorId {
        &self.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> fcp_core::FcpResult<()> {
        self.connector.handle_configure(config).await.map(|_| ())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> fcp_core::FcpResult<HandshakeResponse> {
        let connector_label = self.id.to_string();
        let session_id = SessionId::new();
        let mut request = serde_json::to_value(&req).map_err(|err| FcpError::Internal {
            message: format!("failed to serialize handshake request: {err}"),
        })?;
        let request_obj = request.as_object_mut().ok_or_else(|| FcpError::Internal {
            message: format!("{connector_label} handshake request did not serialize to an object"),
        })?;
        request_obj.insert(
            "session_id".to_string(),
            serde_json::Value::String(session_id.0.to_string()),
        );

        let response = self.connector.handle_handshake(request).await?;
        let protocol_version = response
            .get("protocol_version")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| FcpError::Internal {
                message: format!("{connector_label} handshake response missing protocol_version"),
            })?;
        if protocol_version != "2.0" {
            return Err(FcpError::Internal {
                message: format!(
                    "{connector_label} handshake protocol_version expected 2.0, got {protocol_version}"
                ),
            });
        }
        let _connector_id = response
            .get("connector_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| FcpError::Internal {
                message: format!("{connector_label} handshake response missing connector_id"),
            })?;
        let connector_caps: std::collections::BTreeSet<String> = response
            .get("capabilities")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| FcpError::Internal {
                message: format!("{connector_label} handshake response missing capabilities array"),
            })?
            .iter()
            .filter_map(|value| value.as_str().map(str::to_string))
            .collect();
        let capabilities_granted: Vec<CapabilityGrant> = req
            .capabilities_requested
            .iter()
            .filter(|capability| connector_caps.contains(capability.as_str()))
            .cloned()
            .map(|capability| CapabilityGrant {
                capability,
                operation: None,
            })
            .collect();

        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.instance_id.clone(),
        ));

        Ok(HandshakeResponse {
            status: "accepted".to_string(),
            capabilities_granted,
            session_id,
            manifest_hash: "sha256:dropbox-e2e".to_string(),
            nonce: req.nonce,
            event_caps: None,
            auth_caps: None,
            op_catalog_hash: None,
        })
    }

    async fn health(&self) -> HealthSnapshot {
        match self.connector.handle_health().await {
            Ok(payload) => {
                let status = payload
                    .get("status")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown");
                match status {
                    "healthy" => HealthSnapshot::ready(),
                    "degraded" => HealthSnapshot::degraded("not_handshaken"),
                    "unconfigured" => HealthSnapshot::degraded("not_configured"),
                    other => HealthSnapshot::degraded(format!("dropbox_status:{other}")),
                }
            }
            Err(err) => HealthSnapshot::error(err.to_string()),
        }
    }

    async fn self_check(&self) -> fcp_core::FcpResult<fcp_core::SelfCheckReport> {
        let value = self.connector.handle_self_check().await?;
        serde_json::from_value(value).map_err(|err| FcpError::Internal {
            message: format!("failed to deserialize Dropbox self_check: {err}"),
        })
    }

    fn metrics(&self) -> ConnectorMetrics {
        ConnectorMetrics::default()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> fcp_core::FcpResult<()> {
        self.verifier = None;
        self.connector.handle_shutdown(json!({})).await.map(|_| ())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: vec![OperationInfo {
                id: OperationId::from_static("dropbox.files.list"),
                summary: "dropbox.files.list".to_string(),
                description: None,
                input_schema: json!({"type": "object"}),
                output_schema: json!({"type": "object"}),
                capability: CapabilityId::from_static("dropbox.files.read"),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: String::new(),
                    common_mistakes: Vec::new(),
                    examples: Vec::new(),
                    related: Vec::new(),
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

    async fn invoke(&self, req: InvokeRequest) -> fcp_core::FcpResult<InvokeResponse> {
        let verifier = self.verifier.as_ref().ok_or(FcpError::Internal {
            message: "Dropbox verifier not initialized; handshake required".into(),
        })?;
        let required_capability = required_capability(req.operation.as_str())?;
        verifier.verify(
            &req.capability_token,
            &required_capability,
            &req.operation,
            &[],
        )?;

        let request_id = req.id.clone();
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
        let verifier = self.verifier.as_ref().ok_or(FcpError::Internal {
            message: "Dropbox verifier not initialized; handshake required".into(),
        })?;
        let required_capability = required_capability(req.operation.as_str())?;
        verifier.verify(
            &req.capability_token,
            &required_capability,
            &req.operation,
            &[],
        )?;

        let value = self
            .connector
            .handle_simulate(json!({
                "operation_id": req.operation.as_str(),
                "input": req.input,
            }))
            .await?;

        Ok(SimulateResponse {
            r#type: "simulate_response".to_string(),
            id: req.id,
            would_succeed: value
                .get("allowed")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            failure_reason: value
                .get("reason")
                .and_then(serde_json::Value::as_str)
                .filter(|_| {
                    !value
                        .get("allowed")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false)
                })
                .map(str::to_string),
            denial_code: None,
            missing_capabilities: Vec::new(),
            estimated_cost: None,
            availability: None,
            response_metadata: None,
        })
    }

    async fn subscribe(&self, _req: SubscribeRequest) -> fcp_core::FcpResult<SubscribeResponse> {
        Err(FcpError::StreamingNotSupported)
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> fcp_core::FcpResult<()> {
        Ok(())
    }
}

fn required_capability(operation: &str) -> fcp_core::FcpResult<CapabilityId> {
    let capability = match operation {
        "dropbox.files.list"
        | "dropbox.files.list_continue"
        | "dropbox.files.get_metadata"
        | "dropbox.files.search" => "dropbox.files.read",
        "dropbox.files.create_folder"
        | "dropbox.files.delete"
        | "dropbox.files.move"
        | "dropbox.files.copy" => "dropbox.files.write",
        "dropbox.account.get_space_usage" | "dropbox.account.get_current" => "dropbox.account.read",
        _ => {
            return Err(FcpError::InvalidRequest {
                code: 1002,
                message: format!("Unknown operation: {operation}"),
            });
        }
    };

    capability
        .parse::<CapabilityId>()
        .map_err(|err| FcpError::Internal {
            message: format!("invalid capability id mapping for {operation}: {err}"),
        })
}

fn dropbox_manifest_with_hash() -> String {
    let raw = include_str!("../../../connectors/dropbox/manifest.toml");
    let unchecked = ConnectorManifest::parse_str_unchecked(raw).expect("unchecked manifest parse");
    let computed = unchecked
        .compute_interface_hash()
        .expect("compute interface hash");
    raw.replace(
        &unchecked.manifest.interface_hash.to_string(),
        &computed.to_string(),
    )
}

fn dropbox_manifest_toml() -> toml::Value {
    toml::from_str(include_str!("../../../connectors/dropbox/manifest.toml"))
        .expect("Dropbox manifest TOML")
}

fn dropbox_config(base_url: &str) -> serde_json::Value {
    json!({
        "access_token": "dropbox-test-access-token",
        "base_url": base_url,
        "content_url": base_url,
    })
}

fn handshake_request(host_public_key: [u8; 32], capabilities: &[&str]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0".to_string(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [19_u8; 32],
        capabilities_requested: capabilities
            .iter()
            .map(|capability| {
                capability
                    .parse::<CapabilityId>()
                    .expect("capability id parse")
            })
            .collect(),
        host: None,
        transport_caps: None,
        requested_instance_id: Some(InstanceId::new()),
    }
}

fn build_token(
    signing_key: &Ed25519SigningKey,
    capability: &str,
    operations: &[&str],
) -> CapabilityToken {
    let now = Utc::now();
    let constraints = fcp_core::CapabilityConstraints {
        resource_allow: vec!["*".to_string()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor).expect("serialize test constraints");
    let token = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:test")
        .operations(operations)
        .issuer("node:test")
        .validity(now, now + ChronoDuration::hours(1))
        .constraints_cbor(&constraints_cbor)
        .sign(signing_key)
        .expect("capability token sign");
    CapabilityToken::from_raw(token)
}

fn invoke_request(
    operation: &'static str,
    input: serde_json::Value,
    token: CapabilityToken,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".to_string(),
        id: RequestId::from("dropbox-e2e"),
        connector_id: ConnectorId::from_static("dropbox"),
        operation: OperationId::from_static(operation),
        zone_id: ZoneId::work(),
        input,
        capability_token: token,
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

fn operation_network_constraints<'a>(
    manifest: &'a toml::Value,
    operation_name: &str,
) -> &'a toml::value::Table {
    manifest
        .get("provides")
        .and_then(toml::Value::as_table)
        .and_then(|provides| provides.get("operations"))
        .and_then(toml::Value::as_table)
        .and_then(|operations| operations.get(operation_name))
        .and_then(toml::Value::as_table)
        .and_then(|operation| operation.get("network_constraints"))
        .and_then(toml::Value::as_table)
        .expect("operation network_constraints")
}

fn operation_host_allow_list(manifest: &toml::Value, operation_name: &str) -> Vec<String> {
    operation_network_constraints(manifest, operation_name)
        .get("host_allow")
        .and_then(toml::Value::as_array)
        .map(|hosts| {
            hosts
                .iter()
                .filter_map(toml::Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .expect("operation host_allow")
}

fn host_allowed(host: &str, host_allow: &[String]) -> bool {
    fcp_sandbox::host_matches_allow_list(host, host_allow)
}

fn assert_report_logs_validate(report: &E2eReport) {
    let jsonl = report.to_stable_json_lines();
    assert!(
        !jsonl.trim().is_empty(),
        "report should emit stable JSONL evidence"
    );

    let first_line = jsonl.lines().next().expect("at least one JSONL line");
    let first_value: serde_json::Value =
        serde_json::from_str(first_line).expect("first JSONL line should parse");
    assert_eq!(
        first_value
            .get("timestamp")
            .and_then(serde_json::Value::as_str),
        Some("1970-01-01T00:00:00Z")
    );
    assert_eq!(
        first_value
            .get("correlation_id")
            .and_then(serde_json::Value::as_str),
        Some("00000000-0000-4000-8000-000000000000")
    );
    assert_eq!(
        first_value
            .get("duration_ms")
            .and_then(serde_json::Value::as_u64),
        Some(0)
    );

    for line in jsonl.lines() {
        let value: serde_json::Value = serde_json::from_str(line).expect("jsonl line should parse");
        validate_log_entry_value(&value).expect("jsonl line should satisfy E2E schema");
    }

    let scan = scan_log_jsonl(&jsonl);
    assert_eq!(scan.error_count, 0, "stable evidence should scan cleanly");
}

#[fcp_async_core::runtime::test]
async fn dropbox_default_deny_compliance_suite_passes() {
    let mock = MockApiServer::start().await;

    let mut connector = DropboxConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(
        signing_key.verifying_key().to_bytes(),
        &["dropbox.files.read"],
    );
    let token = build_token(&signing_key, "dropbox.files.read", &["dropbox.files.list"]);
    let invoke = invoke_request(
        "dropbox.files.get_metadata",
        json!({ "path": "/Documents/report.pdf" }),
        token,
    );

    let dynamic = DynamicSuite {
        config: dropbox_config(&mock.base_url()),
        handshake,
        invoke: Some(invoke),
        expect_invoke_error: true,
        simulate: None,
        expect_simulate_would_succeed: None,
        require_simulate_denial_details: false,
        require_capability_denial: true,
        require_decision_receipt: false,
    };
    let suite = ComplianceSuite::new(
        "dropbox_default_deny",
        dropbox_manifest_with_hash(),
        dynamic,
    );

    let mut runner = E2eRunner::new("fcp-e2e-dropbox");
    let report = runner
        .run_compliance_suite(&mut connector, suite)
        .await
        .expect("compliance suite run");

    assert!(
        report.passed,
        "default deny compliance should pass: {report:#?}"
    );
    assert_report_logs_validate(&report);
}

#[fcp_async_core::runtime::test]
async fn dropbox_allow_valid_token_connector_suite_passes() {
    let mock = MockApiServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"^/files/list_folder.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "entries": [{"name": "report.pdf", ".tag": "file"}],
            "cursor": "abc",
            "has_more": false
        })))
        .mount(mock.inner())
        .await;

    let mut connector = DropboxConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(
        signing_key.verifying_key().to_bytes(),
        &["dropbox.files.read"],
    );
    let token = build_token(&signing_key, "dropbox.files.read", &["dropbox.files.list"]);
    let invoke = invoke_request("dropbox.files.list", json!({ "path": "/Documents" }), token);

    let suite = ConnectorSuite {
        test_name: "dropbox_allow_valid_token".to_string(),
        config: dropbox_config(&mock.base_url()),
        handshake,
        invoke: Some(invoke),
        invoke_expectations: InvokeExpectations {
            expect_error: false,
            expect_decision_receipt: false,
            expect_audit_event: false,
            expect_receipt: false,
            expected_reason_code: None,
            rate_limit_pool: None,
        },
    };

    let mut runner = E2eRunner::new("fcp-e2e-dropbox-happy");
    let report = runner
        .run_connector_suite(&mut connector, suite)
        .await
        .expect("connector suite run");

    assert!(report.passed, "allow valid token should pass: {report:#?}");
    let invoke_entry = report
        .logs
        .iter()
        .find(|e| e.context.get("operation") == Some(&json!("invoke")))
        .expect("invoke log entry");
    assert_eq!(
        invoke_entry.result, "pass",
        "invoke should pass: {invoke_entry:#?}"
    );
    assert_eq!(
        invoke_entry.context.get("invoke_status"),
        Some(&json!(format!("{:?}", InvokeStatus::Ok)))
    );
    let received = mock.received_requests().await;
    let hits = received
        .iter()
        .filter(|request| request.url.path() == "/files/list_folder")
        .count();
    assert_eq!(hits, 1, "expected exactly one POST to /files/list_folder");
    assert_report_logs_validate(&report);
}

#[test]
fn dropbox_manifest_network_guard_allows_and_denies() {
    let manifest = dropbox_manifest_toml();
    let operations = manifest
        .get("provides")
        .and_then(toml::Value::as_table)
        .and_then(|provides| provides.get("operations"))
        .and_then(toml::Value::as_table)
        .expect("operations table");

    assert_eq!(
        operations.len(),
        4,
        "Dropbox manifest should declare 4 operations"
    );

    let expected_hosts = vec![
        "api.dropboxapi.com".to_string(),
        "content.dropboxapi.com".to_string(),
    ];

    for operation_name in operations.keys() {
        let host_allow = operation_host_allow_list(&manifest, operation_name);
        assert_eq!(
            host_allow, expected_hosts,
            "operation {operation_name} should use exact Dropbox API host allowlist"
        );

        assert!(host_allowed("api.dropboxapi.com", &host_allow));
        assert!(host_allowed("content.dropboxapi.com", &host_allow));
        assert!(!host_allowed("dropboxapi.com", &host_allow));
        assert!(!host_allowed("evil.api.dropboxapi.com", &host_allow));
        assert!(!host_allowed("example.com", &host_allow));
        assert!(!host_allowed("127.0.0.1", &host_allow));

        let constraints = operation_network_constraints(&manifest, operation_name);
        assert_eq!(
            constraints
                .get("deny_localhost")
                .and_then(toml::Value::as_bool),
            Some(true),
            "operation {operation_name} must deny localhost"
        );
        assert_eq!(
            constraints
                .get("deny_private_ranges")
                .and_then(toml::Value::as_bool),
            Some(true),
            "operation {operation_name} must deny private ranges"
        );
        assert_eq!(
            constraints
                .get("require_sni")
                .and_then(toml::Value::as_bool),
            Some(true),
            "operation {operation_name} must require SNI"
        );
    }
}
