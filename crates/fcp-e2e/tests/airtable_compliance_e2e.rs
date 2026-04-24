//! E2E Airtable connector compliance tests (flywheel_connectors-soft.4).
//!
//! Exercises the Airtable connector through the E2E compliance harness:
//! - Default deny (missing capability -> error)
//! - Allow with valid token (happy path invoke via mock API)
//! - Network guard allow/deny (manifest `host_allow` validation)
//! - Dangerous action gating (risk level verification)
//!
//! All tests are deterministic -- no real API calls.
//! Run: `cargo test --package fcp-e2e --features airtable`

#![cfg(feature = "airtable")]
#![allow(clippy::too_many_lines)]

use chrono::{Duration as ChronoDuration, Utc};
use fcp_async_core::sync::Mutex;
use fcp_conformance::DynamicSuite;
use fcp_core::{
    AgentHint, CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId,
    ConnectorMetrics, FcpConnector, FcpError, HandshakeRequest, HandshakeResponse,
    HealthSnapshot, IdempotencyClass, InstanceId, Introspection, InvokeRequest, InvokeResponse,
    InvokeStatus, OperationId, OperationInfo, RequestId, RiskLevel, SafetyTier, ShutdownRequest,
    SimulateRequest, SimulateResponse, SubscribeRequest, SubscribeResponse, UnsubscribeRequest,
    ZoneId,
};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_e2e::{ComplianceSuite, ConnectorSuite, E2eRunner, InvokeExpectations};
use fcp_manifest::ConnectorManifest;
use fcp_testkit::MockApiServer;
use serde_json::json;
use wiremock::{
    Mock, ResponseTemplate,
    matchers::{method, path},
};

use fcp_airtable::connector::AirtableConnector;

// ============================================================================
// FcpConnector adapter for AirtableConnector
// ============================================================================

struct AirtableConnectorAdapter {
    connector: Mutex<AirtableConnector>,
    id: ConnectorId,
}

impl AirtableConnectorAdapter {
    fn new() -> Self {
        Self {
            connector: Mutex::new(AirtableConnector::new()),
            id: ConnectorId::from_static("airtable"),
        }
    }
}

fcp_core::impl_fcp_sealed!(AirtableConnectorAdapter);

#[fcp_core::async_trait]
impl FcpConnector for AirtableConnectorAdapter {
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
        let request = serde_json::to_value(req).map_err(|err| FcpError::Internal {
            message: format!("failed to serialize handshake request: {err}"),
        })?;
        let response = self.connector.lock().await.handle_handshake(request).await?;
        serde_json::from_value(response).map_err(|err| FcpError::Internal {
            message: format!("failed to deserialize handshake response: {err}"),
        })
    }

    async fn health(&self) -> HealthSnapshot {
        match self.connector.lock().await.handle_health().await {
            Ok(payload) => {
                let status = payload
                    .get("status")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown");
                match status {
                    "healthy" => HealthSnapshot::ready(),
                    "not_configured" => HealthSnapshot::degraded("not_configured"),
                    other => HealthSnapshot::degraded(format!("airtable_status:{other}")),
                }
            }
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
                id: OperationId::from_static("airtable.list_bases"),
                summary: "List accessible Airtable bases".to_string(),
                description: None,
                input_schema: json!({
                    "type": "object",
                    "required": [],
                    "properties": {
                        "offset": { "type": "string" }
                    }
                }),
                output_schema: json!({
                    "type": "object",
                    "required": ["bases"],
                    "properties": {
                        "bases": { "type": "array" }
                    }
                }),
                capability: CapabilityId::from_static("airtable.read"),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "List Airtable bases.".to_string(),
                    common_mistakes: Vec::new(),
                    examples: vec!["{}".to_string()],
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

        let value = std::thread::scope(|scope| {
            scope
                .spawn(move || {
                    fcp_async_core::runtime::block_on_sync(async {
                        self.connector.lock().await.handle_invoke(params).await
                    })
                })
                .join()
                .map_err(|_| FcpError::Internal {
                    message: "airtable invoke helper thread panicked".to_string(),
                })?
                .map_err(|err| FcpError::Internal {
                    message: format!("failed to run airtable invoke helper runtime: {err}"),
                })?
        })?;

        Ok(InvokeResponse::ok(request_id, value))
    }

    async fn simulate(&self, req: SimulateRequest) -> fcp_core::FcpResult<SimulateResponse> {
        let request = serde_json::to_value(req).map_err(|err| FcpError::Internal {
            message: format!("failed to serialize simulate request: {err}"),
        })?;
        let value = self.connector.lock().await.handle_simulate(request).await?;
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

// ============================================================================
// Helpers
// ============================================================================

fn reference_manifest_with_hash() -> String {
    let raw = include_str!("../../../tests/vectors/manifest/manifest_valid.toml");
    let unchecked = ConnectorManifest::parse_str_unchecked(raw).expect("unchecked manifest parse");
    let computed = unchecked
        .compute_interface_hash()
        .expect("compute interface hash");
    raw.replace(
        &unchecked.manifest.interface_hash.to_string(),
        &computed.to_string(),
    )
}

fn handshake_request(host_public_key: [u8; 32], capabilities: &[&str]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0".to_string(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [9u8; 32],
        capabilities_requested: capabilities
            .iter()
            .map(|cap| cap.parse::<CapabilityId>().expect("capability id parse"))
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
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".to_string()],
        ..CapabilityConstraints::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor)
        .expect("serialize airtable test constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:test")
        .operations(operations)
        .issuer("node:test")
        .validity(now, now + ChronoDuration::hours(1))
        .constraints_cbor(&constraints_cbor)
        .sign(signing_key)
        .expect("capability token sign");
    CapabilityToken::from_raw(cose)
}

fn invoke_request(
    operation: &'static str,
    input: serde_json::Value,
    token: CapabilityToken,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".to_string(),
        id: RequestId::from("airtable-e2e"),
        connector_id: ConnectorId::from_static("airtable"),
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

fn airtable_config(base_url: &str) -> serde_json::Value {
    json!({
        "token": "patFAKETOKEN123.abc",
        "base_url": base_url,
    })
}

fn airtable_manifest_toml() -> toml::Value {
    toml::from_str(include_str!("../../../connectors/airtable/manifest.toml"))
        .expect("airtable manifest toml")
}

fn operation_host_allow_list(manifest: &toml::Value, operation_name: &str) -> Vec<String> {
    manifest
        .get("provides")
        .and_then(toml::Value::as_table)
        .and_then(|provides| provides.get("operations"))
        .and_then(toml::Value::as_table)
        .and_then(|operations| operations.get(operation_name))
        .and_then(toml::Value::as_table)
        .and_then(|operation| operation.get("network_constraints"))
        .and_then(toml::Value::as_table)
        .and_then(|constraints| constraints.get("host_allow"))
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

// ============================================================================
// Test 1: Default deny -- compliance suite
// ============================================================================

/// Default deny: invoke without matching capability triggers error.
/// Token grants "airtable.delete" but invoke targets "airtable.list_bases"
/// (which requires "airtable.read").
#[fcp_async_core::runtime::test]
async fn airtable_default_deny_compliance_suite_passes() {
    let mut connector = AirtableConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(signing_key.verifying_key().to_bytes(), &["airtable.delete"]);
    let token = build_token(&signing_key, "airtable.delete", &["airtable.delete"]);
    let invoke = invoke_request("airtable.list_bases", json!({}), token);

    let dynamic = DynamicSuite {
        config: json!({
            "token": "patFAKETOKEN123.abc",
            "base_url": "http://localhost:9999",
        }),
        handshake: handshake.clone(),
        invoke: Some(invoke),
        expect_invoke_error: true,
        simulate: None,
        expect_simulate_would_succeed: None,
        require_simulate_denial_details: false,
        require_capability_denial: true,
        require_decision_receipt: false,
    };
    let suite = ComplianceSuite::new(
        "airtable_default_deny",
        reference_manifest_with_hash(),
        dynamic,
    );

    let mut runner = E2eRunner::new("fcp-e2e-airtable");
    let report = runner
        .run_compliance_suite(&mut connector, suite)
        .await
        .expect("compliance suite run");

    assert!(report.passed, "default deny compliance should pass");
}

// ============================================================================
// Test 2: Allow with valid token -- connector suite
// ============================================================================

/// Allow: invoke with valid capability token succeeds against mock API.
#[fcp_async_core::runtime::test]
async fn airtable_allow_valid_token_connector_suite_passes() {
    let mock = MockApiServer::start().await;

    Mock::given(method("GET"))
        .and(path("/meta/bases"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "bases": [
                {
                    "id": "appABC123",
                    "name": "Project Tracker",
                    "permissionLevel": "create"
                }
            ]
        })))
        .mount(mock.inner())
        .await;

    let mut connector = AirtableConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(signing_key.verifying_key().to_bytes(), &["airtable.read"]);
    let token = build_token(&signing_key, "airtable.read", &["airtable.list_bases"]);
    let invoke = invoke_request("airtable.list_bases", json!({}), token);
    let suite = ConnectorSuite {
        test_name: "airtable_allow_valid_token".to_string(),
        config: airtable_config(&mock.base_url()),
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

    let mut runner = E2eRunner::new("fcp-e2e-airtable");
    let report = runner
        .run_connector_suite(&mut connector, suite)
        .await
        .expect("connector suite run");

    assert!(report.passed, "allow suite should pass: {report:#?}");
    let invoke_entry = report
        .logs
        .iter()
        .find(|entry| entry.context.get("operation") == Some(&json!("invoke")))
        .expect("invoke entry");
    assert_eq!(invoke_entry.result, "pass");
    assert_eq!(
        invoke_entry.context.get("invoke_status"),
        Some(&json!(format!("{:?}", InvokeStatus::Ok)))
    );
    let received = mock.received_requests().await;
    let hits = received
        .iter()
        .filter(|request| request.url.path() == "/meta/bases")
        .count();
    assert_eq!(hits, 1, "expected exactly one GET to /meta/bases");
}

// ============================================================================
// Test 3: Network guard -- manifest host_allow validation
// ============================================================================

/// Network guard: Airtable manifest restricts most operations to `api.airtable.com`
/// and attachment downloads to `dl.airtable.com` + CDN hosts.
#[test]
fn airtable_manifest_network_guard_allows_and_denies() {
    let manifest = airtable_manifest_toml();

    // Operations that only allow api.airtable.com
    let api_only_ops = [
        "create_record",
        "create_records",
        "delete_record",
        "get_base_schema",
        "get_record",
        "list_bases",
        "list_records",
        "replace_record",
        "update_record",
    ];

    for operation_name in api_only_ops {
        let host_allow = operation_host_allow_list(&manifest, operation_name);
        assert_eq!(
            host_allow,
            vec!["api.airtable.com".to_string()],
            "operation {operation_name} should allow only api.airtable.com"
        );

        assert!(
            host_allowed("api.airtable.com", &host_allow),
            "api.airtable.com should be allowed for {operation_name}"
        );
        assert!(
            !host_allowed("airtable.com", &host_allow),
            "airtable.com (bare domain) should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("evil.api.airtable.com", &host_allow),
            "evil.api.airtable.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("example.com", &host_allow),
            "example.com should be denied for {operation_name}"
        );
    }

    // download_attachment allows CDN hosts
    let download_allow = operation_host_allow_list(&manifest, "download_attachment");
    let expected_download_hosts = vec![
        "dl.airtable.com".to_string(),
        "*.dl.airtable.com".to_string(),
        "v5.airtableusercontent.com".to_string(),
    ];
    assert_eq!(
        download_allow, expected_download_hosts,
        "download_attachment should allow dl.airtable.com + CDN hosts"
    );

    // Wildcard should match subdomains
    assert!(
        host_allowed("cdn.dl.airtable.com", &download_allow),
        "cdn.dl.airtable.com should be allowed by *.dl.airtable.com"
    );
    assert!(
        host_allowed("v5.airtableusercontent.com", &download_allow),
        "v5.airtableusercontent.com should be allowed"
    );
    assert!(
        !host_allowed("api.airtable.com", &download_allow),
        "api.airtable.com should NOT be allowed for downloads"
    );
    assert!(
        !host_allowed("evil.airtableusercontent.com", &download_allow),
        "evil.airtableusercontent.com should be denied"
    );
}

// ============================================================================
// Test 4: Dangerous action gating -- risk level verification
// ============================================================================

/// Dangerous operations (delete_record, replace_record) should have high risk
/// and dangerous safety tier. Write operations should be medium/risky.
#[test]
fn airtable_operation_risk_levels_properly_gated() {
    let manifest = airtable_manifest_toml();
    let operations = manifest
        .get("provides")
        .and_then(toml::Value::as_table)
        .and_then(|p| p.get("operations"))
        .and_then(toml::Value::as_table)
        .expect("operations table");

    // Dangerous operations: high risk + dangerous + interactive approval
    let dangerous_ops = ["delete_record", "replace_record"];
    for op_name in dangerous_ops {
        let op = operations.get(op_name).unwrap_or_else(|| {
            panic!("operation {op_name} should exist in manifest");
        });
        let risk = op.get("risk_level").and_then(toml::Value::as_str).unwrap();
        let safety = op.get("safety_tier").and_then(toml::Value::as_str).unwrap();
        let approval = op
            .get("requires_approval")
            .and_then(toml::Value::as_str)
            .unwrap();

        assert_eq!(risk, "high", "{op_name} should be high risk, got {risk}");
        assert_eq!(
            safety, "dangerous",
            "{op_name} should be dangerous, got {safety}"
        );
        assert_eq!(
            approval, "interactive",
            "{op_name} should require interactive approval, got {approval}"
        );
    }

    // Write operations: medium risk + risky + policy approval
    let write_ops = ["create_record", "create_records", "update_record"];
    for op_name in write_ops {
        let op = operations.get(op_name).unwrap_or_else(|| {
            panic!("operation {op_name} should exist in manifest");
        });
        let risk = op.get("risk_level").and_then(toml::Value::as_str).unwrap();
        let safety = op.get("safety_tier").and_then(toml::Value::as_str).unwrap();
        let approval = op
            .get("requires_approval")
            .and_then(toml::Value::as_str)
            .unwrap();

        assert_eq!(
            risk, "medium",
            "{op_name} should be medium risk, got {risk}"
        );
        assert_eq!(safety, "risky", "{op_name} should be risky, got {safety}");
        assert_eq!(
            approval, "policy",
            "{op_name} should require policy approval, got {approval}"
        );
    }

    // Read operations: low risk + safe + no approval
    let read_ops = [
        "list_bases",
        "list_records",
        "get_record",
        "get_base_schema",
        "download_attachment",
        "list_tables",
        "get_table",
        "list_fields",
    ];
    for op_name in read_ops {
        let op = operations.get(op_name).unwrap_or_else(|| {
            panic!("operation {op_name} should exist in manifest");
        });
        let risk = op.get("risk_level").and_then(toml::Value::as_str).unwrap();
        let safety = op.get("safety_tier").and_then(toml::Value::as_str).unwrap();
        let approval = op
            .get("requires_approval")
            .and_then(toml::Value::as_str)
            .unwrap();

        assert_eq!(risk, "low", "{op_name} should be low risk, got {risk}");
        assert_eq!(safety, "safe", "{op_name} should be safe, got {safety}");
        assert_eq!(
            approval, "none",
            "{op_name} should need no approval, got {approval}"
        );
    }

    // Total operation count
    assert_eq!(
        operations.len(),
        25,
        "Airtable manifest should expose the current 25-operation surface"
    );
}
