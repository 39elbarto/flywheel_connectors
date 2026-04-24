//! E2E Snowflake connector compliance tests.
//!
//! Exercises the Snowflake connector through the shared E2E harness:
//! - Default deny behavior for capability mismatch
//! - Allow path with valid capability token
//! - Network guard allow/deny checks via manifest constraints
//!
//! All tests are deterministic with mock servers only.
//! Run: `cargo test --package fcp-e2e --features snowflake`

#![cfg(feature = "snowflake")]
#![allow(clippy::too_many_lines)]

use chrono::{Duration as ChronoDuration, Utc};
use fcp_conformance::DynamicSuite;
use fcp_core::InvokeStatus;
use fcp_core::{
    CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier, ConnectorId,
    ConnectorMetrics, FcpConnector, FcpError, HandshakeRequest, HandshakeResponse, HealthSnapshot,
    InstanceId, Introspection, InvokeRequest, InvokeResponse, ObjectId, OperationId, RequestId,
    SessionId, ShutdownRequest, SimulateRequest, SimulateResponse, SubscribeRequest,
    SubscribeResponse, UnsubscribeRequest, ZoneId,
};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_e2e::{
    ComplianceSuite, ConnectorSuite, E2eReport, E2eRunner, InvokeExpectations, scan_log_jsonl,
    validate_log_entry_value,
};
use fcp_manifest::ConnectorManifest;
use fcp_snowflake::connector::SnowflakeConnector;
use fcp_testkit::MockApiServer;
use serde_json::json;
use wiremock::{
    Mock, ResponseTemplate,
    matchers::{method, path_regex},
};

struct SnowflakeConnectorAdapter {
    connector: SnowflakeConnector,
    id: ConnectorId,
    instance_id: InstanceId,
    verifier: Option<CapabilityVerifier>,
}

impl SnowflakeConnectorAdapter {
    fn new() -> Self {
        Self {
            connector: SnowflakeConnector::new(),
            id: ConnectorId::from_static("snowflake"),
            instance_id: InstanceId::new(),
            verifier: None,
        }
    }
}

fcp_core::impl_fcp_sealed!(SnowflakeConnectorAdapter);

#[fcp_core::async_trait]
impl FcpConnector for SnowflakeConnectorAdapter {
    fn id(&self) -> &ConnectorId {
        &self.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> fcp_core::FcpResult<()> {
        self.connector.handle_configure(config).await.map(|_| ())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> fcp_core::FcpResult<HandshakeResponse> {
        let session_id = SessionId::new();
        let mut params = serde_json::to_value(&req).map_err(|err| FcpError::Internal {
            message: format!("failed to serialize handshake request: {err}"),
        })?;
        if let Some(obj) = params.as_object_mut() {
            obj.insert(
                "session_id".to_string(),
                serde_json::Value::String(session_id.0.to_string()),
            );
        }

        let response = self.connector.handle_handshake(params).await?;
        let protocol_version = response
            .get("protocol_version")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| FcpError::Internal {
                message: "snowflake handshake response missing protocol_version".into(),
            })?;
        if protocol_version != "2.0" {
            return Err(FcpError::Internal {
                message: format!(
                    "snowflake handshake protocol_version expected 2.0, got {protocol_version}"
                ),
            });
        }
        let _connector_id = response
            .get("connector_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| FcpError::Internal {
                message: "snowflake handshake response missing connector_id".into(),
            })?;
        let connector_caps: std::collections::BTreeSet<String> = response
            .get("capabilities")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| FcpError::Internal {
                message: "snowflake handshake response missing capabilities array".into(),
            })?
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
        let capabilities_granted: Vec<CapabilityGrant> = req
            .capabilities_requested
            .iter()
            .filter(|cap| connector_caps.contains(cap.as_str()))
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
            manifest_hash: "sha256:snowflake-e2e".to_string(),
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
                    other => HealthSnapshot::degraded(format!("snowflake_status:{other}")),
                }
            }
            Err(err) => HealthSnapshot::error(err.to_string()),
        }
    }

    async fn self_check(&self) -> fcp_core::FcpResult<fcp_core::SelfCheckReport> {
        let value = self.connector.handle_self_check().await?;
        serde_json::from_value(value).map_err(|err| FcpError::Internal {
            message: format!("failed to deserialize Snowflake self_check: {err}"),
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
        SnowflakeConnector::introspection()
    }

    async fn invoke(&self, req: InvokeRequest) -> fcp_core::FcpResult<InvokeResponse> {
        let verifier = self.verifier.as_ref().ok_or(FcpError::Internal {
            message: "Snowflake verifier not initialized; handshake required".into(),
        })?;
        let required_capability = required_capability(req.operation.as_str())?;
        let request_id = req.id.clone();
        if let Err(err) = verifier.verify(
            req.capability_token.clone(),
            &required_capability,
            &req.operation,
            &[],
        ) {
            let decision_label = format!("{}.decision", req.operation.as_str());
            return Ok(InvokeResponse::error(request_id, err)
                .with_decision_receipt_id(stable_object_id(&decision_label)));
        }
        let value = self
            .connector
            .handle_invoke(json!({
                "operation_id": req.operation.as_str(),
                "input": req.input,
            }))
            .await?;
        let mut response = InvokeResponse::ok(request_id, value);
        if req.operation.as_str() == "snowflake.sql.execute" {
            response = response
                .with_receipt_id(stable_object_id("snowflake.sql.execute.receipt"))
                .with_audit_event_id(stable_object_id("snowflake.sql.execute.audit"));
        }
        Ok(response)
    }

    async fn simulate(&self, req: SimulateRequest) -> fcp_core::FcpResult<SimulateResponse> {
        let verifier = self.verifier.as_ref().ok_or(FcpError::Internal {
            message: "Snowflake verifier not initialized; handshake required".into(),
        })?;
        let required_capability = required_capability(req.operation.as_str())?;
        verifier.verify(
            req.capability_token.clone(),
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
        "snowflake.databases.list" | "snowflake.tables.list" => "snowflake.databases.read",
        "snowflake.warehouses.list" => "snowflake.warehouses.read",
        "snowflake.sql.query" => "snowflake.sql.read",
        "snowflake.sql.execute" => "snowflake.sql.write",
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

fn snowflake_manifest_with_hash() -> String {
    let raw = include_str!("../../../connectors/snowflake/manifest.toml");
    let unchecked = ConnectorManifest::parse_str_unchecked(raw).expect("unchecked manifest parse");
    let computed = unchecked
        .compute_interface_hash()
        .expect("compute interface hash");
    raw.replace(
        &unchecked.manifest.interface_hash.to_string(),
        &computed.to_string(),
    )
}

fn snowflake_manifest_toml() -> toml::Value {
    toml::from_str(include_str!("../../../connectors/snowflake/manifest.toml"))
        .expect("Snowflake manifest TOML")
}

fn snowflake_config(base_url: &str) -> serde_json::Value {
    json!({
        "access_token": "snowflake-test-access-token",
        "account_identifier": "testaccount",
        "base_url": base_url,
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
    ciborium::into_writer(&constraints, &mut constraints_cbor)
        .expect("serialize test constraints");
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
        id: RequestId::from("snowflake-e2e"),
        connector_id: ConnectorId::from_static("snowflake"),
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

fn stable_object_id(label: &str) -> ObjectId {
    ObjectId::from_unscoped_bytes(label.as_bytes())
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
async fn snowflake_default_deny_compliance_suite_passes() {
    let mock = MockApiServer::start().await;

    let mut connector = SnowflakeConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(
        signing_key.verifying_key().to_bytes(),
        &["snowflake.databases.read"],
    );
    let token = build_token(
        &signing_key,
        "snowflake.databases.read",
        &["snowflake.databases.list"],
    );
    let invoke = invoke_request(
        "snowflake.sql.execute",
        json!({ "statement": "DROP TABLE test" }),
        token,
    );

    let dynamic = DynamicSuite {
        config: snowflake_config(&mock.base_url()),
        handshake,
        invoke: Some(invoke),
        expect_invoke_error: true,
        simulate: None,
        expect_simulate_would_succeed: None,
        require_simulate_denial_details: false,
        require_capability_denial: true,
        require_decision_receipt: true,
    };
    let suite = ComplianceSuite::new(
        "snowflake_default_deny",
        snowflake_manifest_with_hash(),
        dynamic,
    );

    let mut runner = E2eRunner::new("fcp-e2e-snowflake");
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
async fn snowflake_allow_valid_token_connector_suite_passes() {
    let mock = MockApiServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex(r"^/databases.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"name": "ANALYTICS", "kind": "STANDARD"},
            {"name": "RAW", "kind": "STANDARD"}
        ])))
        .mount(mock.inner())
        .await;

    let mut connector = SnowflakeConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(
        signing_key.verifying_key().to_bytes(),
        &["snowflake.databases.read"],
    );
    let token = build_token(
        &signing_key,
        "snowflake.databases.read",
        &["snowflake.databases.list"],
    );
    let invoke = invoke_request("snowflake.databases.list", json!({}), token);
    let suite = ConnectorSuite {
        test_name: "snowflake_allow_valid_token".to_string(),
        config: snowflake_config(&mock.base_url()),
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

    let mut runner = E2eRunner::new("fcp-e2e-snowflake");
    let report = runner
        .run_connector_suite(&mut connector, suite)
        .await
        .expect("connector suite run");

    assert!(report.passed, "allow suite should pass: {report:#?}");
    assert_report_logs_validate(&report);
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
    let hits = received.iter().filter(|r| r.url.path() == "/databases").count();
    assert_eq!(hits, 1, "expected exactly one GET to /databases");
}

#[fcp_async_core::runtime::test]
async fn snowflake_dangerous_execute_emits_receipt_audit_and_stable_evidence() {
    let mock = MockApiServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"^/statements.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "message": "Statement executed",
            "statementHandle": "stmt_123",
        })))
        .mount(mock.inner())
        .await;

    let mut connector = SnowflakeConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(
        signing_key.verifying_key().to_bytes(),
        &["snowflake.sql.write"],
    );
    let token = build_token(
        &signing_key,
        "snowflake.sql.write",
        &["snowflake.sql.execute"],
    );
    let invoke = invoke_request(
        "snowflake.sql.execute",
        json!({
            "statement": "CREATE TABLE test_table (id INT)",
            "database": "DEV",
            "warehouse": "COMPUTE_WH",
        }),
        token,
    );

    let suite = ConnectorSuite {
        test_name: "snowflake_sql_execute_receipts".to_string(),
        config: snowflake_config(&mock.base_url()),
        handshake,
        invoke: Some(invoke),
        invoke_expectations: InvokeExpectations {
            expect_error: false,
            expect_decision_receipt: false,
            expect_audit_event: true,
            expect_receipt: true,
            expected_reason_code: None,
            rate_limit_pool: None,
        },
    };

    let mut runner = E2eRunner::new("fcp-e2e-snowflake-dangerous");
    let report = runner
        .run_connector_suite(&mut connector, suite)
        .await
        .expect("connector suite run");

    assert!(
        report.passed,
        "dangerous execute compliance should pass: {report:#?}"
    );
    assert_report_logs_validate(&report);

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
    assert_eq!(
        invoke_entry.context.get("audit_event_id"),
        Some(&json!(
            stable_object_id("snowflake.sql.execute.audit").to_string()
        ))
    );
    assert_eq!(
        invoke_entry.context.get("receipt_id"),
        Some(&json!(
            stable_object_id("snowflake.sql.execute.receipt").to_string()
        ))
    );
    let received = mock.received_requests().await;
    let hits = received.iter().filter(|r| r.url.path() == "/statements").count();
    assert_eq!(hits, 1, "expected exactly one POST to /statements");
}

#[test]
fn snowflake_manifest_network_guard_allows_and_denies() {
    let manifest = snowflake_manifest_toml();
    let operations = manifest
        .get("provides")
        .and_then(toml::Value::as_table)
        .and_then(|provides| provides.get("operations"))
        .and_then(toml::Value::as_table)
        .expect("operations table");

    assert_eq!(
        operations.len(),
        5,
        "Snowflake manifest should declare 5 operations"
    );

    let expected_hosts = vec!["*.snowflakecomputing.com".to_string()];

    for operation_name in operations.keys() {
        let host_allow = operation_host_allow_list(&manifest, operation_name);
        assert_eq!(
            host_allow, expected_hosts,
            "operation {operation_name} should use exact Snowflake API host allowlist"
        );

        assert!(host_allowed(
            "myaccount.snowflakecomputing.com",
            &host_allow
        ));
        assert!(host_allowed(
            "myaccount.us-east-1.snowflakecomputing.com",
            &host_allow
        ));
        assert!(!host_allowed("snowflakecomputing.com", &host_allow));
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
