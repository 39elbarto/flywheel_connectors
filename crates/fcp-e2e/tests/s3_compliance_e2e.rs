//! E2E S3 connector compliance tests.
//!
//! Exercises the S3 connector through the E2E compliance harness:
//! - Default deny (missing capability -> error + decision receipt)
//! - Allow with valid token (happy path invoke via mock REST API)
//! - Network guard allow/deny (manifest `host_allow` wildcard validation)
//!
//! All tests are deterministic -- no real API calls.
//! Run: `cargo test --package fcp-e2e --features s3`

#![cfg(feature = "s3")]
#![allow(clippy::too_many_lines)]

use chrono::{Duration as ChronoDuration, Utc};
use fcp_async_core::sync::Mutex;
use fcp_conformance::DynamicSuite;
use fcp_core::{
    AgentHint, CapabilityId, CapabilityToken, ConnectorId, ConnectorMetrics, FcpConnector,
    FcpError, HandshakeRequest, HandshakeResponse, HealthSnapshot, IdempotencyClass, InstanceId,
    Introspection, InvokeRequest, InvokeResponse, InvokeStatus, OperationId, OperationInfo,
    RequestId, RiskLevel, SafetyTier, SelfCheckReport, ShutdownRequest, SimulateRequest,
    SimulateResponse, SubscribeRequest, SubscribeResponse, UnsubscribeRequest, ZoneId,
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

use fcp_s3::connector::S3Connector;

// ============================================================================
// FcpConnector adapter for S3Connector
// ============================================================================

struct S3ConnectorAdapter {
    connector: Mutex<S3Connector>,
    id: ConnectorId,
}

impl S3ConnectorAdapter {
    fn new() -> Self {
        Self {
            connector: Mutex::new(S3Connector::new()),
            id: ConnectorId::from_static("s3"),
        }
    }
}

fcp_core::impl_fcp_sealed!(S3ConnectorAdapter);

#[fcp_core::async_trait]
impl FcpConnector for S3ConnectorAdapter {
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
        let response = self
            .connector
            .lock()
            .await
            .handle_handshake(request)
            .await?;
        serde_json::from_value(response).map_err(|err| FcpError::Internal {
            message: format!("failed to deserialize handshake response: {err}"),
        })
    }

    async fn health(&self) -> HealthSnapshot {
        match self.connector.lock().await.handle_health().await {
            Ok(val) => {
                let status = val
                    .get("status")
                    .and_then(|s| s.as_str())
                    .unwrap_or("unknown");
                if status == "healthy" {
                    HealthSnapshot::ready()
                } else {
                    HealthSnapshot::degraded("not_healthy")
                }
            }
            Err(_) => HealthSnapshot::degraded("error"),
        }
    }

    async fn self_check(&self) -> fcp_core::FcpResult<SelfCheckReport> {
        let value = self.connector.lock().await.handle_self_check().await?;
        serde_json::from_value(value).map_err(|e| FcpError::Internal {
            message: format!("Failed to parse self_check result: {e}"),
        })
    }

    fn metrics(&self) -> ConnectorMetrics {
        ConnectorMetrics::default()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> fcp_core::FcpResult<()> {
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: vec![OperationInfo {
                id: OperationId::from_static("s3.get_object"),
                summary: "s3.get_object".to_string(),
                description: None,
                input_schema: json!({"type": "object"}),
                output_schema: json!({"type": "object"}),
                capability: CapabilityId::from_static("s3.get_object"),
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
        let request_id = req.id.clone();
        let params = json!({
            "operation": req.operation.as_str(),
            "input": req.input,
            "capability_token": req.capability_token,
        });
        let value = self.connector.lock().await.handle_invoke(params).await?;
        Ok(InvokeResponse::ok(request_id, value))
    }

    async fn simulate(&self, req: SimulateRequest) -> fcp_core::FcpResult<SimulateResponse> {
        let request = serde_json::to_value(req).map_err(|err| FcpError::Internal {
            message: err.to_string(),
        })?;
        let value = self.connector.lock().await.handle_simulate(request).await?;
        Ok(serde_json::from_value(value).unwrap())
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
        nonce: [7u8; 32],
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
    let constraints = fcp_core::CapabilityConstraints {
        resource_allow: vec!["*".to_string()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor).expect("serialize test constraints");
    let resolved_capability = match capability {
        "s3.get_object" => "s3.read",
        _ => capability,
    };
    let cose = CapabilityTokenBuilder::new()
        .capability_id(resolved_capability)
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
        id: RequestId::from("s3-e2e"),
        connector_id: ConnectorId::from_static("s3"),
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

fn s3_manifest_toml() -> toml::Value {
    toml::from_str(include_str!("../../../connectors/s3/manifest.toml")).expect("s3 manifest toml")
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

/// S3 `get_object` mock response.
fn s3_get_object_response() -> serde_json::Value {
    json!({
        "body": "hello from s3 e2e test",
        "content_type": "text/plain"
    })
}

// ============================================================================
// Test 1: Default deny -- compliance suite
// ============================================================================

/// Default deny: invoke without matching capability triggers error.
/// Token grants "s3.write" but invoke targets "s3.get_object"
/// (which requires "s3.read").
#[fcp_async_core::runtime::test]
async fn s3_default_deny_compliance_suite_passes() {
    let mut connector = S3ConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(signing_key.verifying_key().to_bytes(), &["s3.write"]);
    // Token grants "s3.write" but invoke targets "s3.get_object" -> denial
    let token = build_token(&signing_key, "s3.write", &["s3.write"]);
    let invoke = invoke_request(
        "s3.get_object",
        json!({ "bucket": "test-bucket", "key": "test-file.txt" }),
        token,
    );

    let dynamic = DynamicSuite {
        config: json!({
            "access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "region": "us-east-1",
            "base_url": "http://localhost:9999"
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
    let suite = ComplianceSuite::new("s3_default_deny", reference_manifest_with_hash(), dynamic);

    let mut runner = E2eRunner::new("fcp-e2e-s3");
    let report = runner
        .run_compliance_suite(&mut connector, suite)
        .await
        .expect("compliance suite run");

    assert!(report.passed, "default deny compliance should pass");
}

// ============================================================================
// Test 2: Allow with valid token -- connector suite
// ============================================================================

/// Allow: invoke with valid capability token succeeds against mock REST API.
#[fcp_async_core::runtime::test]
async fn s3_allow_valid_token_connector_suite_passes() {
    let mock = MockApiServer::start().await;

    // Mount mock for GET /{bucket}/{key} endpoint
    Mock::given(method("GET"))
        .and(path("/test-bucket/test-file.txt"))
        .respond_with(ResponseTemplate::new(200).set_body_json(s3_get_object_response()))
        .mount(mock.inner())
        .await;

    let mut connector = S3ConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(signing_key.verifying_key().to_bytes(), &["s3.get_object"]);
    let token = build_token(&signing_key, "s3.get_object", &["s3.get_object"]);
    let invoke = invoke_request(
        "s3.get_object",
        json!({ "bucket": "test-bucket", "key": "test-file.txt" }),
        token,
    );
    let suite = ConnectorSuite {
        test_name: "s3_allow_valid_token".to_string(),
        config: json!({
            "access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "region": "us-east-1",
            "base_url": mock.base_url(),
        }),
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

    let mut runner = E2eRunner::new("fcp-e2e-s3");
    let report = runner
        .run_connector_suite(&mut connector, suite)
        .await
        .expect("connector suite run");

    assert!(report.passed, "allow suite should pass");
    let received = mock.received_requests().await;
    let hits = received
        .iter()
        .filter(|r| r.url.path() == "/test-bucket/test-file.txt")
        .count();
    assert_eq!(
        hits, 1,
        "expected exactly one GET to /test-bucket/test-file.txt"
    );
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
}

// ============================================================================
// Test 3: Network guard -- manifest host_allow wildcard validation
// ============================================================================

/// Network guard: S3 manifest uses wildcard host_allow patterns like
/// `*.s3.amazonaws.com`, `s3.amazonaws.com`, and `*.amazonaws.com`.
/// Verify that matching hosts pass and non-matching hosts are denied.
#[test]
fn s3_manifest_network_guard_allows_and_denies() {
    let manifest = s3_manifest_toml();

    // Most operations share the same host_allow with wildcard *.s3.amazonaws.com
    let operations_with_s3_wildcard = [
        "s3.put_object",
        "s3.get_object",
        "s3.delete_object",
        "s3.list_objects",
        "s3.head_object",
        "s3.copy_object",
        "s3.generate_presigned_url",
    ];

    let expected_hosts_with_s3_wildcard = vec![
        "*.s3.amazonaws.com".to_string(),
        "s3.amazonaws.com".to_string(),
        "*.amazonaws.com".to_string(),
    ];

    for operation_name in operations_with_s3_wildcard {
        let host_allow = operation_host_allow_list(&manifest, operation_name);
        assert_eq!(
            host_allow, expected_hosts_with_s3_wildcard,
            "operation {operation_name} should allow *.s3.amazonaws.com, s3.amazonaws.com, *.amazonaws.com"
        );

        // Allowed hosts via wildcard patterns
        assert!(
            host_allowed("s3.amazonaws.com", &host_allow),
            "s3.amazonaws.com should be allowed for {operation_name}"
        );
        assert!(
            host_allowed("my-bucket.s3.amazonaws.com", &host_allow),
            "my-bucket.s3.amazonaws.com should be allowed for {operation_name}"
        );
        assert!(
            host_allowed("s3.us-east-1.amazonaws.com", &host_allow),
            "s3.us-east-1.amazonaws.com should be allowed for {operation_name}"
        );

        // Denied hosts
        assert!(
            !host_allowed("amazonaws.com", &host_allow),
            "amazonaws.com (bare domain) should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("example.com", &host_allow),
            "example.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("evil.com", &host_allow),
            "evil.com should be denied for {operation_name}"
        );
    }

    // list_buckets has a slightly different host_allow (no *.s3.amazonaws.com)
    let list_buckets_hosts = operation_host_allow_list(&manifest, "s3.list_buckets");
    let expected_list_buckets = vec![
        "s3.amazonaws.com".to_string(),
        "*.amazonaws.com".to_string(),
    ];
    assert_eq!(
        list_buckets_hosts, expected_list_buckets,
        "s3.list_buckets should allow s3.amazonaws.com, *.amazonaws.com"
    );

    // Allowed for list_buckets
    assert!(host_allowed("s3.amazonaws.com", &list_buckets_hosts));
    assert!(host_allowed(
        "s3.us-east-1.amazonaws.com",
        &list_buckets_hosts
    ));

    // Denied for list_buckets
    assert!(!host_allowed("amazonaws.com", &list_buckets_hosts));
    assert!(!host_allowed("example.com", &list_buckets_hosts));
}
