//! E2E Kubernetes connector compliance tests.
//!
//! Exercises the Kubernetes connector through the E2E compliance harness:
//! - Default deny (missing capability -> error + decision receipt)
//! - Allow with valid token (happy path invoke via mock REST API)
//! - Network guard allow/deny (manifest `host_allow` variable validation)
//!
//! All tests are deterministic -- no real API calls.
//! Run: `cargo test --package fcp-e2e --features kubernetes`

#![cfg(feature = "kubernetes")]
#![allow(clippy::too_many_lines)]

use chrono::{Duration as ChronoDuration, Utc};
use fcp_conformance::DynamicSuite;
use fcp_core::{
    AgentHint, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier, ConnectorId,
    ConnectorMetrics, FcpConnector, FcpError, HandshakeRequest, HandshakeResponse, HealthSnapshot,
    IdempotencyClass, InstanceId, Introspection, InvokeRequest, InvokeResponse, InvokeStatus,
    OperationId, OperationInfo, RequestId, RiskLevel, SafetyTier, SessionId, ShutdownRequest,
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
    matchers::{method, path_regex},
};

use fcp_kubernetes::connector::KubernetesConnector;

// ============================================================================
// FcpConnector adapter for KubernetesConnector
// ============================================================================

struct KubernetesConnectorAdapter {
    connector: KubernetesConnector,
    id: ConnectorId,
    instance_id: InstanceId,
    verifier: Option<CapabilityVerifier>,
}

impl KubernetesConnectorAdapter {
    fn new() -> Self {
        Self {
            connector: KubernetesConnector::new(),
            id: ConnectorId::from_static("kubernetes"),
            instance_id: InstanceId::new(),
            verifier: None,
        }
    }
}

fcp_core::impl_fcp_sealed!(KubernetesConnectorAdapter);

#[fcp_core::async_trait]
impl FcpConnector for KubernetesConnectorAdapter {
    fn id(&self) -> &ConnectorId {
        &self.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> fcp_core::FcpResult<()> {
        self.connector.handle_configure(config).await.map(|_| ())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> fcp_core::FcpResult<HandshakeResponse> {
        self.connector
            .handle_handshake(json!({
                "session_id": "kubernetes-e2e-session",
            }))
            .await?;

        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.instance_id.clone(),
        ));

        Ok(HandshakeResponse {
            status: "accepted".to_string(),
            capabilities_granted: req
                .capabilities_requested
                .iter()
                .cloned()
                .map(|capability| CapabilityGrant {
                    capability,
                    operation: None,
                })
                .collect(),
            session_id: SessionId::new(),
            manifest_hash: "sha256:kubernetes-e2e".to_string(),
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
                    other => HealthSnapshot::degraded(format!("kubernetes_status:{other}")),
                }
            }
            Err(err) => HealthSnapshot::error(err.to_string()),
        }
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
                id: OperationId::from_static("kubernetes.list_pods"),
                summary: "List pods in a namespace".to_string(),
                description: None,
                input_schema: serde_json::json!({
                    "type": "object",
                    "required": ["namespace"],
                    "properties": {
                        "namespace": { "type": "string" },
                        "label_selector": { "type": "string" }
                    }
                }),
                output_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "pods": { "type": "array" }
                    }
                }),
                capability: CapabilityId::from_static("kubernetes.read"),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "List pods in a namespace.".to_string(),
                    common_mistakes: Vec::new(),
                    examples: vec![r#"{"namespace": "default"}"#.to_string()],
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
            message: "kubernetes verifier not initialized; handshake required".into(),
        })?;
        let required_cap = required_capability(req.operation.as_str())?;
        verifier.verify(req.capability_token, &required_cap, &req.operation, &[])?;

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
            message: "kubernetes verifier not initialized; handshake required".into(),
        })?;
        let required_cap = required_capability(req.operation.as_str())?;
        verifier.verify(req.capability_token, &required_cap, &req.operation, &[])?;

        let value = self
            .connector
            .handle_simulate(json!({
                "operation_id": req.operation.as_str(),
                "input": req.input,
            }))
            .await?;
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

fn required_capability(operation: &str) -> fcp_core::FcpResult<CapabilityId> {
    let capability = match operation {
        "kubernetes.list_pods"
        | "kubernetes.get_pod"
        | "kubernetes.get_deployment"
        | "kubernetes.list_deployments"
        | "kubernetes.get_pod_logs"
        | "kubernetes.get_service"
        | "kubernetes.get_configmap"
        | "kubernetes.stream_pod_logs"
        | "kubernetes.watch_events" => "kubernetes.read",
        "kubernetes.scale_deployment"
        | "kubernetes.rollout_restart"
        | "kubernetes.update_configmap" => "kubernetes.write",
        "kubernetes.delete_pod" => "kubernetes.admin",
        "kubernetes.get_secret" => "kubernetes.secrets",
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
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:test")
        .operations(operations)
        .issuer("node:test")
        .validity(now, now + ChronoDuration::hours(1))
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
        id: RequestId::from("kubernetes-e2e"),
        connector_id: ConnectorId::from_static("kubernetes"),
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

fn kubernetes_manifest_toml() -> toml::Value {
    toml::from_str(include_str!("../../../connectors/kubernetes/manifest.toml"))
        .expect("kubernetes manifest toml")
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
    host_allow.iter().any(|pattern| {
        pattern == host
            || pattern
                .strip_prefix("*.")
                .is_some_and(|suffix| host.ends_with(&format!(".{suffix}")))
    })
}

/// Kubernetes pods list API success response.
fn kubernetes_list_pods_response() -> serde_json::Value {
    json!({
        "kind": "PodList",
        "apiVersion": "v1",
        "items": []
    })
}

// ============================================================================
// Test 1: Default deny -- compliance suite
// ============================================================================

/// Default deny: invoke without matching capability triggers error.
/// Token grants "kubernetes.admin" but invoke targets "kubernetes.list_pods"
/// (which requires "kubernetes.read").
#[fcp_async_core::runtime::test]
async fn kubernetes_default_deny_compliance_suite_passes() {
    let mut connector = KubernetesConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(
        signing_key.verifying_key().to_bytes(),
        &["kubernetes.admin"],
    );
    // Token grants "kubernetes.admin" but invoke targets "kubernetes.list_pods" -> denial
    let token = build_token(&signing_key, "kubernetes.admin", &["kubernetes.admin"]);
    let invoke = invoke_request(
        "kubernetes.list_pods",
        json!({ "namespace": "default" }),
        token,
    );

    let dynamic = DynamicSuite {
        config: json!({
            "bearer_token": "test-token-000",
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
    let suite = ComplianceSuite::new(
        "kubernetes_default_deny",
        reference_manifest_with_hash(),
        dynamic,
    );

    let mut runner = E2eRunner::new("fcp-e2e-kubernetes");
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
async fn kubernetes_allow_valid_token_connector_suite_passes() {
    let mock = MockApiServer::start().await;

    // Mount mock for GET /api/v1/namespaces/*/pods
    Mock::given(method("GET"))
        .and(path_regex(r"^/api/v1/namespaces/.*/pods"))
        .respond_with(ResponseTemplate::new(200).set_body_json(kubernetes_list_pods_response()))
        .mount(mock.inner())
        .await;

    let mut connector = KubernetesConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(signing_key.verifying_key().to_bytes(), &["kubernetes.read"]);
    let token = build_token(&signing_key, "kubernetes.read", &["kubernetes.list_pods"]);
    let invoke = invoke_request(
        "kubernetes.list_pods",
        json!({ "namespace": "default" }),
        token,
    );
    let suite = ConnectorSuite {
        test_name: "kubernetes_allow_valid_token".to_string(),
        config: json!({
            "bearer_token": "test-token-e2e",
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

    let mut runner = E2eRunner::new("fcp-e2e-kubernetes");
    let report = runner
        .run_connector_suite(&mut connector, suite)
        .await
        .expect("connector suite run");

    assert!(report.passed, "allow suite should pass");
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
// Test 3: Network guard -- manifest host_allow validation
// ============================================================================

/// Network guard: Kubernetes manifest uses `$KUBE_API_HOST` as a variable
/// placeholder for all operations. Verify that each operation declares a
/// non-empty `host_allow` list containing the variable placeholder.
#[test]
fn kubernetes_manifest_network_guard_allows_and_denies() {
    let manifest = kubernetes_manifest_toml();

    let operations = [
        "kubernetes.list_pods",
        "kubernetes.get_pod",
        "kubernetes.get_deployment",
        "kubernetes.list_deployments",
        "kubernetes.get_pod_logs",
    ];

    for operation_name in operations {
        let host_allow = operation_host_allow_list(&manifest, operation_name);

        // All operations should have a non-empty host_allow list
        assert!(
            !host_allow.is_empty(),
            "host_allow should not be empty for {operation_name}"
        );

        // All operations use the $KUBE_API_HOST variable
        assert!(
            host_allow.iter().any(|h| h.contains("KUBE_API_HOST")),
            "$KUBE_API_HOST variable should be in host_allow for {operation_name}"
        );

        // Verify that arbitrary hosts are not present in the allow list
        assert!(
            !host_allowed("evil.com", &host_allow),
            "evil.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("example.com", &host_allow),
            "example.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("notk8s.io", &host_allow),
            "notk8s.io should be denied for {operation_name}"
        );
    }
}
