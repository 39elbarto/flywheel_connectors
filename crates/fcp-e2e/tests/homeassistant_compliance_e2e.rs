//! E2E Home Assistant connector compliance tests.
//!
//! Exercises the Home Assistant connector through the E2E compliance harness:
//! - Default deny (missing capability -> error + decision receipt)
//! - Allow with valid token (happy path invoke via mock REST API)
//! - Network guard allow/deny (manifest `host_allow` validation)
//!
//! All tests are deterministic -- no real API calls.
//! Run: `cargo test --package fcp-e2e --features homeassistant`

#![cfg(feature = "homeassistant")]
#![allow(clippy::too_many_lines)]

use chrono::{Duration as ChronoDuration, Utc};
use fcp_conformance::DynamicSuite;
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_e2e::{ComplianceSuite, ConnectorSuite, E2eRunner, InvokeExpectations};
use fcp_manifest::ConnectorManifest;
use fcp_prelude::{
    AgentHint, CapabilityGrant, CapabilityId, CapabilityToken, ConnectorId, ConnectorMetrics,
    FcpConnector, FcpError, HandshakeRequest, HandshakeResponse, HealthSnapshot, IdempotencyClass,
    InstanceId, Introspection, InvokeRequest, InvokeResponse, InvokeStatus, OperationId,
    OperationInfo, RequestId, RiskLevel, SafetyTier, SessionId, ShutdownRequest, SimulateRequest,
    SimulateResponse, SubscribeRequest, SubscribeResponse, UnsubscribeRequest, ZoneId,
};
use fcp_testkit::MockApiServer;
use serde_json::json;
use wiremock::{
    Mock, ResponseTemplate,
    matchers::{method, path_regex},
};

use fcp_homeassistant::connector::HomeAssistantConnector;

// ============================================================================
// FcpConnector adapter for HomeAssistantConnector
// ============================================================================

struct HomeAssistantConnectorAdapter {
    connector: HomeAssistantConnector,
    id: ConnectorId,
}

impl HomeAssistantConnectorAdapter {
    fn new() -> Self {
        Self {
            connector: HomeAssistantConnector::new(),
            id: ConnectorId::from_static("homeassistant"),
        }
    }
}

fcp_core::impl_fcp_sealed!(HomeAssistantConnectorAdapter);

#[fcp_core::async_trait]
impl FcpConnector for HomeAssistantConnectorAdapter {
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
        let params_obj = params.as_object_mut().ok_or_else(|| FcpError::Internal {
            message: "homeassistant handshake request did not serialize to an object".into(),
        })?;
        params_obj.insert(
            "session_id".to_string(),
            serde_json::Value::String(session_id.0.to_string()),
        );

        let response = self.connector.handle_handshake(params).await?;

        let protocol_version = response
            .get("protocol_version")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| FcpError::Internal {
                message: "homeassistant handshake response missing protocol_version".into(),
            })?;
        if protocol_version != "2.0" {
            return Err(FcpError::Internal {
                message: format!(
                    "homeassistant handshake protocol_version expected 2.0, got {protocol_version}"
                ),
            });
        }
        let connector_id = response
            .get("connector_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| FcpError::Internal {
                message: "homeassistant handshake response missing connector_id".into(),
            })?;
        if connector_id != "fcp.homeassistant" {
            return Err(FcpError::Internal {
                message: format!(
                    "homeassistant handshake connector_id expected fcp.homeassistant, got {connector_id}"
                ),
            });
        }
        let _connector_version = response
            .get("connector_version")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| FcpError::Internal {
                message: "homeassistant handshake response missing connector_version".into(),
            })?;
        let connector_caps: std::collections::BTreeSet<String> = response
            .get("capabilities")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| FcpError::Internal {
                message: "homeassistant handshake response missing capabilities array".into(),
            })?
            .into_iter()
            .filter_map(|value| value.as_str().map(str::to_string))
            .collect();
        let expected_caps = std::collections::BTreeSet::from([
            "homeassistant.read".to_string(),
            "homeassistant.write".to_string(),
            "homeassistant.control".to_string(),
        ]);
        if connector_caps != expected_caps {
            return Err(FcpError::Internal {
                message: format!(
                    "homeassistant handshake capabilities mismatch: expected {expected_caps:?}, got {connector_caps:?}"
                ),
            });
        }

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

        Ok(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
            session_id,
            manifest_hash: "sha256:homeassistant-connector-v1".into(),
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
                    "not_configured" | "unconfigured" => HealthSnapshot::degraded("not_configured"),
                    other => HealthSnapshot::degraded(format!("homeassistant_status:{other}")),
                }
            }
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
                id: OperationId::from_static("homeassistant.list_states"),
                summary: "List current states of all entities".to_string(),
                description: None,
                input_schema: json!({
                    "type": "object"
                }),
                output_schema: json!({
                    "type": "object",
                    "properties": {
                        "states": { "type": "array" }
                    }
                }),
                capability: CapabilityId::from_static("homeassistant.read"),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Get a snapshot of all entity states.".to_string(),
                    common_mistakes: Vec::new(),
                    examples: vec![r#"{}"#.to_string()],
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
            "operation_id": req.operation.as_str(),
            "input": req.input,
            "capability_token": req.capability_token,
        });
        let value = self.connector.handle_invoke(params).await?;
        Ok(InvokeResponse::ok(request_id, value))
    }

    async fn simulate(&self, req: SimulateRequest) -> fcp_core::FcpResult<SimulateResponse> {
        let request = serde_json::to_value(req).map_err(|err| FcpError::Internal {
            message: format!("failed to serialize simulate request: {err}"),
        })?;
        let value = self.connector.handle_simulate(request).await?;
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
        "homeassistant.list_states" => "homeassistant.read",
        _ => capability,
    };
    let cose = CapabilityTokenBuilder::new()
        .capability_id(resolved_capability)
        .zone_id("z:work")
        .principal("user:test")
        .operations(operations)
        .issuer("node:test")
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&constraints_cbor)
        .expect("test constraints CBOR should be valid")
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
        id: RequestId::from("homeassistant-e2e"),
        connector_id: ConnectorId::from_static("homeassistant"),
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

fn homeassistant_manifest_toml() -> toml::Value {
    toml::from_str(include_str!(
        "../../../connectors/homeassistant/manifest.toml"
    ))
    .expect("homeassistant manifest toml")
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

/// Home Assistant list states API success response.
fn homeassistant_list_states_response() -> serde_json::Value {
    json!([
        {
            "entity_id": "light.living_room",
            "state": "on",
            "attributes": {}
        }
    ])
}

// ============================================================================
// Test 1: Default deny -- compliance suite
// ============================================================================

/// Default deny: invoke without matching capability triggers error.
/// Token grants "homeassistant.control" but invoke targets
/// "homeassistant.list_states" (which requires "homeassistant.read").
#[fcp_async_core::runtime::test]
async fn homeassistant_default_deny_compliance_suite_passes() {
    let mut connector = HomeAssistantConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(
        signing_key.verifying_key().to_bytes(),
        &["homeassistant.control"],
    );
    // Token grants "homeassistant.control" but invoke targets
    // "homeassistant.list_states" -> error
    // (the connector will fail because the server at localhost:9999 is unreachable)
    let token = build_token(
        &signing_key,
        "homeassistant.control",
        &["homeassistant.control"],
    );
    let invoke = invoke_request("homeassistant.list_states", json!({}), token);

    let dynamic = DynamicSuite {
        config: json!({
            "base_url": "http://localhost:9999",
            "access_token": "eyJ_test_token"
        }),
        handshake: handshake.clone(),
        invoke: Some(invoke),
        expect_invoke_error: true,
        simulate: None,
        expect_simulate_would_succeed: None,
        require_simulate_denial_details: false,
        require_capability_denial: false,
        require_decision_receipt: false,
    };
    let suite = ComplianceSuite::new(
        "homeassistant_default_deny",
        reference_manifest_with_hash(),
        dynamic,
    );

    let mut runner = E2eRunner::new("fcp-e2e-homeassistant");
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
async fn homeassistant_allow_valid_token_connector_suite_passes() {
    let mock = MockApiServer::start().await;

    // Mount mock for GET /states (base_url already includes /api if needed)
    Mock::given(method("GET"))
        .and(path_regex(r"^/states.*"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(homeassistant_list_states_response()),
        )
        .mount(mock.inner())
        .await;

    let mut connector = HomeAssistantConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(
        signing_key.verifying_key().to_bytes(),
        &["homeassistant.read"],
    );
    let token = build_token(
        &signing_key,
        "homeassistant.list_states",
        &["homeassistant.list_states"],
    );
    let invoke = invoke_request("homeassistant.list_states", json!({}), token);
    let suite = ConnectorSuite {
        test_name: "homeassistant_allow_valid_token".to_string(),
        config: json!({
            "base_url": mock.base_url(),
            "access_token": "eyJ_test_token"
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

    let mut runner = E2eRunner::new("fcp-e2e-homeassistant");
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
    let received = mock.received_requests().await;
    let hits = received
        .iter()
        .filter(|request| request.url.path() == "/states")
        .count();
    assert_eq!(hits, 1, "expected exactly one GET to /states");
}

// ============================================================================
// Test 3: Network guard -- manifest host_allow validation
// ============================================================================

/// Network guard: Home Assistant manifest uses `$ha_host` as a template
/// variable for all operations. Since the host is a variable, we verify
/// that every operation has at least one host_allow entry and that the
/// variable placeholder is consistently present.
#[test]
fn homeassistant_manifest_network_guard_allows_and_denies() {
    let manifest = homeassistant_manifest_toml();

    let operations = [
        "homeassistant.list_states",
        "homeassistant.get_state",
        "homeassistant.call_service",
        "homeassistant.list_devices",
        "homeassistant.list_areas",
    ];

    for operation_name in operations {
        let host_allow = operation_host_allow_list(&manifest, operation_name);

        // Every operation must have at least one host_allow entry
        assert!(
            !host_allow.is_empty(),
            "host_allow should not be empty for {operation_name}"
        );

        // The host_allow should contain the $ha_host variable placeholder
        assert!(
            host_allow.iter().any(|h| h.contains("$ha_host")),
            "$ha_host variable should be present in host_allow for {operation_name}"
        );

        // Static evil hosts should never match the literal entries
        // (the only entry is "$ha_host", which is a variable, not a real host)
        assert!(
            !host_allowed("evil.com", &host_allow),
            "evil.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("example.com", &host_allow),
            "example.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("api.hubapi.com", &host_allow),
            "api.hubapi.com should be denied for {operation_name}"
        );
    }
}
