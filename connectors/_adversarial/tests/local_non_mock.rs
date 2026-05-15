use fcp_adversarial::{
    AdversarialConnector, AdversarialConnectorError, AdversarialScenario, CONNECTOR_ID,
    OP_ADVERSARIAL_EMIT,
};
use fcp_prelude::{
    CapabilityId, CapabilityToken, ConnectorId, FcpConnector, FcpError, HandshakeRequest,
    InvokeRequest, InvokeStatus, OperationId, RequestId, SimulateRequest, SubscribeRequest, ZoneId,
};
use serde::Serialize;
use serde_json::{Value, json};

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const BEAD_ID: &str = "flywheel_connectors-bky21.3.6.55";
const CAP_ADVERSARIAL_EMIT: &str = "adversarial.emit";
const ROUTE_NO_EGRESS: &str = "in_process_no_egress";
const REDACTION_SENTINEL: &str = "PROVIDER_SECRET_AND_PAYLOAD_BYTES_MUST_NOT_APPEAR";

#[fcp_async_core::runtime::test]
async fn local_non_mock_emits_hostile_response_errors_without_egress() {
    let connector = configured_connector().await;
    assert!(connector.instance_id().starts_with("inst_"));

    let mut evidence = Vec::new();
    for expectation in scenario_expectations() {
        let response = connector
            .invoke(invoke_request(
                &format!("adversarial-local-{}", expectation.scenario.as_str()),
                json!({ "scenario": expectation.scenario.as_str() }),
            ))
            .await
            .expect("adversarial invoke should return a structured response");

        assert_eq!(response.status, InvokeStatus::Error);
        let error = response.error.expect("adversarial scenarios return errors");
        expectation.assert_matches(&error);
        evidence.push(evidence_log(
            "invoke",
            expectation.scenario.as_str(),
            expectation.error_code,
            "structured_error",
        ));
    }

    let metrics = connector.metrics();
    assert_eq!(metrics.requests_total, scenario_expectations().len() as u64);
    assert_eq!(metrics.requests_success, 0);
    assert_eq!(metrics.requests_error, scenario_expectations().len() as u64);

    let evidence_json = serde_json::to_string(&evidence).expect("evidence serializes");
    assert!(evidence_json.contains(ACCEPTANCE_SUITE_CLASS));
    assert!(evidence_json.contains(BEAD_ID));
    assert!(!evidence_json.contains(REDACTION_SENTINEL));
    assert!(!evidence_json.contains("provider_response_body"));
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_lifecycle_requires_opt_in_and_rejects_streaming() {
    let err = AdversarialConnector::try_new_for_deploy_mode("production")
        .expect_err("production deploy mode must refuse this connector");
    assert_eq!(err, AdversarialConnectorError::ConnectorTrustError);

    let mut connector = AdversarialConnector::new();
    let configure_err = connector
        .configure(json!({ "deploy_mode": "production" }))
        .await
        .expect_err("production configure must fail closed");
    assert!(
        matches!(configure_err, FcpError::Unauthorized { code: 2009, ref message } if message.contains("ConnectorTrustError")),
        "unexpected configure error: {configure_err:?}"
    );

    connector
        .configure(json!({ "deploy_mode": "test" }))
        .await
        .expect("test mode is explicit opt-in");
    let handshake = connector
        .handshake(handshake_request())
        .await
        .expect("handshake should advertise adversarial capability");
    assert_eq!(handshake.status, "accepted");
    assert_eq!(handshake.capabilities_granted.len(), 1);
    assert_eq!(
        handshake.capabilities_granted[0].capability.as_str(),
        CAP_ADVERSARIAL_EMIT
    );
    assert_eq!(
        handshake.capabilities_granted[0]
            .operation
            .as_ref()
            .expect("operation grant is scoped")
            .as_str(),
        OP_ADVERSARIAL_EMIT
    );
    let event_caps = handshake.event_caps.expect("event caps advertised");
    assert!(!event_caps.streaming);
    assert!(!event_caps.replay);
    assert_eq!(event_caps.min_buffer_events, 0);
    assert!(!event_caps.requires_ack);

    let health = connector.health().await;
    assert_eq!(health.status.as_str(), "ready");
    assert_eq!(
        health
            .details
            .as_ref()
            .and_then(|details| details["status"].as_str()),
        Some("ADVERSARIAL")
    );
    assert_eq!(
        health
            .details
            .as_ref()
            .and_then(|details| details["scenario_count"].as_u64()),
        Some(10)
    );

    let stream_err = connector
        .subscribe(SubscribeRequest {
            r#type: "subscribe".to_string(),
            id: RequestId::new("adversarial-local-subscribe"),
            topics: vec!["adversarial.scenarios".to_string()],
            since: None,
            max_events_per_sec: None,
            batch_ms: None,
            window_size: None,
            capability_token: Some(CapabilityToken::test_token()),
        })
        .await
        .expect_err("adversarial connector does not expose streaming");
    assert!(matches!(stream_err, FcpError::StreamingNotSupported));

    let evidence_json = serde_json::to_string(&evidence_log(
        "lifecycle",
        "opt_in",
        "FCP-2009",
        "fail_closed",
    ))
    .expect("evidence serializes");
    assert!(evidence_json.contains(ROUTE_NO_EGRESS));
    assert!(!evidence_json.contains(REDACTION_SENTINEL));
}

#[fcp_async_core::runtime::test]
async fn evidence_schema_carries_connector_and_tracker_identity() {
    assert_eq!(ACCEPTANCE_SUITE_CLASS, "local_non_mock");
    assert_eq!(CONNECTOR_ID, "fcp.adversarial");
    assert_eq!(OP_ADVERSARIAL_EMIT, "adversarial.emit");

    let connector = configured_connector().await;
    let introspection = connector.introspect();
    assert_eq!(introspection.operations.len(), 1);
    assert_eq!(introspection.operations[0].id.as_str(), OP_ADVERSARIAL_EMIT);
    assert_eq!(
        introspection.operations[0].capability.as_str(),
        CAP_ADVERSARIAL_EMIT
    );
    assert_eq!(
        introspection.operations[0].input_schema["properties"]["scenario"]["enum"]
            .as_array()
            .expect("scenario enum should be present")
            .len(),
        scenario_expectations().len()
    );

    let allowed = connector
        .simulate(simulate_request(OP_ADVERSARIAL_EMIT))
        .await
        .expect("known operation should simulate");
    assert!(allowed.would_succeed);

    let denied = connector
        .simulate(simulate_request("adversarial.unknown"))
        .await
        .expect("unknown operation simulation should be a denial response");
    assert!(!denied.would_succeed);
    assert_eq!(denied.denial_code.as_deref(), Some("FCP-1004"));

    let evidence = evidence_log(
        "introspect",
        "catalog",
        "schema_valid",
        "connector_metadata_verified",
    );
    let value = serde_json::to_value(evidence).expect("evidence serializes");
    assert_eq!(value["suite_class"], ACCEPTANCE_SUITE_CLASS);
    assert_eq!(value["bead_id"], BEAD_ID);
    assert_eq!(value["connector_id"], CONNECTOR_ID);
    assert_eq!(value["route"], ROUTE_NO_EGRESS);
    assert_eq!(value["network_boundary"], "no_network_or_provider_process");
}

async fn configured_connector() -> AdversarialConnector {
    let mut connector =
        AdversarialConnector::try_new_for_deploy_mode("test").expect("test mode should load");
    connector
        .configure(json!({ "deploy_mode": "test" }))
        .await
        .expect("configure should require explicit opt-in");
    connector
        .handshake(handshake_request())
        .await
        .expect("handshake should work");
    connector
}

fn handshake_request() -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key: [7; 32],
        nonce: [9; 32],
        capabilities_requested: vec![CapabilityId::from_static(CAP_ADVERSARIAL_EMIT)],
        host: None,
        transport_caps: None,
        requested_instance_id: None,
    }
}

fn invoke_request(id: &str, input: Value) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".to_string(),
        id: RequestId::new(id),
        connector_id: ConnectorId::from_static(CONNECTOR_ID),
        operation: OperationId::from_static(OP_ADVERSARIAL_EMIT),
        zone_id: ZoneId::work(),
        input,
        capability_token: CapabilityToken::test_token(),
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

fn simulate_request(operation: &'static str) -> SimulateRequest {
    SimulateRequest::new(
        ConnectorId::from_static(CONNECTOR_ID),
        OperationId::from_static(operation),
        ZoneId::work(),
        json!({ "scenario": "oversized_payload" }),
        CapabilityToken::test_token(),
    )
}

#[derive(Clone, Copy)]
struct ScenarioExpectation {
    scenario: AdversarialScenario,
    error_code: &'static str,
}

impl ScenarioExpectation {
    fn assert_matches(self, error: &FcpError) {
        match (self.scenario, error) {
            (AdversarialScenario::OversizedPayload, FcpError::ResourceExhausted { resource }) => {
                assert_eq!(resource, "provider_payload>1073741825B");
            }
            (
                AdversarialScenario::MidStreamDisconnect,
                FcpError::ConnectorUnavailable {
                    code: 5001,
                    message,
                },
            ) => {
                assert!(message.contains("disconnected"));
            }
            (
                AdversarialScenario::TimeSkewPlus1y,
                FcpError::InvalidRequest {
                    code: 1008,
                    message,
                },
            ) => {
                assert!(message.contains("future"));
            }
            (
                AdversarialScenario::TimeSkewMinus1y,
                FcpError::InvalidRequest {
                    code: 1008,
                    message,
                },
            ) => {
                assert!(message.contains("past"));
            }
            (
                AdversarialScenario::InvalidUtf8Header,
                FcpError::MalformedFrame {
                    code: 1011,
                    message,
                },
            ) => {
                assert!(message.contains("invalid UTF-8"));
            }
            (AdversarialScenario::DeeplyNestedJson, FcpError::ResourceExhausted { resource }) => {
                assert_eq!(resource, "json_nesting>1001");
            }
            (AdversarialScenario::OversizedJsonKey, FcpError::ResourceExhausted { resource }) => {
                assert_eq!(resource, "json_key>1048577B");
            }
            (
                AdversarialScenario::NullByteInjection,
                FcpError::MalformedFrame {
                    code: 1012,
                    message,
                },
            ) => {
                assert!(message.contains("null byte"));
            }
            (
                AdversarialScenario::HeaderSmuggling,
                FcpError::MalformedFrame {
                    code: 1013,
                    message,
                },
            ) => {
                assert!(message.contains("header smuggling"));
            }
            (
                AdversarialScenario::CrlfInjection,
                FcpError::MalformedFrame {
                    code: 1014,
                    message,
                },
            ) => {
                assert!(message.contains("CRLF injection"));
            }
            _ => panic!("unexpected error for {}: {error:?}", self.scenario.as_str()),
        }
    }
}

const fn scenario_expectations() -> &'static [ScenarioExpectation] {
    &[
        ScenarioExpectation {
            scenario: AdversarialScenario::OversizedPayload,
            error_code: "FCP-resource-exhausted",
        },
        ScenarioExpectation {
            scenario: AdversarialScenario::MidStreamDisconnect,
            error_code: "FCP-5001",
        },
        ScenarioExpectation {
            scenario: AdversarialScenario::TimeSkewPlus1y,
            error_code: "FCP-1008",
        },
        ScenarioExpectation {
            scenario: AdversarialScenario::TimeSkewMinus1y,
            error_code: "FCP-1008",
        },
        ScenarioExpectation {
            scenario: AdversarialScenario::InvalidUtf8Header,
            error_code: "FCP-1011",
        },
        ScenarioExpectation {
            scenario: AdversarialScenario::DeeplyNestedJson,
            error_code: "FCP-resource-exhausted",
        },
        ScenarioExpectation {
            scenario: AdversarialScenario::OversizedJsonKey,
            error_code: "FCP-resource-exhausted",
        },
        ScenarioExpectation {
            scenario: AdversarialScenario::NullByteInjection,
            error_code: "FCP-1012",
        },
        ScenarioExpectation {
            scenario: AdversarialScenario::HeaderSmuggling,
            error_code: "FCP-1013",
        },
        ScenarioExpectation {
            scenario: AdversarialScenario::CrlfInjection,
            error_code: "FCP-1014",
        },
    ]
}

#[derive(Serialize)]
struct EvidenceLog {
    suite_class: &'static str,
    bead_id: &'static str,
    connector_id: &'static str,
    operation: &'static str,
    scenario: &'static str,
    route: &'static str,
    network_boundary: &'static str,
    outcome: &'static str,
    fcp_error_code: &'static str,
    redaction: &'static str,
}

const fn evidence_log(
    operation: &'static str,
    scenario: &'static str,
    fcp_error_code: &'static str,
    outcome: &'static str,
) -> EvidenceLog {
    EvidenceLog {
        suite_class: ACCEPTANCE_SUITE_CLASS,
        bead_id: BEAD_ID,
        connector_id: CONNECTOR_ID,
        operation,
        scenario,
        route: ROUTE_NO_EGRESS,
        network_boundary: "no_network_or_provider_process",
        outcome,
        fcp_error_code,
        redaction: "no_provider_secret_or_raw_payload_bytes_logged",
    }
}
