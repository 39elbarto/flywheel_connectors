use fcp_adversarial::{AdversarialConnector, AdversarialConnectorError, OP_ADVERSARIAL_EMIT};
use fcp_prelude::{
    CapabilityId, CapabilityToken, ConnectorId, FcpConnector, FcpError, HandshakeRequest,
    InvokeRequest, InvokeStatus, OperationId, RequestId, ZoneId,
};
use serde_json::{Value, json};

#[fcp_async_core::runtime::test]
async fn test_oversized_payload_returns_structured_error() {
    let err = invoke_scenario("oversized_payload").await;
    assert!(
        matches!(err, FcpError::ResourceExhausted { ref resource } if resource == "provider_payload>1073741825B"),
        "expected ResourceExhausted oversized_payload error, got {err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn test_mid_stream_disconnect_returns_structured_error() {
    let err = invoke_scenario("mid_stream_disconnect").await;
    assert!(
        matches!(err, FcpError::ConnectorUnavailable { code: 5001, ref message } if message.contains("disconnected")),
        "expected ConnectorUnavailable mid-stream error, got {err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn test_time_skew_plus_1y_rejected() {
    let err = invoke_scenario("time_skew_plus_1y").await;
    assert!(
        matches!(err, FcpError::InvalidRequest { code: 1008, ref message } if message.contains("one year in the future")),
        "expected InvalidRequest time skew error, got {err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn test_invalid_utf8_header_rejected() {
    let err = invoke_scenario("invalid_utf8_header").await;
    assert!(
        matches!(err, FcpError::MalformedFrame { code: 1011, ref message } if message.contains("invalid UTF-8")),
        "expected MalformedFrame invalid UTF-8 error, got {err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn test_deeply_nested_json_rejected_at_1001_levels() {
    let err = invoke_scenario("deeply_nested_json").await;
    assert!(
        matches!(err, FcpError::ResourceExhausted { ref resource } if resource == "json_nesting>1001"),
        "expected ResourceExhausted depth error, got {err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn test_oversized_json_key_rejected_at_1mb() {
    let err = invoke_scenario("oversized_json_key").await;
    assert!(
        matches!(err, FcpError::ResourceExhausted { ref resource } if resource == "json_key>1048577B"),
        "expected ResourceExhausted oversized key error, got {err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn test_null_byte_in_response_field_rejected() {
    let err = invoke_scenario("null_byte_injection").await;
    assert!(
        matches!(err, FcpError::MalformedFrame { code: 1012, ref message } if message.contains("null byte")),
        "expected MalformedFrame null byte error, got {err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn test_header_smuggling_rejected() {
    let err = invoke_scenario("header_smuggling").await;
    assert!(
        matches!(err, FcpError::MalformedFrame { code: 1013, ref message } if message.contains("header smuggling")),
        "expected MalformedFrame header smuggling error, got {err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn test_crlf_injection_rejected() {
    let err = invoke_scenario("crlf_injection").await;
    assert!(
        matches!(err, FcpError::MalformedFrame { code: 1014, ref message } if message.contains("CRLF injection")),
        "expected MalformedFrame CRLF error, got {err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn test_production_refuses_adversarial_connector() {
    let err = AdversarialConnector::try_new_for_deploy_mode("production")
        .expect_err("production mode must refuse adversarial connector");
    assert_eq!(err, AdversarialConnectorError::ConnectorTrustError);
}

#[fcp_async_core::runtime::test]
async fn test_production_configure_is_unauthorized() {
    let mut connector = AdversarialConnector::new();
    let err = connector
        .configure(json!({ "deploy_mode": "production" }))
        .await
        .expect_err("production configure must refuse adversarial connector");

    assert!(
        matches!(err, FcpError::Unauthorized { code: 2009, ref message } if message.contains("ConnectorTrustError")),
        "expected Unauthorized ConnectorTrustError, got {err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn introspection_advertises_adversarial_status_and_manifest() {
    let connector = configured_connector().await;
    let introspect = connector.introspect();
    assert_eq!(introspect.operations.len(), 1);

    let operation = &introspect.operations[0];
    assert_eq!(operation.id.as_str(), OP_ADVERSARIAL_EMIT);
    assert_eq!(operation.capability.as_str(), "adversarial.emit");
    assert_eq!(
        operation.input_schema["properties"]["scenario"]["enum"]
            .as_array()
            .expect("scenario enum should be an array")
            .len(),
        10
    );
    assert!(introspect.events.is_empty());
    assert!(
        introspect
            .event_caps
            .as_ref()
            .is_some_and(|caps| !caps.streaming && !caps.replay)
    );
}

async fn invoke_scenario(scenario: &str) -> FcpError {
    let connector = configured_connector().await;
    let response = connector
        .invoke(invoke(
            OP_ADVERSARIAL_EMIT,
            &json!({ "scenario": scenario }),
        ))
        .await
        .expect("adversarial invoke should return a structured response");
    assert_eq!(response.status, InvokeStatus::Error);
    response
        .error
        .expect("adversarial scenario must carry an FCP error")
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
        capabilities_requested: vec![CapabilityId::from_static("adversarial.emit")],
        host: None,
        transport_caps: None,
        requested_instance_id: None,
    }
}

fn invoke(operation: &'static str, input: &Value) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new("adversarial-integration"),
        connector_id: ConnectorId::from_static("fcp.adversarial"),
        operation: OperationId::from_static(operation),
        zone_id: ZoneId::work(),
        input: input.clone(),
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
