use fcp_adversarial::{
    AdversarialConnector, AdversarialConnectorError, CONNECTOR_ID, OP_ADVERSARIAL_EMIT,
};
use fcp_prelude::{
    CapabilityId, CapabilityToken, ConnectorId, FcpConnector, FcpError, HandshakeRequest,
    InvokeRequest, InvokeResponse, InvokeStatus, OperationId, RequestId, ZoneId,
};
use serde_json::json;

async fn ready_connector() -> AdversarialConnector {
    let mut connector = AdversarialConnector::new();
    connector
        .configure(json!({ "deploy_mode": "test" }))
        .await
        .expect("configure adversarial connector");
    connector
        .handshake(HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: [7; 32],
            nonce: [9; 32],
            capabilities_requested: vec![CapabilityId::from_static(OP_ADVERSARIAL_EMIT)],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        })
        .await
        .expect("handshake adversarial connector");
    connector
}

fn invoke_request(scenario: &str) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::random(),
        connector_id: ConnectorId::from_static(CONNECTOR_ID),
        operation: OperationId::from_static(OP_ADVERSARIAL_EMIT),
        zone_id: ZoneId::work(),
        input: json!({ "scenario": scenario }),
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

async fn invoke_error(scenario: &str) -> FcpError {
    let connector = ready_connector().await;
    let response = connector
        .invoke(invoke_request(scenario))
        .await
        .expect("adversarial scenario should return an invoke response");
    assert_structured_error_response(&response);
    response.error.expect("structured FCP error")
}

fn assert_structured_error_response(response: &InvokeResponse) {
    assert_eq!(response.status, InvokeStatus::Error);
    assert!(response.result.is_none());
    assert!(response.error.is_some());
}

#[fcp_async_core::runtime::test]
async fn test_oversized_payload_returns_structured_error() {
    let error = invoke_error("oversized_payload").await;
    assert!(
        matches!(error, FcpError::ResourceExhausted { resource } if resource.contains(">1073741825B"))
    );
}

#[fcp_async_core::runtime::test]
async fn test_mid_stream_disconnect_returns_structured_error() {
    let error = invoke_error("mid_stream_disconnect").await;
    assert!(matches!(
        error,
        FcpError::ConnectorUnavailable { code: 5001, .. }
    ));
}

#[fcp_async_core::runtime::test]
async fn test_time_skew_plus_1y_rejected() {
    let error = invoke_error("time_skew_plus_1y").await;
    assert!(matches!(error, FcpError::InvalidRequest { code: 1008, .. }));
}

#[fcp_async_core::runtime::test]
async fn test_time_skew_minus_1y_rejected() {
    let error = invoke_error("time_skew_minus_1y").await;
    assert!(matches!(error, FcpError::InvalidRequest { code: 1008, .. }));
}

#[fcp_async_core::runtime::test]
async fn test_invalid_utf8_header_rejected() {
    let error = invoke_error("invalid_utf8_header").await;
    assert!(matches!(error, FcpError::MalformedFrame { code: 1011, .. }));
}

#[fcp_async_core::runtime::test]
async fn test_deeply_nested_json_rejected_at_1001_levels() {
    let error = invoke_error("deeply_nested_json").await;
    assert!(matches!(error, FcpError::ResourceExhausted { resource } if resource.contains("1001")));
}

#[fcp_async_core::runtime::test]
async fn test_oversized_json_key_rejected_at_1mb() {
    let error = invoke_error("oversized_json_key").await;
    assert!(
        matches!(error, FcpError::ResourceExhausted { resource } if resource.contains("1048577B"))
    );
}

#[fcp_async_core::runtime::test]
async fn test_null_byte_in_response_field_rejected() {
    let error = invoke_error("null_byte_injection").await;
    assert!(matches!(error, FcpError::MalformedFrame { code: 1012, .. }));
}

#[fcp_async_core::runtime::test]
async fn test_header_smuggling_rejected() {
    let error = invoke_error("header_smuggling").await;
    assert!(matches!(error, FcpError::MalformedFrame { code: 1013, .. }));
}

#[fcp_async_core::runtime::test]
async fn test_crlf_injection_rejected() {
    let error = invoke_error("crlf_injection").await;
    assert!(matches!(error, FcpError::MalformedFrame { code: 1014, .. }));
}

#[test]
fn test_production_refuses_adversarial_connector() {
    let error = AdversarialConnector::try_new_for_deploy_mode("production")
        .expect_err("production must refuse adversarial connector");
    assert_eq!(error, AdversarialConnectorError::ConnectorTrustError);
}
