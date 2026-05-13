#![allow(clippy::too_many_lines)]

use fcp_adversarial::{AdversarialConnector, AdversarialConnectorError};
use fcp_prelude::FcpError;
use serde_json::{Value, json};

const OP_TRIGGER: &str = "adversarial.trigger";

#[fcp_async_core::runtime::test]
async fn test_oversized_payload_returns_structured_error() {
    let err = invoke_scenario("oversized_payload").await;
    assert!(
        matches!(err, FcpError::ResourceExhausted { ref resource } if resource.contains("oversized_payload")),
        "expected ResourceExhausted oversized_payload error, got {err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn test_mid_stream_disconnect_returns_structured_error() {
    let err = invoke_scenario("mid_stream_disconnect").await;
    assert!(
        matches!(err, FcpError::External { ref service, retryable: true, .. } if service == "adversarial-mid-stream"),
        "expected retryable External error, got {err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn test_time_skew_plus_1y_rejected() {
    let err = invoke_scenario("time_skew_plus_1y").await;
    assert!(
        matches!(err, FcpError::InvalidRequest { ref message, .. } if message.contains("time_skew_plus_1y")),
        "expected InvalidRequest time skew error, got {err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn test_invalid_utf8_header_rejected() {
    let err = invoke_scenario("invalid_utf8_header").await;
    assert!(
        matches!(err, FcpError::MalformedFrame { ref message, .. } if message.contains("invalid_utf8_header")),
        "expected MalformedFrame invalid UTF-8 error, got {err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn test_deeply_nested_json_rejected_at_1001_levels() {
    let err = invoke_scenario("deeply_nested_json").await;
    assert!(
        matches!(err, FcpError::InvalidRequest { ref message, .. } if message.contains("depth 1001")),
        "expected InvalidRequest depth error, got {err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn test_oversized_json_key_rejected_at_1mb() {
    let err = invoke_scenario("oversized_json_key").await;
    assert!(
        matches!(err, FcpError::ResourceExhausted { ref resource } if resource.contains("oversized_json_key")),
        "expected ResourceExhausted oversized key error, got {err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn test_null_byte_in_response_field_rejected() {
    let err = invoke_scenario("null_byte_in_response_field").await;
    assert!(
        matches!(err, FcpError::MalformedFrame { ref message, .. } if message.contains("null_byte_in_response_field")),
        "expected MalformedFrame null byte error, got {err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn test_header_smuggling_rejected() {
    let err = invoke_scenario("header_smuggling").await;
    assert!(
        matches!(err, FcpError::MalformedFrame { ref message, .. } if message.contains("header_smuggling")),
        "expected MalformedFrame header smuggling error, got {err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn test_crlf_injection_rejected() {
    let err = invoke_scenario("crlf_injection").await;
    assert!(
        matches!(err, FcpError::MalformedFrame { ref message, .. } if message.contains("crlf_injection")),
        "expected MalformedFrame CRLF error, got {err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn test_production_refuses_adversarial_connector() {
    let err = AdversarialConnector::new_for_deploy_mode("production")
        .expect_err("production mode must refuse adversarial connector");
    assert!(
        matches!(
            err,
            AdversarialConnectorError::ConnectorTrustError { ref deploy_mode }
                if deploy_mode == "production"
        ),
        "expected ConnectorTrustError, got {err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn introspection_advertises_adversarial_status_and_manifest() {
    let connector = configured_connector().await;
    let introspect = connector
        .handle_introspect()
        .await
        .expect("introspect should work");
    assert_eq!(introspect["surface_status"], "adversarial");
    assert_eq!(introspect["operations"][0]["id"], OP_TRIGGER);
    assert_eq!(
        introspect["scenarios"]
            .as_array()
            .expect("scenarios should be an array")
            .len(),
        10
    );

    let manifest = fcp_manifest::ConnectorManifest::parse_str(include_str!("../manifest.toml"))
        .expect("adversarial manifest should parse");
    assert_eq!(
        manifest.connector.status,
        fcp_manifest::ConnectorStatus::Adversarial
    );
    assert!(manifest.connector.status.is_hidden_by_default());
}

async fn invoke_scenario(scenario: &str) -> FcpError {
    let connector = configured_connector().await;
    connector
        .handle_invoke(invoke(OP_TRIGGER, &json!({ "scenario": scenario })))
        .await
        .expect_err("adversarial scenario must return structured error")
}

async fn configured_connector() -> AdversarialConnector {
    let mut connector =
        AdversarialConnector::new_for_deploy_mode("test").expect("test mode should load");
    connector
        .handle_configure(json!({ "allow_adversarial": true }))
        .await
        .expect("configure should require explicit opt-in");
    connector
        .handle_handshake(json!({}))
        .await
        .expect("handshake should work");
    connector
}

fn invoke(operation: &str, input: &Value) -> Value {
    json!({ "operation_id": operation, "input": input })
}
