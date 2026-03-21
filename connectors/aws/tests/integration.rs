//! Integration tests for the FCP AWS connector.

#![allow(
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use chrono::{Duration, Utc};
use fcp_aws::connector::AwsConnector;
use fcp_core::{
    CapabilityId, CapabilityToken, ConnectorId, FcpConnector, HandshakeRequest, InvokeRequest,
    OperationId, RequestId, ZoneId,
};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_testkit::readiness_helpers::{
    assert_doctor_response_valid, assert_self_check_not_ready, assert_self_check_ready,
};
use serde_json::json;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const OP_S3_DELETE_OBJECT: &str = "aws.s3.delete_object";
const OP_STS_IDENTITY: &str = "aws.sts.get_caller_identity";

fn handshake_req(host_public_key: [u8; 32]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [5u8; 32],
        capabilities_requested: vec![
            CapabilityId::from_static("aws.s3.write"),
            CapabilityId::from_static("aws.iam.read"),
        ],
        host: None,
        transport_caps: None,
        requested_instance_id: None,
    }
}

fn generate_valid_token(signing_key: &Ed25519SigningKey, op: &'static str) -> CapabilityToken {
    let capability = match op {
        OP_S3_DELETE_OBJECT => "aws.s3.write",
        OP_STS_IDENTITY => "aws.iam.read",
        _ => panic!("unsupported test operation: {op}"),
    };
    let now = Utc::now();
    let raw = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[op])
        .issuer("node:test")
        .validity(now, now + Duration::hours(1))
        .sign(signing_key)
        .expect("capability token signing should succeed");
    CapabilityToken { raw }
}

fn invoke_req(
    op: &'static str,
    input: serde_json::Value,
    capability_token: CapabilityToken,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new("aws-integration-1"),
        connector_id: ConnectorId::from_static("fcp.aws"),
        operation: OperationId::from_static(op),
        zone_id: ZoneId::work(),
        input,
        capability_token,
        holder_proof: None,
        context: None,
        idempotency_key: None,
        lease_seq: None,
        deadline_ms: None,
        correlation_id: None,
        provenance: None,
        approval_tokens: vec![],
    }
}

async fn setup_connector(mock_url: &str) -> (AwsConnector, Ed25519SigningKey) {
    let mut connector = AwsConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    connector
        .configure(json!({
            "access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "region": "us-east-1",
            "s3_base_url": mock_url,
            "ec2_base_url": mock_url,
            "lambda_base_url": mock_url,
            "sts_base_url": mock_url,
            "retry": { "max_retries": 0 }
        }))
        .await
        .unwrap();
    connector
        .handshake(handshake_req(signing_key.verifying_key().to_bytes()))
        .await
        .unwrap();
    (connector, signing_key)
}

#[fcp_async_core::runtime::test]
async fn lifecycle_health_unconfigured_includes_guidance() {
    let connector = AwsConnector::new();
    let health = connector.health().await;
    assert!(!health.is_ready());
    let details = health.details.expect("health details");
    assert!(details["operator_guidance"]["prerequisites"].is_array());
    assert_eq!(
        details["verification_script"],
        "scripts/e2e/aws_connector_verification.sh"
    );
    assert_eq!(
        details["artifact_root_hint"],
        "artifacts/e2e/aws_connector/<timestamp>"
    );
}

#[fcp_async_core::runtime::test]
async fn doctor_unconfigured_reports_remediation() {
    let connector = AwsConnector::new();
    let doctor = serde_json::to_value(connector.doctor()).unwrap();
    assert_doctor_response_valid(&doctor);
    assert_eq!(doctor["ready"], false);
    assert_eq!(
        doctor["operator_guidance"]["artifact_root_hint"],
        "artifacts/e2e/aws_connector/<timestamp>"
    );
}

#[fcp_async_core::runtime::test]
async fn self_check_ready_with_custom_sts_override_and_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(query_param("Action", "GetCallerIdentity"))
        .and(query_param("Version", "2011-06-15"))
        .and(header("X-Aws-Access-Key-Id", "AKIAIOSFODNN7EXAMPLE"))
        .and(header(
            "X-Aws-Secret-Access-Key",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "account": "123456789012",
            "arn": "arn:aws:sts::123456789012:assumed-role/test/AwsConnector",
            "user_id": "AIDATESTUSER"
        })))
        .mount(&server)
        .await;

    let (connector, _signing_key) = setup_connector(&server.uri()).await;
    let doctor = serde_json::to_value(connector.doctor()).unwrap();
    assert_doctor_response_valid(&doctor);
    assert_eq!(doctor["ready"], true);
    println!(
        "aws_doctor_evidence={}",
        serde_json::to_string_pretty(&doctor).unwrap()
    );

    let report = connector.self_check().await.unwrap();
    let value = serde_json::to_value(&report).unwrap();
    assert_self_check_ready(&value);
    assert_eq!(
        value["details"]["provisioning"]["sts_self_check_supported"],
        true
    );
    println!(
        "aws_self_check_evidence={}",
        serde_json::to_string_pretty(&value).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn self_check_retryable_sts_failure_reports_degraded() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(query_param("Action", "GetCallerIdentity"))
        .and(query_param("Version", "2011-06-15"))
        .respond_with(ResponseTemplate::new(503).set_body_string("sts unavailable"))
        .mount(&server)
        .await;

    let (connector, _signing_key) = setup_connector(&server.uri()).await;
    let report = connector.self_check().await.unwrap();
    let value = serde_json::to_value(&report).unwrap();
    assert_self_check_not_ready(&value);
    assert_eq!(value["status"], "degraded");
    assert_eq!(value["reason_code"], "self_check_retryable");
}

#[fcp_async_core::runtime::test]
async fn invoke_dangerous_s3_delete_preserves_artifact_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/test-bucket/object.txt"))
        .and(header("X-Aws-Access-Key-Id", "AKIAIOSFODNN7EXAMPLE"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "delete_marker": true,
            "version_id": "ver-123"
        })))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server.uri()).await;
    let response = connector
        .invoke(invoke_req(
            OP_S3_DELETE_OBJECT,
            json!({
                "bucket": "test-bucket",
                "key": "object.txt"
            }),
            generate_valid_token(&signing_key, OP_S3_DELETE_OBJECT),
        ))
        .await
        .unwrap();

    let result = response.result.expect("s3 delete result");
    assert_eq!(result["delete_marker"], true);
    println!(
        "aws_risky_mutation_evidence={}",
        serde_json::to_string_pretty(&result).unwrap()
    );
}
