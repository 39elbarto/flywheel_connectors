//! Integration tests for the FCP Cloudflare connector.

#![allow(
    clippy::cast_possible_truncation,
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use chrono::{Duration, Utc};
use fcp_cloudflare::connector::CloudflareConnector;
use fcp_core::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector,
    HandshakeRequest, InvokeRequest, OperationId, RequestId, ZoneId,
};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_testkit::readiness_helpers::{
    assert_doctor_response_valid, assert_self_check_not_ready, assert_self_check_ready,
};
use serde_json::json;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const OP_ZONES_LIST: &str = "cloudflare.zones.list";
const OP_DNS_DELETE: &str = "cloudflare.dns.delete_record";

fn handshake_req(host_public_key: [u8; 32]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [1u8; 32],
        capabilities_requested: vec![
            CapabilityId::from_static("cloudflare.zones.read"),
            CapabilityId::from_static("cloudflare.dns.write"),
        ],
        host: None,
        transport_caps: None,
        requested_instance_id: None,
    }
}

fn generate_valid_token(
    signing_key: &Ed25519SigningKey,
    op: &'static str,
) -> Result<CapabilityToken, String> {
    let capability = match op {
        OP_ZONES_LIST => "cloudflare.zones.read",
        OP_DNS_DELETE => "cloudflare.dns.write",
        _ => return Err(format!("unsupported test operation: {op}")),
    };
    let now = Utc::now();
    // C3.4: tokens MUST include constraints (default-deny)
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor)
        .map_err(|err| format!("serialize constraints: {err:?}"))?;
    let raw = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[op])
        .issuer("node:test")
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .map_err(|err| format!("constraints CBOR should validate: {err:?}"))?
        .sign(signing_key)
        .map_err(|err| format!("capability token signing should succeed: {err:?}"))?;
    Ok(CapabilityToken::from_raw(raw))
}

fn invoke_req(
    op: &'static str,
    input: serde_json::Value,
    capability_token: CapabilityToken,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new("integration-1"),
        connector_id: ConnectorId::from_static("fcp.cloudflare"),
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

async fn setup_connector(mock_url: &str) -> (CloudflareConnector, Ed25519SigningKey) {
    let mut connector = CloudflareConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    connector
        .configure(json!({
            "mode": "api_token",
            "api_token": "test-cloudflare-token",
            "account_id": "account-123",
            "base_url": mock_url,
            "retry": { "max_retries": 0 },
        }))
        .await
        .unwrap();
    connector
        .handshake(handshake_req(signing_key.verifying_key().to_bytes()))
        .await
        .unwrap();
    (connector, signing_key)
}

async fn setup_api_key_connector(mock_url: &str) -> (CloudflareConnector, Ed25519SigningKey) {
    let mut connector = CloudflareConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    connector
        .configure(json!({
            "mode": "api_key",
            "api_key": "test-global-key",
            "email": "ops@example.com",
            "account_id": "account-123",
            "base_url": mock_url,
            "retry": { "max_retries": 0 },
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
    let connector = CloudflareConnector::new();
    let health = connector.health().await;
    assert!(!health.is_ready());
    let details = health.details.expect("health details");
    assert!(details["operator_guidance"]["prerequisites"].is_array());
    assert_eq!(
        details["verification_script"],
        "scripts/e2e/cloudflare_connector_verification.sh"
    );
}

#[fcp_async_core::runtime::test]
async fn doctor_unconfigured_reports_remediation() {
    let connector = CloudflareConnector::new();
    let doctor = serde_json::to_value(connector.doctor()).unwrap();
    assert_doctor_response_valid(&doctor);
    assert_eq!(doctor["status"], "unhealthy");
    assert_eq!(doctor["ready"], false);
    assert_eq!(
        doctor["operator_guidance"]["artifact_root_hint"],
        "artifacts/e2e/cloudflare_connector/<timestamp>"
    );
}

#[fcp_async_core::runtime::test]
async fn configure_rejects_invalid_network_constraints() {
    let mut connector = CloudflareConnector::new();
    let error = connector
        .configure(json!({
            "mode": "api_token",
            "api_token": "test-cloudflare-token",
            "account_id": "account-123",
            "base_url": "http://example.com",
            "retry": { "max_retries": 0 },
        }))
        .await
        .expect_err("invalid base_url policy should fail during configure");

    assert!(matches!(
        error,
        fcp_core::FcpError::InvalidRequest { code: 1001, .. }
    ));
}

#[fcp_async_core::runtime::test]
async fn self_check_ready_with_active_token_and_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/user/tokens/verify"))
        .and(header("Authorization", "Bearer test-cloudflare-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "errors": [],
            "messages": [],
            "result": { "id": "tok-123", "status": "active" }
        })))
        .mount(&server)
        .await;

    let (connector, _signing_key) = setup_connector(&server.uri()).await;
    let doctor = serde_json::to_value(connector.doctor()).unwrap();
    assert_doctor_response_valid(&doctor);
    println!(
        "cloudflare_doctor_evidence={}",
        serde_json::to_string_pretty(&doctor).unwrap()
    );

    let report = connector.self_check().await.unwrap();
    let value = serde_json::to_value(&report).unwrap();
    assert_self_check_ready(&value);
    assert_eq!(value["details"]["provisioning"]["auth_mode"], "api_token");
    println!(
        "cloudflare_self_check_evidence={}",
        serde_json::to_string_pretty(&value).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn self_check_api_key_mode_uses_legacy_headers() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/user/tokens/verify"))
        .and(header("X-Auth-Key", "test-global-key"))
        .and(header("X-Auth-Email", "ops@example.com"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "errors": [],
            "messages": [],
            "result": { "id": "tok-legacy", "status": "active" }
        })))
        .mount(&server)
        .await;

    let (connector, _signing_key) = setup_api_key_connector(&server.uri()).await;
    let doctor = serde_json::to_value(connector.doctor()).unwrap();
    assert_eq!(doctor["status"], "degraded");

    let report = connector.self_check().await.unwrap();
    let value = serde_json::to_value(&report).unwrap();
    assert_self_check_ready(&value);
    assert_eq!(
        value["details"]["provisioning"]["uses_legacy_global_key"],
        true
    );
}

#[fcp_async_core::runtime::test]
async fn self_check_retryable_error_surfaces_degraded_status() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/user/tokens/verify"))
        .respond_with(ResponseTemplate::new(503).set_body_string("cloudflare overloaded"))
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
async fn invoke_safe_read_zones_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/zones"))
        .and(header("Authorization", "Bearer test-cloudflare-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "errors": [],
            "messages": [],
            "result": [
                { "id": "zone-123", "name": "example.com", "status": "active" }
            ]
        })))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server.uri()).await;
    let response = connector
        .invoke(invoke_req(
            OP_ZONES_LIST,
            json!({}),
            generate_valid_token(&signing_key, OP_ZONES_LIST).expect("test token should build"),
        ))
        .await
        .unwrap();
    let result = response.result.expect("zones list result");
    assert_eq!(result.as_array().unwrap().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn invoke_risky_dns_delete_preserves_artifact_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/zones/zone-123/dns_records/rec-456"))
        .and(header("Authorization", "Bearer test-cloudflare-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "errors": [],
            "messages": [],
            "result": { "id": "rec-456", "deleted": true }
        })))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server.uri()).await;
    let response = connector
        .invoke(invoke_req(
            OP_DNS_DELETE,
            json!({
                "zone_id": "zone-123",
                "record_id": "rec-456"
            }),
            generate_valid_token(&signing_key, OP_DNS_DELETE).expect("test token should build"),
        ))
        .await
        .unwrap();

    let result = response.result.expect("dns delete result");
    assert_eq!(result["deleted"], true);
    println!(
        "cloudflare_risky_mutation_evidence={}",
        serde_json::to_string_pretty(&result).unwrap()
    );
}
