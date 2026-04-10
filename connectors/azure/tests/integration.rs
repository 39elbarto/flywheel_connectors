//! Integration tests for the FCP Azure connector.

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
use fcp_azure::{
    client::{
        AzureApiVersions, DEFAULT_BLOB_API_VERSION, DEFAULT_KEYVAULT_API_VERSION,
        DEFAULT_SUBSCRIPTIONS_API_VERSION,
    },
    connector::AzureConnector,
};
use fcp_core::{
    ApprovalMode, CapabilityId, CapabilityToken, ConnectorId, FcpConnector, HandshakeRequest,
    IdempotencyClass, InvokeRequest, OperationId, RequestId, SafetyTier, ZoneId,
};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_testkit::readiness_helpers::{
    assert_doctor_response_valid, assert_self_check_not_ready, assert_self_check_ready,
};
use serde_json::json;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const OP_LIST_SUBSCRIPTIONS: &str = "azure.management.list_subscriptions";
const OP_BLOB_PUT: &str = "azure.storage.blob_put";
const OP_KEYVAULT_SET_SECRET: &str = "azure.keyvault.set_secret";

fn handshake_req(host_public_key: [u8; 32]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [9u8; 32],
        capabilities_requested: vec![
            CapabilityId::from_static("azure.management.read"),
            CapabilityId::from_static("azure.storage.write"),
            CapabilityId::from_static("azure.keyvault.write"),
        ],
        host: None,
        transport_caps: None,
        requested_instance_id: None,
    }
}

fn generate_valid_token(signing_key: &Ed25519SigningKey, op: &'static str) -> CapabilityToken {
    let capability = match op {
        OP_LIST_SUBSCRIPTIONS => "azure.management.read",
        OP_BLOB_PUT => "azure.storage.write",
        OP_KEYVAULT_SET_SECRET => "azure.keyvault.write",
        _ => panic!("unsupported Azure integration test operation: {op}"),
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
    CapabilityToken::from_raw(raw)
}

fn invoke_req(
    op: &'static str,
    input: serde_json::Value,
    capability_token: CapabilityToken,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new("azure-integration-1"),
        connector_id: ConnectorId::from_static("fcp.azure"),
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

async fn setup_connector(management_url: &str) -> (AzureConnector, Ed25519SigningKey) {
    let mut connector = AzureConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    connector
        .configure(json!({
            "mode": "bearer_token",
            "bearer_token": "test-token",
            "management_url": management_url,
            "retry": { "max_retries": 0 },
            "api_versions": AzureApiVersions::compiled_defaults()
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
    let connector = AzureConnector::new();
    let health = connector.health().await;
    assert!(!health.is_ready());
    let details = health.details.as_ref().expect("health details");
    assert!(details["operator_guidance"]["dedicated_environment"].is_string());
    assert!(details["operator_guidance"]["prerequisites"].is_array());
    assert!(details["operator_guidance"]["redaction_rules"].is_array());
    assert_eq!(
        details["verification_script"],
        "scripts/e2e/azure_connector_verification.sh"
    );
    assert_eq!(
        details["artifact_root_hint"],
        "artifacts/e2e/azure_connector/<timestamp>"
    );
    println!(
        "azure_health_evidence={}",
        serde_json::to_string_pretty(&health).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn doctor_unconfigured_reports_remediation() {
    let connector = AzureConnector::new();
    let doctor = serde_json::to_value(connector.doctor()).unwrap();
    assert_doctor_response_valid(&doctor);
    assert_eq!(doctor["ready"], false);
    assert_eq!(
        doctor["verification_script"],
        "scripts/e2e/azure_connector_verification.sh"
    );
    assert!(doctor["operator_guidance"]["redaction_rules"].is_array());
    assert_eq!(
        doctor["operator_guidance"]["artifact_root_hint"],
        "artifacts/e2e/azure_connector/<timestamp>"
    );
    println!(
        "azure_doctor_guidance_evidence={}",
        serde_json::to_string_pretty(&doctor).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn self_check_ready_with_local_management_override_and_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/subscriptions"))
        .and(query_param(
            "api-version",
            DEFAULT_SUBSCRIPTIONS_API_VERSION,
        ))
        .and(header("authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": [
                {
                    "subscriptionId": "sub-123",
                    "displayName": "Fixture Subscription",
                    "state": "Enabled",
                    "tenantId": "tenant-123"
                }
            ],
            "nextLink": null
        })))
        .mount(&server)
        .await;

    let (connector, _signing_key) = setup_connector(&server.uri()).await;
    let doctor = serde_json::to_value(connector.doctor()).unwrap();
    assert_doctor_response_valid(&doctor);
    assert_eq!(doctor["ready"], true);
    assert_eq!(
        doctor["provisioning"]["api_versions"]["subscriptions"],
        DEFAULT_SUBSCRIPTIONS_API_VERSION
    );
    println!(
        "azure_doctor_evidence={}",
        serde_json::to_string_pretty(&doctor).unwrap()
    );

    let report = connector.self_check().await.unwrap();
    let value = serde_json::to_value(&report).unwrap();
    assert_self_check_ready(&value);
    assert_eq!(
        value["details"]["verification_script"],
        "scripts/e2e/azure_connector_verification.sh"
    );
    assert_eq!(
        value["details"]["provisioning"]["management_url"],
        server.uri()
    );
    assert_eq!(
        value["details"]["provisioning"]["api_versions"]["subscriptions"],
        DEFAULT_SUBSCRIPTIONS_API_VERSION
    );
    println!(
        "azure_self_check_evidence={}",
        serde_json::to_string_pretty(&value).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn self_check_retryable_management_failure_reports_degraded() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/subscriptions"))
        .and(query_param(
            "api-version",
            DEFAULT_SUBSCRIPTIONS_API_VERSION,
        ))
        .respond_with(ResponseTemplate::new(503).set_body_json(json!({
            "error": {
                "code": "ServiceUnavailable",
                "message": "temporary ARM outage"
            }
        })))
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
async fn invoke_blob_put_preserves_artifact_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/fixtures/hello.txt"))
        .and(header("authorization", "Bearer test-token"))
        .and(header("x-ms-version", DEFAULT_BLOB_API_VERSION))
        .and(header("x-ms-blob-type", "BlockBlob"))
        .respond_with(ResponseTemplate::new(201))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server.uri()).await;
    let response = connector
        .invoke(invoke_req(
            OP_BLOB_PUT,
            json!({
                "storage_account": "fixtureacct",
                "container": "fixtures",
                "blob_name": "hello.txt",
                "content_base64": "aGVsbG8=",
                "blob_base_url": server.uri()
            }),
            generate_valid_token(&signing_key, OP_BLOB_PUT),
        ))
        .await
        .unwrap();

    let result = response.result.expect("blob put result");
    assert_eq!(result["created"], true);
    assert_eq!(result["blob_name"], "hello.txt");
    println!(
        "azure_blob_put_evidence={}",
        serde_json::to_string_pretty(&result).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_keyvault_set_secret_preserves_artifact_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/secrets/api-key"))
        .and(query_param("api-version", DEFAULT_KEYVAULT_API_VERSION))
        .and(header("authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": "fixture-secret",
            "id": "https://fixture.vault.azure.net/secrets/api-key/version-1",
            "attributes": {
                "enabled": true,
                "created": 1710000000,
                "updated": 1710000001
            }
        })))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server.uri()).await;
    let response = connector
        .invoke(invoke_req(
            OP_KEYVAULT_SET_SECRET,
            json!({
                "vault_name": "fixture",
                "secret_name": "api-key",
                "value": "fixture-secret",
                "vault_base_url": server.uri(),
                "enabled": true
            }),
            generate_valid_token(&signing_key, OP_KEYVAULT_SET_SECRET),
        ))
        .await
        .unwrap();

    let result = response.result.expect("keyvault set secret result");
    assert_eq!(
        result["id"],
        "https://fixture.vault.azure.net/secrets/api-key/version-1"
    );
    assert_eq!(result["attributes"]["enabled"], true);
    let redacted_evidence = json!({
        "id": result["id"],
        "attributes": result["attributes"],
    });
    println!(
        "azure_keyvault_set_secret_evidence={}",
        serde_json::to_string_pretty(&redacted_evidence).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn introspection_emits_v3_compliance_evidence() {
    let connector = AzureConnector::new();
    let operations = connector.introspect().operations;
    assert_eq!(operations.len(), 10);

    let keyvault_set_secret = operations
        .iter()
        .find(|operation| operation.id.as_str() == OP_KEYVAULT_SET_SECRET)
        .expect("keyvault set secret operation");
    assert_eq!(keyvault_set_secret.safety_tier, SafetyTier::Dangerous);
    assert_eq!(keyvault_set_secret.idempotency, IdempotencyClass::Strict);
    assert_eq!(
        keyvault_set_secret.requires_approval,
        Some(ApprovalMode::Interactive)
    );

    let blob_put = operations
        .iter()
        .find(|operation| operation.id.as_str() == OP_BLOB_PUT)
        .expect("blob put operation");
    assert_eq!(blob_put.safety_tier, SafetyTier::Risky);
    assert_eq!(blob_put.idempotency, IdempotencyClass::Strict);

    let management_list = operations
        .iter()
        .find(|operation| operation.id.as_str() == OP_LIST_SUBSCRIPTIONS)
        .expect("list subscriptions operation");
    assert_eq!(management_list.safety_tier, SafetyTier::Safe);
    assert_eq!(management_list.idempotency, IdempotencyClass::Strict);

    let evidence = json!({
        "operation_ids": operations
            .iter()
            .map(|operation| operation.id.as_str())
            .collect::<Vec<_>>(),
        "dangerous_operations": operations
            .iter()
            .filter(|operation| operation.safety_tier == SafetyTier::Dangerous)
            .map(|operation| {
                json!({
                    "id": operation.id.as_str(),
                    "capability": operation.capability.as_str(),
                    "idempotency": format!("{:?}", operation.idempotency),
                    "requires_approval": serde_json::to_value(operation.requires_approval)
                        .unwrap_or(serde_json::Value::Null),
                })
            })
            .collect::<Vec<_>>(),
    });
    println!(
        "azure_v3_conformance_evidence={}",
        serde_json::to_string_pretty(&evidence).unwrap()
    );
}
