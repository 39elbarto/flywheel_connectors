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

use std::time::Duration as StdDuration;

use chrono::{Duration, Utc};
use fcp_azure::{
    client::{
        AzureApiVersions, AzureClient, DEFAULT_BLOB_API_VERSION, DEFAULT_KEYVAULT_API_VERSION,
        DEFAULT_RESOURCE_GROUPS_API_VERSION, DEFAULT_RESOURCES_API_VERSION,
        DEFAULT_SUBSCRIPTIONS_API_VERSION,
    },
    connector::AzureConnector,
    error::AzureError,
    types::AzureAuth,
};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::{
    ApprovalMode, CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector,
    HandshakeRequest, IdempotencyClass, InstanceId, InvokeRequest, OperationId, RequestId,
    SafetyTier, ZoneId,
};
use fcp_testkit::readiness_helpers::{
    assert_doctor_response_valid, assert_self_check_not_ready, assert_self_check_ready,
};
use serde_json::json;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const OP_LIST_SUBSCRIPTIONS: &str = "azure.management.list_subscriptions";
const OP_BLOB_LIST_BLOBS: &str = "azure.storage.blob_list_blobs";
const OP_BLOB_PUT: &str = "azure.storage.blob_put";
const OP_BLOB_DELETE: &str = "azure.storage.blob_delete";
const OP_KEYVAULT_WRITE_VALUE: &str = "azure.keyvault.set_secret";

fn test_client(base_url: &str) -> AzureClient {
    AzureClient::new(
        AzureAuth::BearerToken {
            bearer_token: "test-token".into(),
        },
        fcp_sdk::migration::HttpRetryConfig::default(),
        AzureApiVersions::compiled_defaults(),
        StdDuration::from_secs(5),
    )
    .unwrap()
    .with_management_url(base_url)
}

fn handshake_req(host_public_key: [u8; 32], requested_instance_id: InstanceId) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [9u8; 32],
        capabilities_requested: vec![
            CapabilityId::from_static("azure.management.read"),
            CapabilityId::from_static("azure.storage.read"),
            CapabilityId::from_static("azure.storage.write"),
            CapabilityId::from_static("azure.keyvault.write"),
        ],
        host: None,
        transport_caps: None,
        requested_instance_id: Some(requested_instance_id),
    }
}

fn generate_valid_token(
    signing_key: &Ed25519SigningKey,
    op: &'static str,
    target_instance: &InstanceId,
) -> CapabilityToken {
    let capability = [
        (OP_LIST_SUBSCRIPTIONS, "azure.management.read"),
        (OP_BLOB_LIST_BLOBS, "azure.storage.read"),
        (OP_BLOB_PUT, "azure.storage.write"),
        (OP_BLOB_DELETE, "azure.storage.write"),
        (OP_KEYVAULT_WRITE_VALUE, "azure.keyvault.write"),
    ]
    .into_iter()
    .find_map(|(operation, capability)| (operation == op).then_some(capability))
    .expect("supported Azure integration test operation");
    let now = Utc::now();
    // C3.4: tokens MUST include constraints (default-deny)
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let raw = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[op])
        .issuer("node:test")
        .validity(now, now + Duration::hours(1))
        .target_instance(target_instance.as_str())
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
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

async fn setup_connector(management_url: &str) -> (AzureConnector, Ed25519SigningKey, InstanceId) {
    let mut connector = AzureConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    let requested_instance_id = InstanceId::new();
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
        .handshake(handshake_req(
            signing_key.verifying_key().to_bytes(),
            requested_instance_id.clone(),
        ))
        .await
        .unwrap();
    (connector, signing_key, requested_instance_id)
}

#[fcp_async_core::runtime::test]
async fn list_subscriptions_returns_typed_payload() {
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
                    "displayName": "Test Sub",
                    "state": "Enabled"
                }
            ]
        })))
        .mount(&server)
        .await;

    let client = test_client(&server.uri());
    let resp = client.list_subscriptions().await.unwrap();
    assert_eq!(resp.value.len(), 1);
    assert_eq!(resp.value[0].subscription_id.as_deref(), Some("sub-123"));
}

#[fcp_async_core::runtime::test]
async fn list_resource_groups_returns_typed_payload() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/subscriptions/sub-1/resourcegroups"))
        .and(query_param(
            "api-version",
            DEFAULT_RESOURCE_GROUPS_API_VERSION,
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": [
                { "name": "rg-1", "location": "eastus" }
            ]
        })))
        .mount(&server)
        .await;

    let client = test_client(&server.uri());
    let resp = client.list_resource_groups("sub-1").await.unwrap();
    assert_eq!(resp.value.len(), 1);
    assert_eq!(resp.value[0].name.as_deref(), Some("rg-1"));
}

#[fcp_async_core::runtime::test]
async fn list_resources_returns_typed_payload() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/subscriptions/sub-1/resourceGroups/rg-1/resources"))
        .and(query_param("api-version", DEFAULT_RESOURCES_API_VERSION))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": [
                { "name": "vm-1", "type": "Microsoft.Compute/virtualMachines", "location": "westus2" }
            ]
        })))
        .mount(&server)
        .await;

    let client = test_client(&server.uri());
    let resp = client.list_resources("sub-1", "rg-1").await.unwrap();
    assert_eq!(resp.value.len(), 1);
    assert_eq!(resp.value[0].name.as_deref(), Some("vm-1"));
}

#[fcp_async_core::runtime::test]
async fn health_check_succeeds_when_subscriptions_ok() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/subscriptions"))
        .and(query_param(
            "api-version",
            DEFAULT_SUBSCRIPTIONS_API_VERSION,
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "value": [] })))
        .mount(&server)
        .await;

    let client = test_client(&server.uri());
    client.health_check().await.unwrap();
}

#[fcp_async_core::runtime::test]
async fn blob_list_containers_parses_xml_response() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/"))
        .and(query_param("comp", "list"))
        .and(header("x-ms-version", DEFAULT_BLOB_API_VERSION))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<?xml version="1.0" encoding="utf-8"?>
<EnumerationResults ServiceEndpoint="https://acct.blob.core.windows.net/">
  <Containers>
    <Container>
      <Name>audio</Name>
      <Properties>
        <Last-Modified>Wed, 26 Oct 2016 20:39:39 GMT</Last-Modified>
        <PublicAccess>container</PublicAccess>
      </Properties>
    </Container>
  </Containers>
  <NextMarker>next-token</NextMarker>
</EnumerationResults>"#,
        ))
        .mount(&server)
        .await;

    let client = test_client(&server.uri());
    let resp = client
        .blob_list_containers("acct", Some(&server.uri()))
        .await
        .unwrap();
    assert_eq!(resp.containers.len(), 1);
    assert_eq!(resp.containers[0].name.as_deref(), Some("audio"));
    assert_eq!(
        resp.containers[0].last_modified.as_deref(),
        Some("Wed, 26 Oct 2016 20:39:39 GMT")
    );
    assert_eq!(
        resp.containers[0].public_access.as_deref(),
        Some("container")
    );
    assert_eq!(resp.next_marker.as_deref(), Some("next-token"));
}

#[fcp_async_core::runtime::test]
async fn blob_list_blobs_parses_xml_response() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/docs"))
        .and(query_param("restype", "container"))
        .and(query_param("comp", "list"))
        .and(header("x-ms-version", DEFAULT_BLOB_API_VERSION))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<?xml version="1.0" encoding="utf-8"?>
<EnumerationResults ServiceEndpoint="https://acct.blob.core.windows.net/" ContainerName="docs">
  <Blobs>
    <Blob>
      <Name>report.txt</Name>
      <Properties>
        <Last-Modified>Wed, 26 Oct 2016 20:39:39 GMT</Last-Modified>
        <Content-Length>1024</Content-Length>
        <Content-Type>text/plain</Content-Type>
      </Properties>
    </Blob>
  </Blobs>
  <NextMarker>blob-next</NextMarker>
</EnumerationResults>"#,
        ))
        .mount(&server)
        .await;

    let client = test_client(&server.uri());
    let resp = client
        .blob_list_blobs("acct", "docs", None, Some(&server.uri()))
        .await
        .unwrap();
    assert_eq!(resp.blobs.len(), 1);
    assert_eq!(resp.blobs[0].name.as_deref(), Some("report.txt"));
    assert_eq!(resp.blobs[0].content_length, Some(1024));
    assert_eq!(resp.blobs[0].content_type.as_deref(), Some("text/plain"));
    assert_eq!(
        resp.blobs[0].last_modified.as_deref(),
        Some("Wed, 26 Oct 2016 20:39:39 GMT")
    );
    assert_eq!(resp.next_marker.as_deref(), Some("blob-next"));
}

#[fcp_async_core::runtime::test]
async fn blob_list_blobs_sends_prefix_filter() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/docs"))
        .and(query_param("restype", "container"))
        .and(query_param("comp", "list"))
        .and(query_param("prefix", "fcp-live/"))
        .and(header("x-ms-version", DEFAULT_BLOB_API_VERSION))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<?xml version="1.0" encoding="utf-8"?>
<EnumerationResults ServiceEndpoint="https://acct.blob.core.windows.net/" ContainerName="docs">
  <Blobs />
</EnumerationResults>"#,
        ))
        .mount(&server)
        .await;

    let client = test_client(&server.uri());
    let resp = client
        .blob_list_blobs("acct", "docs", Some("fcp-live/"), Some(&server.uri()))
        .await
        .unwrap();
    assert!(resp.blobs.is_empty());
}

#[fcp_async_core::runtime::test]
async fn unauthorized_returns_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/subscriptions"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": {
                "code": "AuthenticationFailed",
                "message": "The access token is invalid."
            }
        })))
        .mount(&server)
        .await;

    let client = test_client(&server.uri());
    let err = client.list_subscriptions().await.unwrap_err();
    assert!(matches!(err, AzureError::Unauthorized(_)));
}

#[fcp_async_core::runtime::test]
async fn not_found_returns_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/subscriptions/sub-missing/resourcegroups"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": {
                "code": "SubscriptionNotFound",
                "message": "Subscription not found"
            }
        })))
        .mount(&server)
        .await;

    let client = test_client(&server.uri());
    let err = client
        .list_resource_groups("sub-missing")
        .await
        .unwrap_err();
    assert!(matches!(err, AzureError::NotFound(_)));
}

#[fcp_async_core::runtime::test]
async fn rate_limited_returns_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/subscriptions"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "5")
                .set_body_json(json!({ "message": "throttled" })),
        )
        .mount(&server)
        .await;

    let no_retry = fcp_sdk::migration::HttpRetryConfig {
        max_retries: 0,
        ..fcp_sdk::migration::HttpRetryConfig::default()
    };
    let client = AzureClient::new(
        AzureAuth::BearerToken {
            bearer_token: "test-token".into(),
        },
        no_retry,
        AzureApiVersions::compiled_defaults(),
        StdDuration::from_secs(5),
    )
    .unwrap()
    .with_management_url(&server.uri());
    let err = client.list_subscriptions().await.unwrap_err();
    assert!(matches!(
        err,
        AzureError::RateLimited {
            retry_after_ms: 5_000
        }
    ));
}

#[fcp_async_core::runtime::test]
async fn rate_limited_huge_retry_after_saturates() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/subscriptions"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", u64::MAX.to_string())
                .set_body_json(json!({ "message": "throttled" })),
        )
        .mount(&server)
        .await;

    let no_retry = fcp_sdk::migration::HttpRetryConfig {
        max_retries: 0,
        ..fcp_sdk::migration::HttpRetryConfig::default()
    };
    let client = AzureClient::new(
        AzureAuth::BearerToken {
            bearer_token: "test-token".into(),
        },
        no_retry,
        AzureApiVersions::compiled_defaults(),
        StdDuration::from_secs(5),
    )
    .unwrap()
    .with_management_url(&server.uri());
    let err = client.list_subscriptions().await.unwrap_err();
    assert!(matches!(
        err,
        AzureError::RateLimited {
            retry_after_ms: u64::MAX
        }
    ));
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

    let (connector, _signing_key, _instance_id) = setup_connector(&server.uri()).await;
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

    let (connector, _signing_key, _instance_id) = setup_connector(&server.uri()).await;
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

    let (connector, signing_key, instance_id) = setup_connector(&server.uri()).await;
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
            generate_valid_token(&signing_key, OP_BLOB_PUT, &instance_id),
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
async fn invoke_blob_delete_preserves_artifact_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/fixtures/hello.txt"))
        .and(header("authorization", "Bearer test-token"))
        .and(header("x-ms-version", DEFAULT_BLOB_API_VERSION))
        .respond_with(ResponseTemplate::new(202))
        .mount(&server)
        .await;

    let (connector, signing_key, instance_id) = setup_connector(&server.uri()).await;
    let response = connector
        .invoke(invoke_req(
            OP_BLOB_DELETE,
            json!({
                "storage_account": "fixtureacct",
                "container": "fixtures",
                "blob_name": "hello.txt",
                "blob_base_url": server.uri()
            }),
            generate_valid_token(&signing_key, OP_BLOB_DELETE, &instance_id),
        ))
        .await
        .unwrap();

    let result = response.result.expect("blob delete result");
    assert_eq!(result["deleted"], true);
    assert_eq!(result["blob_name"], "hello.txt");
    println!(
        "azure_blob_delete_evidence={}",
        serde_json::to_string_pretty(&result).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_keyvault_set_secret_preserves_artifact_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/secrets/config-entry"))
        .and(query_param("api-version", DEFAULT_KEYVAULT_API_VERSION))
        .and(header("authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": "fixture-vault-value",
            "id": "https://fixture.vault.azure.net/secrets/config-entry/version-1",
            "attributes": {
                "enabled": true,
                "created": 1710000000,
                "updated": 1710000001
            }
        })))
        .mount(&server)
        .await;

    let (connector, signing_key, instance_id) = setup_connector(&server.uri()).await;
    let response = connector
        .invoke(invoke_req(
            OP_KEYVAULT_WRITE_VALUE,
            json!({
                "vault_name": "fixture",
                "secret_name": "config-entry",
                "value": "fixture-vault-value",
                "vault_base_url": server.uri(),
                "enabled": true
            }),
            generate_valid_token(&signing_key, OP_KEYVAULT_WRITE_VALUE, &instance_id),
        ))
        .await
        .unwrap();

    let result = response.result.expect("keyvault set secret result");
    assert_eq!(
        result["id"],
        "https://fixture.vault.azure.net/secrets/config-entry/version-1"
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
    assert_eq!(operations.len(), 11);

    let keyvault_write_op = operations
        .iter()
        .find(|operation| operation.id.as_str() == OP_KEYVAULT_WRITE_VALUE)
        .expect("keyvault set secret operation");
    assert_eq!(keyvault_write_op.safety_tier, SafetyTier::Dangerous);
    assert_eq!(keyvault_write_op.idempotency, IdempotencyClass::Strict);
    assert_eq!(
        keyvault_write_op.requires_approval,
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
