//! Integration tests for the Package Registry connector readiness and compliance surface.

#![allow(
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unused_async
)]

use std::time::Duration as StdDuration;

use chrono::{Duration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_package_registry::client::PackageRegistryClient;
use fcp_package_registry::connector::{PackageRegistryConnector, operations_info};
use fcp_package_registry::error::Error;
use fcp_package_registry::types::RegistryProvider;
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector,
    HandshakeRequest, InstanceId, InvokeRequest, InvokeStatus, OperationId, RequestId, ZoneId,
};
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig};
use fcp_testkit::readiness_helpers::{
    assert_doctor_response_valid, assert_self_check_not_ready, assert_self_check_ready,
};
use serde_json::json;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const VERIFICATION_SCRIPT_PATH: &str = "scripts/e2e/package_registry_connector_verification.sh";
const ARTIFACT_ROOT_HINT: &str = "artifacts/e2e/package_registry_connector/<timestamp>";
const OP_SEARCH: &str = "registry.search";

fn handshake_req(host_public_key: [u8; 32], instance_id: InstanceId) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [13u8; 32],
        capabilities_requested: vec![
            CapabilityId::from_static("registry.search"),
            CapabilityId::from_static("registry.packages.read"),
            CapabilityId::from_static("registry.versions.read"),
            CapabilityId::from_static("registry.dependencies.read"),
            CapabilityId::from_static("registry.artifacts.read"),
            CapabilityId::from_static("registry.downloads.read"),
        ],
        host: None,
        transport_caps: None,
        requested_instance_id: Some(instance_id),
    }
}

fn generate_valid_token(
    signing_key: &Ed25519SigningKey,
    op: &'static str,
    instance_id: &InstanceId,
) -> CapabilityToken {
    let capability = match op {
        OP_SEARCH => "registry.search",
        _ => panic!("unsupported package-registry integration operation: {op}"),
    };
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
        .target_instance(instance_id.as_str())
        .issuer("node:test")
        .validity(now, now + Duration::hours(1))
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
        id: RequestId::new("package-registry-integration-1"),
        connector_id: ConnectorId::from_static("fcp.package-registry"),
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

async fn setup_connector(
    provider: &str,
    base_url: &str,
) -> (PackageRegistryConnector, Ed25519SigningKey, InstanceId) {
    let mut connector = PackageRegistryConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();
    connector
        .configure(json!({
            "provider": provider,
            "base_url": base_url,
            "request_timeout_ms": 1_000,
            "retry": {
                "max_retries": 0,
                "initial_delay_ms": 1,
                "max_delay_ms": 1,
                "jitter_enabled": false
            }
        }))
        .await
        .unwrap();
    connector
        .handshake(handshake_req(
            signing_key.verifying_key().to_bytes(),
            instance_id.clone(),
        ))
        .await
        .unwrap();
    (connector, signing_key, instance_id)
}

fn runtime_with_timeout(timeout_ms: u64) -> ConnectorRuntime {
    ConnectorRuntime::new(
        ConnectorRuntimeConfig::default()
            .with_request_timeout(StdDuration::from_millis(timeout_ms)),
    )
}

fn registry_client(
    provider: RegistryProvider,
    base_url: &str,
    token: Option<&str>,
    retry_config: HttpRetryConfig,
    request_timeout_ms: u64,
) -> PackageRegistryClient {
    PackageRegistryClient::new(
        provider,
        base_url.to_string(),
        token.map(ToOwned::to_owned),
        retry_config,
        request_timeout_ms,
    )
    .unwrap()
}

#[fcp_async_core::runtime::test]
async fn health_unconfigured_includes_guidance() {
    let connector = PackageRegistryConnector::new();
    let health = connector.health().await;
    assert!(!health.is_ready());
    let details = health.details.as_ref().expect("health details");
    assert!(details["operator_guidance"]["prerequisites"].is_array());
    assert!(details["operator_guidance"]["provider_auth"].is_array());
    assert_eq!(details["verification_script"], VERIFICATION_SCRIPT_PATH);
    assert_eq!(details["artifact_root_hint"], ARTIFACT_ROOT_HINT);
    println!(
        "package_registry_health_evidence={}",
        serde_json::to_string_pretty(&health).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn doctor_unconfigured_reports_operator_guidance() {
    let connector = PackageRegistryConnector::new();
    let doctor = serde_json::to_value(connector.doctor()).unwrap();
    assert_doctor_response_valid(&doctor);
    assert_eq!(doctor["ready"], false);
    assert_eq!(doctor["verification_script"], VERIFICATION_SCRIPT_PATH);
    assert!(doctor["operator_guidance"]["redaction_rules"].is_array());
    assert_eq!(
        doctor["operator_guidance"]["artifact_root_hint"],
        ARTIFACT_ROOT_HINT
    );
    println!(
        "package_registry_doctor_unconfigured={}",
        serde_json::to_string_pretty(&doctor).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn self_check_ready_with_crates_override_and_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/crates"))
        .and(query_param("q", "serde"))
        .and(query_param("per_page", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "crates": [{ "name": "serde", "max_version": "1.0.228" }],
            "meta": { "total": 1 }
        })))
        .mount(&server)
        .await;

    let (connector, _signing_key, _instance_id) = setup_connector("crates_io", &server.uri()).await;
    let doctor = serde_json::to_value(connector.doctor()).unwrap();
    assert_doctor_response_valid(&doctor);
    assert_eq!(doctor["ready"], true);
    println!(
        "package_registry_doctor_ready={}",
        serde_json::to_string_pretty(&doctor).unwrap()
    );

    let report = connector.self_check().await.unwrap();
    let value = serde_json::to_value(&report).unwrap();
    assert_self_check_ready(&value);
    assert_eq!(
        value["details"]["verification_script"],
        VERIFICATION_SCRIPT_PATH
    );
    assert_eq!(value["details"]["artifact_root_hint"], ARTIFACT_ROOT_HINT);
    assert_eq!(value["details"]["provisioning"]["provider"], "crates_io");
    assert_eq!(value["details"]["provisioning"]["auth_mode"], "anonymous");
    assert_eq!(value["details"]["live_probe"]["base_url"], server.uri());
    println!(
        "package_registry_self_check_ready={}",
        serde_json::to_string_pretty(&value).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn self_check_retryable_registry_failure_reports_degraded() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/crates"))
        .respond_with(ResponseTemplate::new(503).set_body_json(json!({
            "message": "temporary crates outage"
        })))
        .mount(&server)
        .await;

    let (connector, _signing_key, _instance_id) = setup_connector("crates_io", &server.uri()).await;
    let report = connector.self_check().await.unwrap();
    let value = serde_json::to_value(&report).unwrap();
    assert_self_check_not_ready(&value);
    assert_eq!(value["status"], "degraded");
    assert_eq!(value["reason_code"], "self_check_retryable");
}

#[fcp_async_core::runtime::test]
async fn client_search_uses_page_offset_for_npm() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/-/v1/search"))
        .and(query_param("text", "serde"))
        .and(query_param("size", "2"))
        .and(query_param("from", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total": 1,
            "objects": [
                {
                    "package": {
                        "name": "serde-json",
                        "description": "fixture",
                        "version": "1.0.0",
                        "links": { "homepage": "https://example.test/serde-json" }
                    }
                }
            ]
        })))
        .mount(&server)
        .await;

    let runtime = runtime_with_timeout(1_000);
    let client = registry_client(
        RegistryProvider::Npm,
        &server.uri(),
        None,
        HttpRetryConfig {
            max_retries: 0,
            ..HttpRetryConfig::default()
        },
        1_000,
    );

    let response = client.search(&runtime, "serde", 2, 2).await.unwrap();
    assert_eq!(response.page, 2);
    assert_eq!(response.limit, 2);
    assert_eq!(response.results[0].name, "serde-json");
}

#[fcp_async_core::runtime::test]
async fn client_health_check_includes_auth_header_when_token_supplied() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/crates"))
        .and(query_param("q", "serde"))
        .and(query_param("per_page", "1"))
        .and(header("authorization", "Bearer crates-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "crates": [{ "name": "serde", "max_version": "1.0.228" }],
            "meta": { "total": 1 }
        })))
        .mount(&server)
        .await;

    let runtime = runtime_with_timeout(1_000);
    let client = registry_client(
        RegistryProvider::CratesIo,
        &server.uri(),
        Some("crates-token"),
        HttpRetryConfig {
            max_retries: 0,
            ..HttpRetryConfig::default()
        },
        1_000,
    );

    let probe = client.health_check(&runtime).await.unwrap();
    assert_eq!(probe["provider"], "crates_io");
    assert_eq!(probe["anonymous"], false);
}

#[fcp_async_core::runtime::test]
async fn client_health_check_maps_401_to_unauthorized() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/crates"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "errors": [{ "detail": "bad token" }]
        })))
        .mount(&server)
        .await;

    let runtime = runtime_with_timeout(1_000);
    let client = registry_client(
        RegistryProvider::CratesIo,
        &server.uri(),
        Some("bad-token"),
        HttpRetryConfig {
            max_retries: 0,
            ..HttpRetryConfig::default()
        },
        1_000,
    );

    let error = client.health_check(&runtime).await.unwrap_err();
    match error {
        Error::Unauthorized(message) => assert!(message.contains("crates_io")),
        other => panic!("expected unauthorized error, got {other:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn client_search_retries_retryable_503_once() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/-/v1/search"))
        .respond_with(ResponseTemplate::new(503).set_body_json(json!({
            "message": "temporary outage"
        })))
        .mount(&server)
        .await;

    let runtime = runtime_with_timeout(1_000);
    let client = registry_client(
        RegistryProvider::Npm,
        &server.uri(),
        None,
        HttpRetryConfig {
            max_retries: 1,
            initial_delay_ms: 1,
            max_delay_ms: 1,
            jitter_enabled: false,
        },
        1_000,
    );

    let error = client.search(&runtime, "serde", 1, 1).await.unwrap_err();
    assert!(matches!(error, Error::Api { status: 503, .. }));
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
}

#[fcp_async_core::runtime::test]
async fn client_health_check_timeout_surfaces_retryable_http_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/crates"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(StdDuration::from_millis(100))
                .set_body_json(json!({
                    "crates": [{ "name": "serde", "max_version": "1.0.228" }],
                    "meta": { "total": 1 }
                })),
        )
        .mount(&server)
        .await;

    let runtime = runtime_with_timeout(20);
    let client = registry_client(
        RegistryProvider::CratesIo,
        &server.uri(),
        None,
        HttpRetryConfig {
            max_retries: 0,
            ..HttpRetryConfig::default()
        },
        20,
    );

    let error = client.health_check(&runtime).await.unwrap_err();
    match error {
        Error::Http(inner) => assert!(inner.is_timeout()),
        other => panic!("expected timeout http error, got {other:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn invoke_search_uses_npm_pagination_offset() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/-/v1/search"))
        .and(query_param("text", "react"))
        .and(query_param("size", "2"))
        .and(query_param("from", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total": 1,
            "objects": [
                {
                    "package": {
                        "name": "react-router-fixture",
                        "description": "fixture package",
                        "version": "1.0.0",
                        "links": { "homepage": "https://example.test/react-router-fixture" }
                    }
                }
            ]
        })))
        .mount(&server)
        .await;

    let (connector, signing_key, instance_id) = setup_connector("npm", &server.uri()).await;
    let response = connector
        .invoke(invoke_req(
            OP_SEARCH,
            json!({
                "query": "react",
                "limit": 2,
                "page": 2
            }),
            generate_valid_token(&signing_key, OP_SEARCH, &instance_id),
        ))
        .await
        .unwrap();

    assert_eq!(response.status, InvokeStatus::Ok);
    let result = response.result.as_ref().expect("invoke result");
    assert_eq!(result["provider"], "npm");
    assert_eq!(result["page"], 2);
    assert_eq!(result["results"][0]["name"], "react-router-fixture");
    println!(
        "package_registry_search_evidence={}",
        serde_json::to_string_pretty(&response).unwrap()
    );
}

#[test]
fn introspection_emits_v3_compliance_evidence() {
    let connector = PackageRegistryConnector::new();
    let introspection = connector.introspect();
    let value = serde_json::to_value(&introspection).unwrap();
    let operations = value["operations"].as_array().expect("operations array");

    assert_eq!(operations.len(), 7);
    assert!(operations.iter().all(|op| {
        op["ai_hints"]["examples"]
            .as_array()
            .is_some_and(|examples| !examples.is_empty())
    }));

    let search = operations_info()
        .into_iter()
        .find(|op| op.id.as_str() == OP_SEARCH)
        .expect("search operation");
    assert_eq!(search.ai_hints.examples.len(), 2);

    println!(
        "package_registry_introspection_evidence={}",
        serde_json::to_string_pretty(&value).unwrap()
    );
}
