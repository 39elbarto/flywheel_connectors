//! Integration tests for the FCP Supabase connector.

#![allow(
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use chrono::{Duration, Utc};
use fcp_core::{
    CapabilityId, CapabilityToken, ConnectorId, FcpConnector, HandshakeRequest, InvokeRequest,
    OperationId, RequestId, ZoneId,
};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_supabase::connector::SupabaseConnector;
use fcp_testkit::readiness_helpers::{
    assert_doctor_response_valid, assert_self_check_not_ready, assert_self_check_ready,
};
use serde_json::json;
use wiremock::matchers::{header, method, path, path_regex, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const OP_QUERY: &str = "supabase.query";
const OP_INSERT: &str = "supabase.insert";
const OP_RPC: &str = "supabase.rpc";
const OP_SCHEMA_TABLES: &str = "supabase.schema.tables";
const OP_STORAGE_UPLOAD: &str = "supabase.storage.upload";
const OP_STORAGE_DELETE: &str = "supabase.storage.delete";

fn handshake_req(host_public_key: [u8; 32]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [7u8; 32],
        capabilities_requested: vec![
            CapabilityId::from_static("supabase.read"),
            CapabilityId::from_static("supabase.write"),
            CapabilityId::from_static("supabase.storage"),
        ],
        host: None,
        transport_caps: None,
        requested_instance_id: None,
    }
}

fn generate_valid_token(signing_key: &Ed25519SigningKey, op: &'static str) -> CapabilityToken {
    let capability = match op {
        OP_QUERY | OP_SCHEMA_TABLES => "supabase.read",
        OP_INSERT | OP_RPC => "supabase.write",
        OP_STORAGE_UPLOAD | OP_STORAGE_DELETE => "supabase.storage",
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
    CapabilityToken::from_raw(raw)
}

fn invoke_req(
    op: &'static str,
    input: serde_json::Value,
    capability_token: CapabilityToken,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new("integration-1"),
        connector_id: ConnectorId::from_static("fcp.supabase"),
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
    mock_url: &str,
    api_key: Option<&str>,
) -> (SupabaseConnector, Ed25519SigningKey) {
    let mut connector = SupabaseConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    let mut config = json!({
        "project_url": mock_url,
        "schema": "public",
        "request_timeout_ms": 30_000
    });
    if let Some(api_key) = api_key {
        config["api_key"] = json!(api_key);
    }
    connector.configure(config).await.unwrap();
    connector
        .handshake(handshake_req(signing_key.verifying_key().to_bytes()))
        .await
        .unwrap();
    (connector, signing_key)
}

#[fcp_async_core::runtime::test]
async fn lifecycle_health_unconfigured_includes_guidance() {
    let connector = SupabaseConnector::new();
    let health = connector.health().await;
    assert!(!health.is_ready());
    let details = health.details.expect("health details");
    assert!(details["operator_guidance"]["prerequisites"].is_array());
    assert_eq!(
        details["verification_script"],
        "scripts/e2e/supabase_connector_verification.sh"
    );
}

#[fcp_async_core::runtime::test]
async fn doctor_unconfigured_reports_remediation() {
    let connector = SupabaseConnector::new();
    let doctor = serde_json::to_value(connector.doctor()).unwrap();
    assert_doctor_response_valid(&doctor);
    assert_eq!(doctor["status"], "unhealthy");
    assert_eq!(doctor["ready"], false);
    assert_eq!(
        doctor["operator_guidance"]["artifact_root_hint"],
        "artifacts/e2e/supabase_connector/<timestamp>"
    );
}

#[fcp_async_core::runtime::test]
async fn self_check_rejects_invalid_network_constraints() {
    let mut connector = SupabaseConnector::new();
    connector
        .configure(json!({
            "api_key": "sb_secret_key",
            "project_url": "http://example.com",
        }))
        .await
        .unwrap();

    let report = connector.self_check().await.unwrap();
    let value = serde_json::to_value(&report).unwrap();
    assert_self_check_not_ready(&value);
    assert_eq!(value["reason_code"], "network_constraints_invalid");
    assert_eq!(value["details"]["provisioning"]["network_ok"], false);
}

#[fcp_async_core::runtime::test]
async fn self_check_ready_with_secret_key_and_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/v1/"))
        .and(header("authorization", "Bearer sb_secret_key"))
        .and(header("apikey", "sb_secret_key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "info": {"title": "PostgREST API", "version": "13.0"},
            "paths": {}
        })))
        .mount(&server)
        .await;

    let (connector, _signing_key) = setup_connector(&server.uri(), Some("sb_secret_key")).await;
    let doctor = serde_json::to_value(connector.doctor()).unwrap();
    assert_doctor_response_valid(&doctor);
    println!(
        "supabase_doctor_evidence={}",
        serde_json::to_string_pretty(&doctor).unwrap()
    );

    let report = connector.self_check().await.unwrap();
    let value = serde_json::to_value(&report).unwrap();
    assert_self_check_ready(&value);
    assert_eq!(value["details"]["live_probe"]["openapi_version"], "13.0");
    println!(
        "supabase_self_check_evidence={}",
        serde_json::to_string_pretty(&value).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn self_check_secretless_requires_injection() {
    let server = MockServer::start().await;
    let (connector, _signing_key) = setup_connector(&server.uri(), None).await;
    let report = connector.self_check().await.unwrap();
    let value = serde_json::to_value(&report).unwrap();
    assert_self_check_not_ready(&value);
    assert_eq!(value["reason_code"], "credential_injection_required");
}

#[fcp_async_core::runtime::test]
async fn self_check_publishable_key_warns_about_permissions() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/v1/"))
        .and(header("authorization", "Bearer sb_publishable_key"))
        .and(header("apikey", "sb_publishable_key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "info": {"title": "PostgREST API", "version": "13.0"},
            "paths": {}
        })))
        .mount(&server)
        .await;

    let (connector, _signing_key) =
        setup_connector(&server.uri(), Some("sb_publishable_key")).await;
    let report = connector.self_check().await.unwrap();
    let value = serde_json::to_value(&report).unwrap();
    assert_self_check_not_ready(&value);
    assert_eq!(value["reason_code"], "limited_key_scope");
    assert_eq!(
        value["details"]["provisioning"]["key_classification"],
        "publishable"
    );
}

#[fcp_async_core::runtime::test]
async fn query_invokes_postgrest_filters() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/v1/todos"))
        .and(query_param("select", "id,title"))
        .and(query_param("status", "eq.open"))
        .and(query_param("limit", "5"))
        .and(query_param("order", "id.desc"))
        .and(header("authorization", "Bearer sb_secret_key"))
        .and(header("apikey", "sb_secret_key"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-range", "0-1/2")
                .set_body_json(json!([
                    {"id": 2, "title": "b"},
                    {"id": 1, "title": "a"}
                ])),
        )
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server.uri(), Some("sb_secret_key")).await;
    let response = connector
        .invoke(invoke_req(
            OP_QUERY,
            json!({
                "table": "todos",
                "select": "id,title",
                "filters": [{"column": "status", "operator": "eq", "value": "open"}],
                "order": [{"column": "id", "ascending": false}],
                "limit": 5
            }),
            generate_valid_token(&signing_key, OP_QUERY),
        ))
        .await
        .unwrap();

    let result = response.result.expect("query result");
    assert_eq!(result["count"], 2);
    assert_eq!(result["data"][0]["id"], 2);
}

#[fcp_async_core::runtime::test]
async fn insert_posts_rows() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/rest/v1/todos"))
        .and(header("prefer", "return=representation"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!([
            {"id": 10, "title": "Ship connector"}
        ])))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server.uri(), Some("sb_secret_key")).await;
    let response = connector
        .invoke(invoke_req(
            OP_INSERT,
            json!({
                "table": "todos",
                "rows": [{"title": "Ship connector"}]
            }),
            generate_valid_token(&signing_key, OP_INSERT),
        ))
        .await
        .unwrap();

    let result = response.result.expect("insert result");
    assert_eq!(result["data"][0]["id"], 10);
}

#[fcp_async_core::runtime::test]
async fn rpc_posts_args() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/rest/v1/rpc/search_todos"))
        .and(header("prefer", "return=representation"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": 1, "title": "connector task"}
        ])))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server.uri(), Some("sb_secret_key")).await;
    let response = connector
        .invoke(invoke_req(
            OP_RPC,
            json!({
                "function": "search_todos",
                "args": {"q": "connector"}
            }),
            generate_valid_token(&signing_key, OP_RPC),
        ))
        .await
        .unwrap();

    let result = response.result.expect("rpc result");
    assert_eq!(result["data"][0]["title"], "connector task");
}

#[fcp_async_core::runtime::test]
async fn schema_tables_reads_openapi_root() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/v1/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "info": {"title": "PostgREST API", "version": "13.0"},
            "paths": {
                "/profiles": {"get": {}, "post": {}, "patch": {}, "delete": {}},
                "/todos": {"get": {}, "post": {}},
                "/rpc/search_todos": {"post": {}}
            }
        })))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server.uri(), Some("sb_secret_key")).await;
    let response = connector
        .invoke(invoke_req(
            OP_SCHEMA_TABLES,
            json!({}),
            generate_valid_token(&signing_key, OP_SCHEMA_TABLES),
        ))
        .await
        .unwrap();

    let result = response.result.expect("schema tables result");
    assert_eq!(result["tables"].as_array().unwrap().len(), 2);
    assert_eq!(result["tables"][0]["name"], "profiles");
}

#[fcp_async_core::runtime::test]
async fn storage_upload_posts_object() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(
            "/storage/v1/object/artifacts/reports/out(\\.txt|%2Etxt)",
        ))
        .and(header("x-upsert", "true"))
        .and(header("content-type", "text/plain"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "Key": "artifacts/reports/out.txt"
        })))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server.uri(), Some("sb_secret_key")).await;
    let response = connector
        .invoke(invoke_req(
            OP_STORAGE_UPLOAD,
            json!({
                "bucket": "artifacts",
                "path": "reports/out.txt",
                "content_base64": BASE64_STANDARD.encode("hello"),
                "content_type": "text/plain",
                "upsert": true
            }),
            generate_valid_token(&signing_key, OP_STORAGE_UPLOAD),
        ))
        .await
        .unwrap();

    let result = response.result.expect("storage upload result");
    assert_eq!(result["object"]["Key"], "artifacts/reports/out.txt");
}

#[fcp_async_core::runtime::test]
async fn storage_delete_preserves_artifact_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path_regex(
            "/storage/v1/object/artifacts/reports/out(\\.txt|%2Etxt)",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "message": "Successfully deleted"
        })))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server.uri(), Some("sb_secret_key")).await;
    let response = connector
        .invoke(invoke_req(
            OP_STORAGE_DELETE,
            json!({
                "bucket": "artifacts",
                "path": "reports/out.txt"
            }),
            generate_valid_token(&signing_key, OP_STORAGE_DELETE),
        ))
        .await
        .unwrap();

    let result = response.result.expect("storage delete result");
    assert_eq!(result["result"]["message"], "Successfully deleted");
    println!(
        "supabase_risky_mutation_evidence={}",
        serde_json::to_string_pretty(&result).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn introspection_emits_v3_compliance_evidence() {
    let connector = SupabaseConnector::new();
    let operations = connector.introspect().operations;
    assert_eq!(operations.len(), 11);
    for operation in &operations {
        if operation.safety_tier == fcp_core::SafetyTier::Dangerous {
            assert_eq!(operation.idempotency, fcp_core::IdempotencyClass::Strict);
        }
    }

    let evidence = json!({
        "operation_ids": operations.iter().map(|op| op.id.as_str()).collect::<Vec<_>>(),
        "dangerous_operations": operations
            .iter()
            .filter(|op| op.safety_tier == fcp_core::SafetyTier::Dangerous)
            .map(|op| {
                json!({
                    "id": op.id.as_str(),
                    "idempotency": format!("{:?}", op.idempotency),
                    "requires_approval": op.requires_approval.is_some()
                })
            })
            .collect::<Vec<_>>(),
    });
    println!(
        "supabase_v3_conformance_evidence={}",
        serde_json::to_string_pretty(&evidence).unwrap()
    );
}
