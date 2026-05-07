//! Integration tests for the FCP `MySQL` connector.

#![allow(
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use fcp_mysql::connector::MysqlConnector;
use fcp_testkit::readiness_helpers::{
    assert_doctor_response_valid, assert_self_check_not_ready, assert_self_check_ready,
};
use fcp_manifest::ConnectorManifest;
use serde_json::{Value, json};
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const VERIFICATION_SCRIPT_PATH: &str = "scripts/e2e/mysql_connector_verification.sh";
const MYSQL_PROXY_HOST_PLACEHOLDER: &str = "operator-configured";
const MYSQL_OPERATION_IDS: &[&str] = &[
    "mysql.execute",
    "mysql.explain",
    "mysql.health",
    "mysql.query",
    "mysql.schema.columns",
    "mysql.schema.indexes",
    "mysql.schema.tables",
];

fn parsed_manifest() -> ConnectorManifest {
    ConnectorManifest::parse_str(include_str!("../manifest.toml"))
        .expect("MySQL manifest should parse with per-operation network constraints")
}

async fn configured_connector(base_url: &str, auth: Value) -> MysqlConnector {
    let mut connector = MysqlConnector::new();
    let mut params = json!({ "base_url": base_url });
    if let Some(api_key) = auth.get("api_key") {
        params["api_key"] = api_key.clone();
    }
    if let Some(credential_id) = auth.get("credential_id") {
        params["credential_id"] = credential_id.clone();
    }
    connector.handle_configure(&params).unwrap();
    connector.handle_handshake(&json!({})).unwrap();
    connector
}

#[fcp_async_core::runtime::test]
async fn health_unconfigured_includes_guidance() {
    let connector = MysqlConnector::new();
    let health = connector.handle_health().await.unwrap();
    assert_eq!(health["status"], "not_configured");
    assert_eq!(health["ready"], false);
    assert_eq!(
        health["details"]["verification_script"],
        VERIFICATION_SCRIPT_PATH
    );
    assert!(health["details"]["operator_guidance"]["prerequisites"].is_array());
}

#[fcp_async_core::runtime::test]
async fn doctor_unconfigured_reports_operator_guidance() {
    let connector = MysqlConnector::new();
    let doctor = connector.handle_doctor().unwrap();
    assert_doctor_response_valid(&doctor);
    assert_eq!(doctor["status"], "unhealthy");
    assert_eq!(doctor["ready"], false);
    assert_eq!(
        doctor["operator_guidance"]["artifact_root_hint"],
        "artifacts/e2e/mysql_connector/<timestamp>"
    );
}

#[test]
fn manifest_declares_strict_per_operation_network_constraints() {
    let manifest = parsed_manifest();
    assert_eq!(manifest.provides.operations.len(), MYSQL_OPERATION_IDS.len());

    for operation_id in MYSQL_OPERATION_IDS {
        let operation = manifest
            .provides
            .operations
            .get(*operation_id)
            .unwrap_or_else(|| panic!("{operation_id} operation should exist"));
        let constraints = operation
            .network_constraints
            .as_ref()
            .unwrap_or_else(|| panic!("{operation_id} should declare network_constraints"));

        assert_eq!(
            constraints.host_allow.as_slice(),
            [MYSQL_PROXY_HOST_PLACEHOLDER],
            "{operation_id} should only allow the operator-pinned MySQL proxy host"
        );
        assert_eq!(constraints.port_allow.as_slice(), [443]);
        assert!(
            constraints.require_sni,
            "{operation_id} should require TLS SNI"
        );
        assert!(
            constraints.deny_private_ranges,
            "{operation_id} should fail closed on private ranges unless the installer substitutes an approved host policy"
        );
        assert_eq!(constraints.max_redirects, 0);
        assert_eq!(constraints.connect_timeout_ms, 10_000);
        assert_eq!(constraints.total_timeout_ms, 30_000);
        assert_eq!(constraints.max_response_bytes, 10_485_760);
    }
}

#[fcp_async_core::runtime::test]
async fn self_check_secretless_requires_injection_and_evidence() {
    let server = MockServer::start().await;
    let connector = configured_connector(
        &server.uri(),
        json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000"
        }),
    )
    .await;

    let report = connector.handle_self_check().await.unwrap();
    assert_self_check_not_ready(&report);
    assert_eq!(report["reason_code"], "credential_injection_required");
    assert_eq!(
        report["details"]["provisioning"]["auth"]["requires_credential_injection"],
        true
    );
}

#[fcp_async_core::runtime::test]
async fn self_check_rejects_invalid_network_constraints() {
    let connector = configured_connector(
        "ftp://db.example.com",
        json!({
            "api_key": "proxy-token"
        }),
    )
    .await;

    let report = connector.handle_self_check().await.unwrap();
    assert_self_check_not_ready(&report);
    assert_eq!(report["reason_code"], "network_constraints_invalid");
    assert_eq!(report["details"]["provisioning"]["network"]["valid"], false);
}

#[fcp_async_core::runtime::test]
async fn self_check_ready_against_live_proxy() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/health"))
        .and(header("authorization", "Bearer proxy-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "ok",
            "server": "mysql-rest-proxy",
        })))
        .mount(&server)
        .await;

    let connector = configured_connector(
        &server.uri(),
        json!({
            "api_key": "proxy-token"
        }),
    )
    .await;

    let report = connector.handle_self_check().await.unwrap();
    assert_self_check_ready(&report);
    assert_eq!(report["details"]["live_probe"]["status"], "ok");
    assert_eq!(report["details"]["live_probe"]["payload"]["status"], "ok");
}

#[fcp_async_core::runtime::test]
async fn query_invoke_hits_proxy() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/query"))
        .and(header("authorization", "Bearer proxy-token"))
        .and(body_json(json!({
            "sql": "SELECT * FROM users WHERE id = ?",
            "params": [1],
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "rows": [{"id": 1, "name": "Ada"}],
            "columns": [{"name": "id"}, {"name": "name"}],
            "row_count": 1,
        })))
        .mount(&server)
        .await;

    let connector = configured_connector(
        &server.uri(),
        json!({
            "api_key": "proxy-token"
        }),
    )
    .await;

    let response = connector
        .handle_invoke(json!({
            "operation": "mysql.query",
            "input": {
                "sql": "SELECT * FROM users WHERE id = ?",
                "params": [1],
            }
        }))
        .await
        .unwrap();
    assert_eq!(response["row_count"], 1);
    assert_eq!(response["rows"][0]["name"], "Ada");
}

#[fcp_async_core::runtime::test]
async fn execute_invoke_hits_proxy() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/execute"))
        .and(header("authorization", "Bearer proxy-token"))
        .and(body_json(json!({
            "sql": "DELETE FROM users WHERE id = ?",
            "params": [9],
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "affected_rows": 1,
        })))
        .mount(&server)
        .await;

    let connector = configured_connector(
        &server.uri(),
        json!({
            "api_key": "proxy-token"
        }),
    )
    .await;

    let response = connector
        .handle_invoke(json!({
            "operation": "mysql.execute",
            "input": {
                "sql": "DELETE FROM users WHERE id = ?",
                "params": [9],
            }
        }))
        .await
        .unwrap();
    assert_eq!(response["affected_rows"], 1);
}

#[fcp_async_core::runtime::test]
async fn schema_tables_invoke_hits_proxy() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/schema/tables"))
        .and(header("authorization", "Bearer proxy-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {
                "name": "users",
                "database": "app",
                "engine": "InnoDB",
                "row_count_estimate": 42,
            }
        ])))
        .mount(&server)
        .await;

    let connector = configured_connector(
        &server.uri(),
        json!({
            "api_key": "proxy-token"
        }),
    )
    .await;

    let response = connector
        .handle_invoke(json!({
            "operation": "mysql.schema.tables",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(response[0]["name"], "users");
}

#[fcp_async_core::runtime::test]
async fn introspection_emits_mutation_approval_evidence() {
    let connector = MysqlConnector::new();
    let introspect = connector.handle_introspect().unwrap();
    assert_eq!(introspect["connector_id"], "fcp.mysql");
    assert_eq!(introspect["verification_script"], VERIFICATION_SCRIPT_PATH);

    let operations = introspect["operations"].as_array().cloned();
    assert!(operations.is_some(), "operations array present");
    let operations = operations.unwrap_or_default();
    let execute = operations.iter().find(|op| op["id"] == "mysql.execute");
    assert!(execute.is_some(), "mysql.execute operation present");
    let execute = execute.unwrap_or(&Value::Null);
    assert_eq!(execute["requires_approval"], "interactive");
    assert_eq!(execute["risk_level"], "high");
}
